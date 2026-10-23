"""Flask dashboard and API for the existing SecureScan scanner."""

import ipaddress
import os
import re
import socket
import threading
from urllib.parse import urlparse

import requests
from flask import Flask, current_app, jsonify, render_template, request

import scanner


app = Flask(__name__)
scan_lock = threading.Lock()
SUPPORTED_PORTS = {"http": 80, "https": 443}


def _normalize_allowlist_entry(entry):
    """Normalize a host rule; wildcard rules may cover subdomains, optionally on one port."""
    entry = entry.strip().lower()
    if not entry:
        return None

    wildcard = entry.startswith("*.")
    if wildcard:
        entry = entry[2:]

    port = None
    if entry.startswith("["):
        closing_bracket = entry.find("]")
        if closing_bracket < 0:
            return None
        host = entry[1:closing_bracket]
        suffix = entry[closing_bracket + 1:]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                return None
            port = int(suffix[1:])
    else:
        try:
            address = ipaddress.ip_address(entry)
        except ValueError:
            host_part, separator, port_part = entry.rpartition(":")
            if separator and port_part.isdigit():
                entry = host_part
                port = int(port_part)
            host = entry
        else:
            if wildcard:
                return None
            host = address.compressed
            return f"[{host}]" if address.version == 6 else host

    if port is not None and not 1 <= port <= 65535:
        return None
    host = host.rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not host or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            return None
        if wildcard:
            host = host.encode("idna").decode("ascii")
    else:
        if wildcard:
            return None
        host = address.compressed

    display_host = f"[{host}]" if ":" in host else host
    return (("*." if wildcard else "") + display_host + (f":{port}" if port else ""))


def configured_hosts():
    """Return normalized exact-host or wildcard-subdomain allowlist rules."""
    normalized_hosts = []
    for entry in os.environ.get("SECURESCAN_ALLOWED_HOSTS", "").split(","):
        normalized = _normalize_allowlist_entry(entry)
        if entry.strip() and normalized is None:
            return set()
        if normalized is not None:
            normalized_hosts.append(normalized)
    return set(normalized_hosts)


def _host_is_allowed(host, port, scheme, allowed_hosts=None):
    """Match exact hosts or explicit wildcard subdomains with optional port constraints."""
    allowed_hosts = configured_hosts() if allowed_hosts is None else allowed_hosts
    normalized_host = host.lower().rstrip(".")
    try:
        normalized_host = ipaddress.ip_address(normalized_host).compressed
    except ValueError:
        try:
            normalized_host = normalized_host.encode("idna").decode("ascii")
        except UnicodeError:
            return False

    for rule in allowed_hosts:
        if rule.startswith("["):
            closing_bracket = rule.find("]")
            rule_host = rule[1:closing_bracket]
            suffix = rule[closing_bracket + 1:]
            configured_port = int(suffix[1:]) if suffix.startswith(":") else None
        else:
            rule_host, separator, rule_port = rule.rpartition(":")
            configured_port = int(rule_port) if separator and rule_port.isdigit() else None
            if configured_port is None:
                rule_host = rule
        if configured_port is not None and configured_port != port:
            continue
        elif configured_port is None and port != SUPPORTED_PORTS[scheme]:
            continue
        pattern = rule_host
        if pattern.startswith("*."):
            pattern = "*." + pattern[2:].strip("[]")
        else:
            pattern = pattern.strip("[]")
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if normalized_host.endswith("." + suffix) and normalized_host != suffix:
                return True
        elif normalized_host == pattern:
            return True
    return False


def _host_resolves_only_to_public_addresses(hostname, port):
    try:
        addresses = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError):
        return False
    return bool(addresses) and all(address.is_global for address in addresses)


def _host_resolves_only_to_loopback_addresses(hostname, port):
    try:
        addresses = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError):
        return False
    return bool(addresses) and all(address.is_loopback for address in addresses)


def _loopback_targets_enabled():
    return os.environ.get("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "").strip().lower() in {
        "1", "true", "yes", "on"
    }


def validate_target_url(target_url):
    """Validate the target against the operator allowlist and public IP space."""
    if not isinstance(target_url, str) or not target_url.strip():
        return "Enter a target URL."
    if len(target_url) > 2048 or any(ord(character) < 32 for character in target_url):
        return "Enter a valid target URL."

    try:
        parsed = urlparse(target_url.strip())
        hostname = parsed.hostname
        explicit_port = parsed.port
    except ValueError:
        return "Enter a valid target URL."

    if parsed.scheme not in SUPPORTED_PORTS or not hostname:
        return "Use a complete HTTP or HTTPS URL."
    if parsed.username or parsed.password or parsed.fragment:
        return "Credentials and URL fragments are not supported."

    host = hostname.lower().rstrip(".")
    effective_port = explicit_port or SUPPORTED_PORTS[parsed.scheme]
    if not _host_is_allowed(host, effective_port, parsed.scheme):
        display_host = f"[{host}]" if ":" in host else host
        return (
            f"Target {display_host}:{effective_port} is not in the server's allowlist. "
            f"Add {display_host}:{effective_port} to SECURESCAN_ALLOWED_HOSTS and restart Flask."
        )

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if address is not None:
        if address.is_loopback:
            if not _loopback_targets_enabled():
                return "Loopback targets are disabled. Set SECURESCAN_ALLOW_LOOPBACK_TARGETS=1 for local testing."
        elif not address.is_global:
            return "Local, private, and reserved network addresses are not allowed."
    elif _loopback_targets_enabled() and host == "localhost":
        if not _host_resolves_only_to_loopback_addresses(host, effective_port):
            return "localhost must resolve exclusively to loopback IP addresses."
    elif not _host_resolves_only_to_public_addresses(host, effective_port):
        return "The target hostname must resolve exclusively to public IP addresses."

    return None


def validate_scanner_request_url(url):
    """Build a policy that limits scanner requests to the validated target origin."""
    try:
        target = urlparse(url)
        target_host = target.hostname.lower().rstrip(".")
    except (AttributeError, KeyError, ValueError) as error:
        raise requests.exceptions.InvalidURL("Invalid target URL.") from error

    def validate(url_to_check):
        try:
            parsed = urlparse(url_to_check)
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError as error:
            raise requests.exceptions.InvalidURL("Invalid scanner request URL.") from error
        if host != target_host:
            raise requests.exceptions.InvalidURL(
                "Scanner redirects must remain on the original authorized hostname."
            )

        # URL fragments are client-side only; browsers and requests do not send them.
        without_fragment = parsed._replace(fragment="").geturl()
        error = validate_target_url(without_fragment)
        if error:
            raise requests.exceptions.InvalidURL(error)

    return validate


def _validate_initial_target_url(url):
    """Validate a requested target before invoking the scanner."""
    error = validate_target_url(url)
    if error:
        return error
    return None


def normalize_finding(finding):
    """Map only fields that the scanner actually records."""
    normalized = {
        "severity": finding.get("severity"),
        "category": finding.get("type"),
        "affected_url": finding.get("url") or None,
        "description": finding.get("description") or None,
        "recommendation": finding.get("recommendation") or None,
    }
    technical_details = {
        key: finding.get(key) or None
        for key in ("cvss", "parameter", "payload", "matching_error", "header")
        if finding.get(key)
    }
    if technical_details:
        normalized["technical_details"] = technical_details
    return normalized


def run_scan(target_url):
    """Invoke the scanner's existing scan entry point and normalize its output."""
    raw_result = scanner.scan_website(
        target_url,
        request_url_validator=validate_scanner_request_url(target_url),
    )
    pages_scanned = raw_result["pages_scanned"]
    request_errors = raw_result["request_errors"]
    if pages_scanned == 0:
        scan_status = "failed"
    elif request_errors:
        scan_status = "partial"
    else:
        scan_status = "completed"

    response = {
        "scan_id": None,
        "target_url": target_url,
        "pages_scanned": pages_scanned,
        "findings": [normalize_finding(item) for item in raw_result["findings"]],
        "security_headers": raw_result["security_headers"],
        "scan_status": scan_status,
    }
    if scan_status == "failed":
        if request_errors:
            failures = _format_request_failures(request_errors)
            if "Timeout" in request_errors:
                response["error"] = "No target pages were retrieved before the scanner timed out. " + failures
            else:
                response["error"] = "No target pages could be retrieved. " + failures
        else:
            response["error"] = (
                "The scanner retrieved no target pages. Check that the URL serves a page."
            )
    elif scan_status == "partial":
        response["error"] = (
            _format_request_failures(request_errors) + " Results may be incomplete."
        )
    return response


def _format_request_failures(request_errors):
    counts = {}
    for error_name in request_errors:
        counts[error_name] = counts.get(error_name, 0) + 1
    summary = ", ".join(
        f"{name} ({count})" for name, count in sorted(counts.items())
    )
    return "Scanner request failures: " + summary + "."


@app.get("/")
def dashboard():
    return render_template(
        "index.html",
        scan_enabled=bool(configured_hosts()),
        loopback_enabled=_loopback_targets_enabled(),
    )


@app.post("/api/scan")
def scan():
    if not request.is_json:
        return jsonify(error="Send the scan request as JSON.", scan_status="rejected"), 415

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="The request body must be a JSON object.", scan_status="rejected"), 400

    if payload.get("authorized") is not True:
        return jsonify(
            error="Confirm that you own or are authorized to test this target.",
            scan_status="rejected",
        ), 400

    if not configured_hosts():
        current_app.logger.warning("Scan request rejected: allowlist is not configured")
        return jsonify(
            error=(
                "Scanning is disabled because SECURESCAN_ALLOWED_HOSTS is unset, empty, "
                "or contains invalid host entries."
            ),
            scan_status="rejected",
        ), 503

    target_url = payload.get("url")
    validation_error = _validate_initial_target_url(target_url)
    if validation_error:
        current_app.logger.warning(
            "Scan request rejected by target validation: %s",
            validation_error,
        )
        return jsonify(error=validation_error, scan_status="rejected"), 400

    if not scan_lock.acquire(blocking=False):
        current_app.logger.info("Scan request rejected: another scan is running")
        return jsonify(
            error="A scan is already running. Please try again after it finishes.",
            scan_status="rejected",
        ), 409

    try:
        current_app.logger.info("Scan request accepted")
        try:
            result = run_scan(target_url.strip())
        except requests.exceptions.Timeout as error:
            current_app.logger.error("SecureScan request timed out (%s)", type(error).__name__)
            return jsonify(
                scan_id=None,
                target_url=target_url.strip(),
                pages_scanned=0,
                findings=[],
                security_headers=None,
                scan_status="failed",
                error="The scanner timed out while waiting for the target.",
            ), 504
        except requests.exceptions.ConnectionError as error:
            current_app.logger.error("SecureScan connection failed (%s)", type(error).__name__)
            return jsonify(
                scan_id=None,
                target_url=target_url.strip(),
                pages_scanned=0,
                findings=[],
                security_headers=None,
                scan_status="failed",
                error="The scanner could not connect to the target. Check the URL, DNS, and network access.",
            ), 502
        except requests.exceptions.RequestException as error:
            current_app.logger.error("SecureScan request failed (%s)", type(error).__name__)
            return jsonify(
                scan_id=None,
                target_url=target_url.strip(),
                pages_scanned=0,
                findings=[],
                security_headers=None,
                scan_status="failed",
                error="The scanner rejected a request or redirect. Check the allowlist and target response.",
            ), 502
        except Exception as error:
            current_app.logger.error("Unexpected SecureScan error (%s)", type(error).__name__)
            return jsonify(
                scan_id=None,
                target_url=target_url.strip(),
                pages_scanned=0,
                findings=[],
                security_headers=None,
                scan_status="failed",
                error=(
                    "An unexpected scanner error occurred ("
                    + type(error).__name__
                    + "). Check the Flask server log."
                ),
            ), 500

        status_code = 200
        if result["scan_status"] == "failed":
            status_code = 504 if "timed out" in result.get("error", "").lower() else 502
        current_app.logger.info(
            "Scan finished: status=%s pages_scanned=%s",
            result["scan_status"],
            result["pages_scanned"],
        )
        return jsonify(result), status_code
    finally:
        scan_lock.release()


if __name__ == "__main__":
    app.run(debug=False)
