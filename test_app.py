import threading
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from unittest.mock import Mock, patch

import pytest
import requests

import app
import scanner


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", "127.0.0.1:8000")
    monkeypatch.delenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", raising=False)
    app.app.config.update(TESTING=True)
    return app.app.test_client()


def scan_request(client, url="http://127.0.0.1:8000/", authorized=True):
    return client.post("/api/scan", json={"url": url, "authorized": authorized})


def test_homepage_and_assets(client):
    assert client.get("/").status_code == 200
    assert client.get("/static/js/script.js").status_code == 200
    assert client.get("/static/css/style.css").status_code == 200


def test_api_routes_and_methods(client):
    assert app.app.url_map.iter_rules()
    assert client.get("/api/scan").status_code == 405


@pytest.mark.parametrize(
    ("url", "expected_error"),
    [
        ("", "Enter a target URL."),
        ("not a url", "Use a complete HTTP or HTTPS URL."),
        ("ftp://127.0.0.1:8000/", "Use a complete HTTP or HTTPS URL."),
        ("http://127.0.0.1:99999/", "Enter a valid target URL."),
        ("http://user:password@127.0.0.1:8000/", "Credentials and URL fragments are not supported."),
        ("http://127.0.0.1:8000/#fragment", "Credentials and URL fragments are not supported."),
    ],
)
def test_rejects_invalid_targets(client, url, expected_error):
    response = scan_request(client, url)
    assert response.status_code == 400
    assert expected_error in response.get_json()["error"]


def test_rejects_missing_url(client):
    response = client.post("/api/scan", json={"authorized": True})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Enter a target URL."


def test_missing_allowlist_fails_closed(client, monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", "")
    response = scan_request(client)
    assert response.status_code == 503
    assert "SECURESCAN_ALLOWED_HOSTS" in response.get_json()["error"]
    assert b"host allowlist is missing or invalid" in client.get("/").data


def test_malformed_allowlist_entry_fails_closed(client, monkeypatch):
    monkeypatch.setenv(
        "SECURESCAN_ALLOWED_HOSTS",
        "127.0.0.1:8000,not a valid host",
    )
    response = scan_request(client)
    assert response.status_code == 503
    assert app.configured_hosts() == set()
    assert b"host allowlist is missing or invalid" in client.get("/").data


def test_rejects_unlisted_host_with_actionable_message(client):
    response = scan_request(client, "http://localhost:8000/")
    assert response.status_code == 400
    assert "localhost:8000" in response.get_json()["error"]
    assert "SECURESCAN_ALLOWED_HOSTS" in response.get_json()["error"]


def test_rejects_wrong_port(client):
    response = scan_request(client, "http://127.0.0.1:8001/")
    assert response.status_code == 400
    assert "127.0.0.1:8001" in response.get_json()["error"]


def test_allowed_hostname_and_port_pass_server_validation(monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", "scan.example.test:8443")
    monkeypatch.setattr(app, "_host_resolves_only_to_public_addresses", lambda *_: True)
    assert app.validate_target_url("https://scan.example.test:8443/") is None
    assert app.validate_target_url("https://scan.example.test/") is not None


def test_dns_resolution_failure_blocks_target(monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", "scan.example.test:8443")
    monkeypatch.setattr(app, "_host_resolves_only_to_public_addresses", lambda *_: False)
    assert app.validate_target_url("https://scan.example.test:8443/") == (
        "The target hostname must resolve exclusively to public IP addresses."
    )


@pytest.mark.parametrize(
    ("host", "rule", "expected"),
    [
        ("example.com", "example.com", True),
        ("evil-example.com", "example.com", False),
        ("app.example.com", "*.example.com", True),
        ("example.com", "*.example.com", False),
    ],
)
def test_allowlist_host_matching_uses_exact_label_boundaries(host, rule, expected):
    assert app._host_is_allowed(host, 443, "https", {rule}) is expected


def test_loopback_is_blocked_without_explicit_opt_in(client):
    response = scan_request(client)
    assert response.status_code == 400
    assert "Loopback targets are disabled" in response.get_json()["error"]


def test_only_allowlisted_loopback_host_and_port_are_enabled(monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", "127.0.0.1:8000")
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    assert app.validate_target_url("http://127.0.0.1:8000/") is None
    assert app.validate_target_url("http://127.0.0.1:8001/") is not None
    assert app.validate_target_url("http://localhost:8000/") is not None


def test_private_ip_is_blocked_even_with_loopback_opt_in(monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", "192.168.1.2:8000")
    assert app.validate_target_url("http://192.168.1.2:8000/") is not None


def test_scanner_redirect_to_unlisted_host_is_rejected(monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", "127.0.0.1:8000")
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    validate = app.validate_scanner_request_url("http://127.0.0.1:8000/")
    response = Mock(status_code=302, headers={"Location": "http://127.0.0.1:8001/"}, url="http://127.0.0.1:8000/")
    with patch.object(requests, "request", return_value=response) as send:
        with scanner.scoped_requests(validate) as errors:
            with pytest.raises(requests.exceptions.InvalidURL):
                scanner._request("GET", "http://127.0.0.1:8000/", timeout=1)
    assert send.call_count == 1
    assert errors == ["InvalidURL"]


def test_same_host_redirect_requires_explicit_destination_port(monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", "127.0.0.1:8000,127.0.0.1:8443")
    validate = app.validate_scanner_request_url("http://127.0.0.1:8000/")
    validate("https://127.0.0.1:8443/")
    with pytest.raises(requests.exceptions.InvalidURL):
        validate("https://127.0.0.1:9443/")


@pytest.mark.parametrize(
    ("exception", "expected_status", "expected_message"),
    [
        (requests.Timeout(), 504, "timed out"),
        (requests.ConnectionError(), 502, "could not connect"),
    ],
)
def test_network_errors_return_useful_messages(
    client, monkeypatch, exception, expected_status, expected_message
):
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    with patch.object(app, "run_scan", side_effect=exception):
        response = scan_request(client)
    assert response.status_code == expected_status
    assert response.get_json()["scan_status"] == "failed"
    assert expected_message in response.get_json()["error"].lower()


def test_unexpected_scanner_error_does_not_expose_exception_text(client):
    with patch.object(app, "_host_is_allowed", return_value=True):
        with patch.object(app, "_host_resolves_only_to_public_addresses", return_value=True):
            with patch.object(app, "run_scan", side_effect=RuntimeError("secret value")):
                response = scan_request(client, "https://scan.example.test/")
    assert response.status_code == 500
    assert "RuntimeError" in response.get_json()["error"]
    assert "secret value" not in response.get_json()["error"]


def test_valid_scan_response_uses_scanner_results(client, monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    raw = {
        "pages_scanned": 2,
        "findings": [{
            "type": "Information Disclosure",
            "severity": "Low",
            "url": "http://127.0.0.1:8000/",
            "description": "Server header disclosed: test-server",
            "header": "",
            "matching_error": "",
            "payload": "",
            "parameter": "",
            "cvss": "3.5",
        }],
        "security_headers": [{"name": "X-Frame-Options", "status": "missing", "value": None}],
        "robots_paths": [],
        "request_errors": [],
    }
    with patch.object(app.scanner, "scan_website", return_value=raw) as scan_website:
        response = scan_request(client)
    body = response.get_json()
    scan_website.assert_called_once()
    assert response.status_code == 200
    assert body["scan_status"] == "completed"
    assert body["pages_scanned"] == 2
    assert body["findings"][0]["category"] == "Information Disclosure"
    assert body["findings"][0]["affected_url"] == "http://127.0.0.1:8000/"
    assert body["findings"][0]["technical_details"]["cvss"] == "3.5"
    assert body["security_headers"] == raw["security_headers"]


def test_empty_findings_are_returned_as_empty_not_fabricated(client, monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    raw = {
        "pages_scanned": 1,
        "findings": [],
        "security_headers": [],
        "robots_paths": [],
        "request_errors": [],
    }
    with patch.object(app.scanner, "scan_website", return_value=raw):
        response = scan_request(client)
    assert response.status_code == 200
    assert response.get_json()["findings"] == []
    assert response.get_json()["scan_status"] == "completed"


def test_report_generation_escapes_scanner_output_and_writes_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scanner.findings[:] = [{
        "type": "<script>alert(1)</script>",
        "severity": "Low",
        "cvss": "3.1",
        "url": "https://authorized.example.test/",
        "parameter": "",
        "payload": "",
        "matching_error": "",
        "header": "",
        "description": "",
    }]
    scanner.robots_paths_found.clear()
    with redirect_stdout(StringIO()):
        scanner.generate_html_report("https://authorized.example.test/", 1)
    report = (tmp_path / "reports" / "scan_report.html").read_text(encoding="utf-8")
    assert "&lt;script&gt;" in report
    assert "<script>alert(1)</script>" not in report


def test_scanner_form_detection_and_sql_signature(monkeypatch):
    response = Mock(text='<form action="/search" method="post"><input name="query"></form>')
    monkeypatch.setattr(scanner, "get_page_html", lambda _: response)
    forms = scanner.find_forms_on_page("http://127.0.0.1:8000/")
    assert forms == [{"action": "/search", "method": "post", "inputs": ["query"]}]
    assert scanner.response_has_sql_error("SQLite database error") == "sqlite"
    assert scanner.MAX_PAGES_TO_CRAWL == 10
    assert scanner.REQUEST_TIMEOUT == 5


def test_scan_lock_rejects_concurrent_scan(client, monkeypatch):
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    app.scan_lock.acquire()
    try:
        response = scan_request(client)
    finally:
        app.scan_lock.release()
    assert response.status_code == 409


def test_local_controlled_http_site_scan(client, monkeypatch, tmp_path):
    class LocalPage(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<!doctype html><html><body>Harmless local test page</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            del _format, _args

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalPage)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    monkeypatch.setenv("SECURESCAN_ALLOWED_HOSTS", f"127.0.0.1:{port}")
    monkeypatch.setenv("SECURESCAN_ALLOW_LOOPBACK_TARGETS", "1")
    monkeypatch.chdir(tmp_path)
    try:
        with redirect_stdout(StringIO()):
            response = scan_request(client, f"http://127.0.0.1:{port}/")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    body = response.get_json()
    assert response.status_code == 200
    assert body["scan_status"] == "completed"
    assert body["pages_scanned"] == 1
    assert isinstance(body["findings"], list)
    assert (tmp_path / "reports" / "scan_report.html").is_file()
