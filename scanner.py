"""
Basic Web Vulnerability Scanner
--------------------------------
This is a SIMPLE, EDUCATIONAL tool written for learning purposes.

IMPORTANT LEGAL NOTICE:
Only run this scanner against websites you own OR have explicit written
permission to test. Scanning websites without permission may be illegal
in your country. This tool is not a professional security product.

What this script does (in plain English):
1. Prints a banner with the target URL.
2. Crawls a few pages of the target website (same domain only).
3. Finds HTML forms on those pages.
4. Tries a few simple XSS payloads to see if they get reflected back.
5. Tries a few simple SQL Injection payloads and looks for DB error messages.
6. Checks for "open redirect" style parameters (next=, url=, redirect=).
7. Checks for common security headers.
8. Checks for information disclosure (server banners, HTML comments).
9. Checks robots.txt for interesting paths.
10. Checks a few common directories for directory listing being enabled.
11. Prints everything in a simple, readable format.
12. Saves every finding into a simple HTML report (reports/scan_report.html).
""" 

import builtins
import os
import re
import argparse
import threading
from contextlib import contextmanager
from datetime import datetime
from html import escape as escape_html
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

# colorama is optional -- if it's not installed, the script still works,

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False


# ---------------------------------------------------------------------------
# SETTINGS 
# ---------------------------------------------------------------------------

MAX_PAGES_TO_CRAWL = 10          # keep the crawl small and fast
REQUEST_TIMEOUT = 5              # seconds to wait for a server response

# A few simple XSS test strings. 
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
]

# A few simple SQL Injection test strings.
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
]

# Common error message snippets that different databases print when they
# receive broken/malicious SQL. If we see one of these in the response,
# it's a strong hint that the input was passed straight into a SQL query.
SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "oracle",
    "odbc",
]

# Parameter names that commonly control redirects.
REDIRECT_PARAM_NAMES = ["next", "url", "redirect"]

# A harmless external URL we use to test for open redirects.
OPEN_REDIRECT_TEST_URL = "https://example.com"

# Security headers every modern website should ideally have.
SECURITY_HEADERS_TO_CHECK = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

# A few common directories that sometimes have directory listing left on
# by mistake. 
COMMON_DIRECTORIES_TO_CHECK = [
    "/uploads/",
    "/images/",
    "/backup/",
    "/files/",
    "/assets/",
]

# Text that usually appears on a page when directory listing is enabled.
DIRECTORY_LISTING_SIGNATURES = [
    "index of /",
    "directory listing",
    "parent directory",
]

# Fixed severity and CVSS values for each vulnerability type. These are
# NOT calculated dynamically -- they are simple, static reference values
# used to make the HTML report look more like a real security report.
SEVERITY_INFO = {
    "SQL Injection": {"severity": "Critical", "cvss": "9.8"},
    "Reflected XSS": {"severity": "Medium", "cvss": "6.1"},
    "Open Redirect": {"severity": "Medium", "cvss": "5.4"},
    "Directory Listing": {"severity": "Low", "cvss": "3.7"},
    "Missing Security Headers": {"severity": "Low", "cvss": "3.1"},
    "Information Disclosure": {"severity": "Low", "cvss": "3.5"},
}

# The order we want vulnerability types to appear in the report's summary table.
VULNERABILITY_TYPES_IN_ORDER = [
    "Reflected XSS",
    "SQL Injection",
    "Open Redirect",
    "Directory Listing",
    "Missing Security Headers",
    "Information Disclosure",
]


# ---------------------------------------------------------------------------
# SHARED DATA: every finding gets stored here as a simple dictionary,
# instead of only being printed and forgotten. Both the terminal output
# and the HTML report are built from this same list.
# ---------------------------------------------------------------------------

findings = []          # list of dictionaries, one per vulnerability found
robots_paths_found = []  # list of "Disallow:"/"Allow:" lines from robots.txt
_request_scope = threading.local()


@contextmanager
def scoped_requests(url_validator, quiet=False):
    """Apply a URL validation policy to requests made during an API scan."""
    previous_validator = getattr(_request_scope, "url_validator", None)
    previous_errors = getattr(_request_scope, "errors", None)
    previous_quiet = getattr(_request_scope, "quiet", False)
    _request_scope.url_validator = url_validator
    _request_scope.errors = []
    _request_scope.quiet = quiet
    try:
        yield _request_scope.errors
    finally:
        if previous_validator is None:
            del _request_scope.url_validator
        else:
            _request_scope.url_validator = previous_validator
        if previous_errors is None:
            del _request_scope.errors
        else:
            _request_scope.errors = previous_errors
        _request_scope.quiet = previous_quiet


def print(*args, **kwargs):
    """Keep CLI output while avoiding URL and payload leakage from API scans."""
    if not getattr(_request_scope, "quiet", False):
        builtins.print(*args, **kwargs)


def _request(method, url, **kwargs):
    """Send a legacy request, enforcing scan scope and safe redirects in API mode."""
    url_validator = getattr(_request_scope, "url_validator", None)
    if url_validator is None:
        return getattr(requests, method.lower())(url, **kwargs)

    errors = _request_scope.errors
    follow_redirects = kwargs.pop("allow_redirects", True)
    current_url = url
    current_method = method.upper()

    for redirect_number in range(6):
        try:
            url_validator(current_url)
            response = requests.request(
                current_method,
                current_url,
                allow_redirects=False,
                **kwargs
            )
        except requests.exceptions.RequestException as error:
            errors.append(type(error).__name__)
            raise

        if response.status_code >= 500:
            errors.append("HTTP " + str(response.status_code))

        if not follow_redirects or response.status_code not in (301, 302, 303, 307, 308):
            return response

        location = response.headers.get("Location")
        if not location:
            return response
        if redirect_number == 5:
            error = requests.exceptions.TooManyRedirects("Too many redirects")
            errors.append(str(error))
            raise error

        current_url = urljoin(response.url or current_url, location)
        kwargs.pop("params", None)
        if response.status_code == 303 or (
            response.status_code in (301, 302) and current_method == "POST"
        ):
            current_method = "GET"
            kwargs.pop("data", None)
            kwargs.pop("json", None)
            kwargs.pop("files", None)

    raise requests.exceptions.TooManyRedirects("Too many redirects")


def add_finding(vulnerability_type, url="", parameter="", payload="",
                 matching_error="", header="", description=""):
    """
    Save one finding into the shared findings list.
    The severity and CVSS score are looked up automatically from
    SEVERITY_INFO, so we don't have to type them every time.
    """
    severity_data = SEVERITY_INFO.get(vulnerability_type, {"severity": "Unknown", "cvss": "N/A"})

    finding = {
        "type": vulnerability_type,
        "severity": severity_data["severity"],
        "cvss": severity_data["cvss"],
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "matching_error": matching_error,
        "header": header,
        "description": description,
    }
    findings.append(finding)


# ---------------------------------------------------------------------------
# SMALL HELPER FUNCTIONS FOR PRINTING NICE OUTPUT
# ---------------------------------------------------------------------------

def print_good(message):
    """Print a positive/found result, e.g. a vulnerability was found."""
    if COLOR_ENABLED:
        print(Fore.RED + "[+] " + message + Style.RESET_ALL)
    else:
        print("[+] " + message)


def print_info(message):
    """Print a neutral, informational line."""
    if COLOR_ENABLED:
        print(Fore.CYAN + "[*] " + message + Style.RESET_ALL)
    else:
        print("[*] " + message)


def print_bad(message):
    """Print a 'not detected' / negative result."""
    if COLOR_ENABLED:
        print(Fore.GREEN + "[-] " + message + Style.RESET_ALL)
    else:
        print("[-] " + message)


def print_warning(message):
    """Print a warning, e.g. a missing security header."""
    if COLOR_ENABLED:
        print(Fore.YELLOW + "[!] " + message + Style.RESET_ALL)
    else:
        print("[!] " + message)


# ---------------------------------------------------------------------------
# 1. BANNER
# ---------------------------------------------------------------------------

def print_banner(target_url):
    """Print a simple ASCII banner and show the target URL."""
    print("=" * 60)
    print("      BASIC WEB VULNERABILITY SCANNER (Educational)")
    print("=" * 60)
    print("Target URL : " + target_url)
    print("WARNING    : Only scan sites you own or have permission to test.")
    print("=" * 60)
    print()


# ---------------------------------------------------------------------------
# 2. CRAWLER
# ---------------------------------------------------------------------------

def get_page_html(url):
    """
    Try to download a page's HTML.
    Returns the response object, or None if something went wrong.
    """
    try:
        response = _request("GET", url, timeout=REQUEST_TIMEOUT)
        return response
    except requests.exceptions.RequestException as error:
        print_warning("Could not fetch " + url + " (" + str(error) + ")")
        return None


def is_same_domain(base_url, link_url):
    """Check whether link_url belongs to the same domain as base_url."""
    base_domain = urlparse(base_url).netloc
    link_domain = urlparse(link_url).netloc
    # If the link has no domain (relative link), treat it as same domain.
    return link_domain == "" or link_domain == base_domain


def crawl_website(start_url):
    """
    Crawl the website starting from start_url.
    Only follows links on the same domain, and stops after
    MAX_PAGES_TO_CRAWL pages to keep things fast and simple.

    Returns a list of visited page URLs.
    """
    print_info("Starting crawl (max " + str(MAX_PAGES_TO_CRAWL) + " pages)...")

    pages_to_visit = [start_url]
    visited_pages = []

    while pages_to_visit and len(visited_pages) < MAX_PAGES_TO_CRAWL:
        current_url = pages_to_visit.pop(0)

        if current_url in visited_pages:
            continue

        response = get_page_html(current_url)
        if response is None:
            continue

        visited_pages.append(current_url)
        print_info("Visited: " + current_url)

        # Parse the page and look for more links to follow.
        soup = BeautifulSoup(response.text, "html.parser")
        for link_tag in soup.find_all("a", href=True):
            full_link = urljoin(current_url, link_tag["href"])

            if is_same_domain(start_url, full_link) and full_link not in visited_pages:
                if full_link not in pages_to_visit:
                    pages_to_visit.append(full_link)

    print_info("Crawl finished. Total pages visited: " + str(len(visited_pages)))
    print()
    return visited_pages


# ---------------------------------------------------------------------------
# 3. FORM DETECTION
# ---------------------------------------------------------------------------

def find_forms_on_page(page_url):
    """
    Download a page and return a list of dictionaries describing each
    HTML form found on it (action, method, and input field names).
    """
    response = get_page_html(page_url)
    if response is None:
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    forms_found = []

    for form_tag in soup.find_all("form"):
        form_info = {
            "action": form_tag.get("action", "").strip(),
            "method": form_tag.get("method", "get").strip().lower(),
            "inputs": [],
        }

        # Look at every input, textarea, and select field inside the form.
        for input_tag in form_tag.find_all(["input", "textarea", "select"]):
            input_name = input_tag.get("name")
            if input_name:
                form_info["inputs"].append(input_name)

        forms_found.append(form_info)

    return forms_found


def show_forms(page_url, forms_found):
    """Print out the details of forms found on a page."""
    if not forms_found:
        return

    print_info("Forms found on " + page_url + ":")
    for form in forms_found:
        print("    Action : " + (form["action"] if form["action"] else "(same page)"))
        print("    Method : " + form["method"].upper())
        print("    Inputs : " + ", ".join(form["inputs"]) if form["inputs"] else "    Inputs : (none)")
        print("    ---")
    print()


# ---------------------------------------------------------------------------
# 4. XSS SCANNER (Reflected XSS only)
# ---------------------------------------------------------------------------

def test_xss_on_form(page_url, form):
    """
    Submit each XSS payload into every input field of a form, one field
    at a time, and check whether the payload is reflected back unescaped
    in the response HTML. If it is, we report it as Reflected XSS.

    Returns True if at least one payload was reflected, otherwise False.
    """
    if not form["inputs"]:
        return False

    target_action_url = urljoin(page_url, form["action"]) if form["action"] else page_url
    xss_was_found = False

    for payload in XSS_PAYLOADS:
        # Build form data: put the payload in every field.
        form_data = {}
        for input_name in form["inputs"]:
            form_data[input_name] = payload

        try:
            if form["method"] == "post":
                response = _request("POST", target_action_url, data=form_data, timeout=REQUEST_TIMEOUT)
            else:
                response = _request("GET", target_action_url, params=form_data, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException:
            continue

        # If the exact payload text appears unescaped in the HTML, it's
        # very likely a Reflected XSS vulnerability.
        if payload in response.text:
            print_good("Reflected XSS Found")
            print("    URL     : " + target_action_url)
            print("    Payload : " + payload)
            print()
            add_finding(
                "Reflected XSS",
                url=target_action_url,
                payload=payload,
                description="The payload was reflected in the HTTP response."
            )
            xss_was_found = True

    return xss_was_found


def scan_forms_for_xss(pages_with_forms):
    """Run the XSS test against every form found on every crawled page."""
    print_info("Testing forms for Reflected XSS...")
    print_info("Note: This scanner can ONLY detect simple Reflected XSS.")
    print_info("Stored XSS and DOM-based XSS cannot be reliably found this way.")
    print()

    found_any = False
    for page_url, forms_found in pages_with_forms:
        for form in forms_found:
            if test_xss_on_form(page_url, form):
                found_any = True

    if not found_any:
        print_bad("Reflected XSS Not Detected")
        print()


# ---------------------------------------------------------------------------
# 5. SQL INJECTION SCANNER (error-based only)
# ---------------------------------------------------------------------------

def response_has_sql_error(response_text):
    """
    Check the response text for common SQL error message snippets.
    Returns the matching snippet, or None if nothing matched.
    """
    lowered_text = response_text.lower()
    for signature in SQL_ERROR_SIGNATURES:
        if signature in lowered_text:
            return signature
    return None


def test_sqli_on_url(page_url):
    """
    If the URL has query parameters (like ?id=5), try replacing each
    parameter value with SQL injection payloads and check the response
    for database error messages.
    """
    parsed_url = urlparse(page_url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return False

    found_vulnerability = False

    for param_name in query_params:
        for payload in SQLI_PAYLOADS:
            # Build a copy of the query parameters with this one changed.
            test_params = {key: value[0] for key, value in query_params.items()}
            test_params[param_name] = payload

            test_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                urlencode(test_params),
                parsed_url.fragment,
            ))

            response = get_page_html(test_url)
            if response is None:
                continue

            matching_error = response_has_sql_error(response.text)
            if matching_error:
                print_good("Possible SQL Injection Found")
                print("    URL     : " + page_url)
                print("    Parameter : " + param_name)
                print("    Payload : " + payload)
                print("    Matching error : " + matching_error)
                print()
                add_finding(
                    "SQL Injection",
                    url=page_url,
                    parameter=param_name,
                    payload=payload,
                    matching_error=matching_error,
                    description="A database error message was returned after sending a malicious payload."
                )
                found_vulnerability = True

    return found_vulnerability


def scan_pages_for_sqli(visited_pages):
    """Run the SQL injection test against every crawled page URL."""
    print_info("Testing URL parameters for SQL Injection...")
    print()

    found_any = False
    for page_url in visited_pages:
        if test_sqli_on_url(page_url):
            found_any = True

    if not found_any:
        print_bad("SQL Injection Not Detected")
        print()


# ---------------------------------------------------------------------------
# 6. OPEN REDIRECT CHECK
# ---------------------------------------------------------------------------

def test_open_redirect_on_url(page_url):
    """
    If the URL has a parameter that looks like it controls redirection
    (next=, url=, redirect=), try replacing it with a harmless external
    URL and see if the server actually redirects us there.
    """
    parsed_url = urlparse(page_url)
    query_params = parse_qs(parsed_url.query)

    found_vulnerability = False

    for param_name in query_params:
        if param_name.lower() not in REDIRECT_PARAM_NAMES:
            continue

        test_params = {key: value[0] for key, value in query_params.items()}
        test_params[param_name] = OPEN_REDIRECT_TEST_URL

        test_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            urlencode(test_params),
            parsed_url.fragment,
        ))

        try:
            response = _request("GET", test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue

        # If the server responds with a redirect (3xx) pointing to our
        # harmless test URL, that's a possible open redirect.
        location_header = response.headers.get("Location", "")
        if response.status_code in (301, 302, 303, 307, 308) and OPEN_REDIRECT_TEST_URL in location_header:
            print_good("Possible Open Redirect Found")
            print("    URL       : " + page_url)
            print("    Parameter : " + param_name)
            print("    Redirects to : " + location_header)
            print()
            add_finding(
                "Open Redirect",
                url=page_url,
                parameter=param_name,
                payload=OPEN_REDIRECT_TEST_URL,
                description="This parameter allowed the page to redirect to an external website."
            )
            found_vulnerability = True

    return found_vulnerability


def scan_pages_for_open_redirect(visited_pages):
    """Run the open redirect test against every crawled page URL."""
    print_info("Checking for Open Redirect parameters...")
    print()

    found_any = False
    for page_url in visited_pages:
        if test_open_redirect_on_url(page_url):
            found_any = True

    if not found_any:
        print_bad("Open Redirect Not Detected")
        print()


# ---------------------------------------------------------------------------
# 7. SECURITY HEADERS CHECK
# ---------------------------------------------------------------------------

def check_security_headers(target_url):
    """Check the presence of important security-related HTTP headers."""
    print_info("Checking Security Headers...")

    response = get_page_html(target_url)
    if response is None:
        print_warning("Could not check headers (page could not be loaded).")
        print()
        return None

    header_results = []
    for header_name in SECURITY_HEADERS_TO_CHECK:
        if header_name in response.headers:
            print("    " + header_name + " : Present")
            header_results.append({
                "name": header_name,
                "status": "present",
                "value": response.headers.get(header_name),
            })
        else:
            print_warning("Missing Security Header: " + header_name)
            header_results.append({
                "name": header_name,
                "status": "missing",
                "value": None,
            })
            add_finding(
                "Missing Security Headers",
                url=target_url,
                header=header_name,
                description="This security header was not found in the HTTP response."
            )
    print()
    return header_results


# ---------------------------------------------------------------------------
# 8. INFORMATION DISCLOSURE
# ---------------------------------------------------------------------------

def check_information_disclosure(target_url):
    """
    Look for information the server might be leaking accidentally:
    - Server header (e.g. "Apache/2.4.41")
    - X-Powered-By header (e.g. "PHP/7.4.3")
    - Version numbers left behind in HTML comments
    """
    print_info("Checking for Information Disclosure...")

    response = get_page_html(target_url)
    if response is None:
        print_warning("Could not check information disclosure (page could not be loaded).")
        print()
        return

    server_header = response.headers.get("Server")
    if server_header:
        print_warning("Server header disclosed: " + server_header)
        add_finding(
            "Information Disclosure",
            url=target_url,
            description="Server header disclosed: " + server_header
        )

    powered_by_header = response.headers.get("X-Powered-By")
    if powered_by_header:
        print_warning("X-Powered-By header disclosed: " + powered_by_header)
        add_finding(
            "Information Disclosure",
            url=target_url,
            description="X-Powered-By header disclosed: " + powered_by_header
        )

    # Look inside HTML comments for anything that looks like a version
    # number, e.g. <!-- version 1.2.3 -->
    html_comments = re.findall(r"<!--(.*?)-->", response.text, re.DOTALL)
    version_pattern = re.compile(r"v(?:ersion)?\s*[:\-]?\s*\d+(\.\d+)+", re.IGNORECASE)

    for comment in html_comments:
        if version_pattern.search(comment):
            print_warning("Possible version info in HTML comment: " + comment.strip())
            add_finding(
                "Information Disclosure",
                url=target_url,
                description="Version information found in an HTML comment: " + comment.strip()
            )

    if not server_header and not powered_by_header:
        print_bad("No obvious information disclosure headers found.")

    print()


# ---------------------------------------------------------------------------
# 9. ROBOTS.TXT CHECK
# ---------------------------------------------------------------------------

def check_robots_txt(target_url):
    """Check whether robots.txt exists and print any paths it lists."""
    print_info("Checking robots.txt...")

    robots_url = urljoin(target_url, "/robots.txt")
    response = get_page_html(robots_url)

    if response is None or response.status_code != 200:
        print_bad("robots.txt not found.")
        print()
        return

    print_good("robots.txt found: " + robots_url)

    # Print any "Disallow:" or "Allow:" lines, which reveal paths the
    # site owner doesn't want search engines to index (sometimes these
    # are sensitive areas of the site).
    for line in response.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
            print("    " + line)
            robots_paths_found.append(line)
    print()


# ---------------------------------------------------------------------------
# 10. DIRECTORY LISTING CHECK
# ---------------------------------------------------------------------------

def check_directory_listing(target_url):
    """
    Request a handful of common directory names (like /uploads/) and see
    if the server responds with a raw directory listing instead of a
    normal page or a 404. This often happens when a web server has
    "directory browsing" left switched on by mistake.
    """
    print_info("Checking common directories for Directory Listing...")

    found_any = False

    for directory in COMMON_DIRECTORIES_TO_CHECK:
        test_url = urljoin(target_url, directory)
        response = get_page_html(test_url)

        if response is None:
            continue

        lowered_text = response.text.lower()

        for signature in DIRECTORY_LISTING_SIGNATURES:
            if signature in lowered_text:
                print_good("Possible Directory Listing Enabled")
                print("    URL : " + test_url)
                print()
                add_finding(
                    "Directory Listing",
                    url=test_url,
                    description="The server appears to be showing a raw directory listing instead of a normal page."
                )
                found_any = True
                break  # no need to check the other signatures for this URL

    if not found_any:
        print_bad("Directory Listing Not Detected")
        print()


# ---------------------------------------------------------------------------
# 11. HTML REPORT GENERATION
# ---------------------------------------------------------------------------

def build_summary_table_rows():
    """
    Build the HTML rows for the summary table. Every fixed vulnerability
    type gets one row, showing "Found" if at least one matching finding
    exists in the findings list, otherwise "Not Found".
    """
    rows_html = ""

    for vulnerability_type in VULNERABILITY_TYPES_IN_ORDER:
        severity_data = SEVERITY_INFO[vulnerability_type]

        # Check if we already recorded a finding of this type.
        was_found = False
        for finding in findings:
            if finding["type"] == vulnerability_type:
                was_found = True
                break

        status_text = "Found" if was_found else "Not Found"
        status_css_class = "status-found" if was_found else "status-not-found"

        rows_html += "<tr>"
        rows_html += "<td>" + escape_html(vulnerability_type) + "</td>"
        rows_html += "<td>" + escape_html(severity_data["severity"]) + "</td>"
        rows_html += "<td>" + escape_html(severity_data["cvss"]) + "</td>"
        rows_html += "<td class='" + status_css_class + "'>" + status_text + "</td>"
        rows_html += "</tr>\n"

    return rows_html


def build_detailed_findings_html():
    """Build the HTML for the "Detailed Findings" section, one block per finding."""
    if not findings:
        return "<p>No vulnerabilities were found during this scan.</p>"

    details_html = ""

    for finding in findings:
        details_html += "<div class='finding'>\n"
        details_html += "<h3>" + escape_html(finding["type"]) + "</h3>\n"
        details_html += "<p><strong>Severity:</strong> " + escape_html(finding["severity"]) + "</p>\n"
        details_html += "<p><strong>CVSS:</strong> " + escape_html(finding["cvss"]) + "</p>\n"

        if finding["url"]:
            details_html += "<p><strong>URL:</strong> " + escape_html(finding["url"]) + "</p>\n"

        if finding["parameter"]:
            details_html += "<p><strong>Parameter:</strong> " + escape_html(finding["parameter"]) + "</p>\n"

        if finding["payload"]:
            details_html += "<p><strong>Payload:</strong> " + escape_html(finding["payload"]) + "</p>\n"

        if finding["matching_error"]:
            details_html += "<p><strong>Matching SQL Error:</strong> " + escape_html(finding["matching_error"]) + "</p>\n"

        if finding["header"]:
            details_html += "<p><strong>Missing Header:</strong> " + escape_html(finding["header"]) + "</p>\n"

        if finding["description"]:
            details_html += "<p><strong>Description:</strong> " + escape_html(finding["description"]) + "</p>\n"

        details_html += "</div>\n"

    return details_html


def build_robots_txt_html():
    """Build the HTML list of paths discovered in robots.txt."""
    if not robots_paths_found:
        return "<p>No robots.txt paths were discovered.</p>"

    list_html = "<ul>\n"
    for path_line in robots_paths_found:
        list_html += "<li>" + escape_html(path_line) + "</li>\n"
    list_html += "</ul>\n"
    return list_html


def generate_html_report(target_url, total_pages_crawled):
    """
    Build a simple HTML report from everything stored in the findings
    list (and the robots.txt paths list), then save it to
    reports/scan_report.html. The folder is created automatically if it
    doesn't already exist.
    """
    print_info("Generating HTML report...")

    # Create the "reports" folder if it isn't there yet.
    if not os.path.exists("reports"):
        os.makedirs("reports")

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary_rows_html = build_summary_table_rows()
    details_html = build_detailed_findings_html()
    robots_html = build_robots_txt_html()

    # A small amount of inline CSS keeps this a single, simple file with
    # no external template files needed.
    html_report = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Web Vulnerability Scan Report</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 30px; color: #222; }}
    h1 {{ color: #333; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 15px; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background-color: #eeeeee; }}
    .status-found {{ color: #b30000; font-weight: bold; }}
    .status-not-found {{ color: #007a00; font-weight: bold; }}
    .finding {{ border: 1px solid #ddd; padding: 12px; margin-top: 12px; background-color: #fafafa; }}
    .finding h3 {{ margin-top: 0; }}
    .footer {{ margin-top: 40px; font-size: 0.9em; color: #666; }}
</style>
</head>
<body>

<h1>Web Vulnerability Scan Report</h1>

<p><strong>Scan Date &amp; Time:</strong> {scan_time}</p>
<p><strong>Target URL:</strong> {target_url}</p>
<p><strong>Total Pages Crawled:</strong> {total_pages_crawled}</p>

<h2>Summary Table</h2>
<table>
<tr><th>Vulnerability</th><th>Severity</th><th>CVSS</th><th>Status</th></tr>
{summary_rows_html}
</table>

<h2>Detailed Findings</h2>
{details_html}

<h2>robots.txt Findings</h2>
{robots_html}

<div class="footer">
<p>Scan Complete</p>
<p>This report was generated by the Basic Educational Web Vulnerability Scanner.</p>
</div>

</body>
</html>
""".format(
        scan_time=escape_html(scan_time),
        target_url=escape_html(target_url),
        total_pages_crawled=total_pages_crawled,
        summary_rows_html=summary_rows_html,
        details_html=details_html,
        robots_html=robots_html,
    )

    report_path = os.path.join("reports", "scan_report.html")
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write(html_report)

    print_good("HTML report saved to: " + report_path)
    print()


# ---------------------------------------------------------------------------
# MAIN PROGRAM
# ---------------------------------------------------------------------------

def scan_website(target_url, request_url_validator=None):
    """Run the existing scan checks and generate the standard HTML report."""
    findings.clear()
    robots_paths_found.clear()

    with scoped_requests(
        request_url_validator,
        quiet=request_url_validator is not None,
    ) as request_errors:
        visited_pages = crawl_website(target_url)

        pages_with_forms = []
        for page_url in visited_pages:
            forms_found = find_forms_on_page(page_url)
            show_forms(page_url, forms_found)
            pages_with_forms.append((page_url, forms_found))

        scan_forms_for_xss(pages_with_forms)
        scan_pages_for_sqli(visited_pages)
        scan_pages_for_open_redirect(visited_pages)
        security_headers = check_security_headers(target_url)
        check_information_disclosure(target_url)
        check_robots_txt(target_url)
        check_directory_listing(target_url)
        generate_html_report(target_url, len(visited_pages))

        return {
            "pages_scanned": len(visited_pages),
            "findings": [dict(finding) for finding in findings],
            "robots_paths": list(robots_paths_found),
            "security_headers": security_headers,
            "request_errors": list(request_errors),
        }


def main():
    """Parse command line arguments and run all the scans in order."""
    parser = argparse.ArgumentParser(
        description="A basic, educational web vulnerability scanner."
    )
    parser.add_argument(
        "url",
        help="The target URL to scan, e.g. http://testphp.vulnweb.com"
    )
    arguments = parser.parse_args()
    target_url = arguments.url

    print_banner(target_url)
    scan_website(target_url)

    print("=" * 60)
    print("Scan complete. Remember: this is an educational tool only.")
    print("=" * 60)


if __name__ == "__main__":
    main()
