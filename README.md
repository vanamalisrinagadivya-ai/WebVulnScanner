## 🚀 How to Run SecureScan

Follow these steps to run SecureScan on Windows.

### 1. Prerequisites

Install the following software:

- **Python 3.8 or newer**
- **Git**
- A web browser

Verify that Python and Git are installed by opening PowerShell and running:

```powershell
python --version
git --version
```

### 2. Clone the repository

Open PowerShell and run:

```powershell
git clone https://github.com/Sandeep961890/SecureScan.git
cd SecureScan
```

### 3. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If activation is blocked, use the virtual environment's Python executable directly instead.

### 4. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 5. Start the Flask dashboard

For a public website, configure the allowlist with a hostname you own or have explicit permission to test.

```powershell
$env:SECURESCAN_ALLOWED_HOSTS = 'staging.yourdomain.com'
python app.py
```

Replace `staging.yourdomain.com` with your authorized target hostname.

Open the dashboard in your browser:

**http://127.0.0.1:5000/**

Enter the authorized target URL in the dashboard and confirm authorization if prompted.

> **Important:** The target must match the configured allowlist. Do not scan third-party websites without permission.

### 6. Test SecureScan locally

You can test the application using a harmless local HTML page instead of a real website.

**PowerShell Window 1 — Start a local test website**

```powershell
$testSite = Join-Path $env:TEMP 'securescan-local-test'
New-Item -ItemType Directory -Force -Path $testSite | Out-Null

@'
<!doctype html>
<html>
<head><title>SecureScan Test Page</title></head>
<body>
  <h1>SecureScan Local Test Page</h1>
  <p>This page is for testing the scanner locally.</p>
</body>
</html>
'@ | Set-Content -Encoding utf8 (Join-Path $testSite 'index.html')

Set-Location $testSite
python -m http.server 8000 --bind 127.0.0.1
```

Keep this terminal open. Your local test page will be available at:

http://127.0.0.1:8000/

**PowerShell Window 2 — Start SecureScan**

Open another PowerShell window and navigate to the cloned project directory:

```powershell
Set-Location 'C:\path\to\SecureScan'
```

Replace the example path with the actual directory where you cloned the repository.

Configure the local target and start the dashboard:

```powershell
$env:SECURESCAN_ALLOWED_HOSTS = '127.0.0.1:8000'
$env:SECURESCAN_ALLOW_LOOPBACK_TARGETS = '1'
python app.py
```

These settings work only if the application implements the documented loopback opt-in and exact host-and-port validation.

Open **http://127.0.0.1:5000/** and enter this target:

```text
http://127.0.0.1:8000/
```

Do not enter port `5000` as the scan target; that port serves the SecureScan dashboard.

### 7. Run the command-line scanner

If the repository includes `scanner.py`, start the local test server first, open another terminal in the project directory, and run:

```powershell
python scanner.py http://127.0.0.1:8000/
```

If supported by the implementation, the scan report will be generated at:

```text
reports/scan_report.html
```

Open the HTML report in your browser.

### 8. Run tests

If the repository includes a pytest test suite, run:

```powershell
python -m pytest -q
```

A missing test suite or an empty test run does not confirm that the application is working correctly.

### 9. Troubleshooting

**Python is not recognized**

Install Python, enable the option to add Python to PATH, reopen PowerShell, and verify with `python --version`.

**Missing module errors**

Activate the correct virtual environment and run:

```powershell
python -m pip install -r requirements.txt
```

**Target rejected by the authorized-host allowlist**

- Check the `SECURESCAN_ALLOWED_HOSTS` value.
- Include the port for non-standard ports, such as `127.0.0.1:8000`.
- Confirm that loopback testing is explicitly enabled when testing locally.
- Restart Flask after changing environment variables.
- Review the application's target-validation code and terminal logs if the rejection continues.

**No vulnerabilities detected**

A clean scan does not prove that a website is secure. This project uses limited heuristic checks and can produce false positives and false negatives.

### 10. Stop the application

Press `Ctrl+C` in each terminal running a server.

### ⚠️ Security Notice

SecureScan is an educational web vulnerability scanner. Use it only on systems you own or are explicitly authorized to assess. It is not a replacement for professional security testing.
i want to all the files 