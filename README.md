# WappScan

> **Technology Stack Fingerprinting & CVE Discovery Tool**

WappScan is a Python command-line tool that combines accurate web technology fingerprinting with automated vulnerability lookup. It detects the technologies used by a target website using **Wappalyzer-next**, extracts version information when available, and queries the **Vulners API** to identify known CVEs affecting the detected software.

## Features

-  Detects web technologies (CMS, frameworks, servers, libraries, etc.)
-  Uses browser-based fingerprinting for improved detection accuracy
-  Searches for known CVEs using the Vulners API
-  Filter vulnerabilities by severity (Low / Medium / High / Critical)
-  Displays a clean, colorized report
-  Multiple scan modes (`fast`, `balanced`, `full`)
-  Confidence threshold filtering to reduce false positives

---

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/WappScan.git
cd WappScan
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

Install the Chromium browser required by Playwright:

```bash
python -m playwright install chromium
```

---

## Requirements

- Python 3.9+
- Playwright + Chromium
- Vulners API Key

Python dependencies:

- requests
- colorama
- wappalyzer-next

---

## Usage

```bash
python WappScan.py <url> -k <VULNERS_API_KEY>
```

Example:

```bash
python WappScan.py https://example.com -k YOUR_API_KEY
```

### Available options

| Option | Description |
|---------|-------------|
| `-k`, `--key` | Vulners API Key (required) |
| `-s`, `--severity` | Minimum severity (`low`, `medium`, `high`, `critical`) |
| `-v`, `--verbose` | Enable verbose output |
| `--scan-type` | `fast`, `balanced`, or `full` (default) |
| `--min-confidence` | Minimum confidence score (default: 50) |

Example:

```bash
python WappScan.py https://example.com \
    -k YOUR_API_KEY \
    --severity medium \
    --scan-type full \
    --min-confidence 70
```

---

## Example Output

```
============================================================
             TECHNOLOGIES DETECTED ON https://example.com
============================================================

Apache          2.4.58
PHP             8.2.1
WordPress       6.6

============================================================
           VULNERABILITIES FOUND (>= high)
============================================================

[9.8] CVE-2024-XXXX    WordPress 6.6 - Example vulnerability
[8.1] CVE-2023-YYYY    Apache 2.4.58 - Example vulnerability
```

---

# Legal Disclaimer

**This tool is intended exclusively for authorized security testing.**

You must only scan systems, applications, or networks for which you have **explicit permission** from the owner.

Unauthorized vulnerability scanning may violate local laws, regulations, or terms of service.

The author assumes **no responsibility or liability** for misuse of this software or any damages resulting from its use.

By using this project, you agree that you are solely responsible for ensuring your activities comply with all applicable laws and regulations.

---

# API Key Security

**Never commit your API key to this repository.**

Pass your Vulners API key as a command-line argument:

```bash
python WappScan.py https://target.com -k YOUR_API_KEY
```

---

# Project Structure

```
.
├── WappScan.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

# Acknowledgements

This project relies on the following open-source services and libraries:

- **Wappalyzer-next** for accurate web technology fingerprinting.
- **Vulners** for vulnerability intelligence and CVE lookup.
- **Playwright** for browser-based technology detection.

---

# License

This project is released under the MIT License.

See the `LICENSE` file for more information.
