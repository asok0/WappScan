"""
WappScan - Technology stack scanner and CVE lookup tool.

This tool combines two capabilities:
1. Technology fingerprinting via Wappalyzer-next (wraps the official Wappalyzer
   browser extension through a headless Chromium instance for accurate detection
   of frameworks, CMS, servers, and libraries used by a target website).
2. Vulnerability lookup via the Vulners API (v4 "audit/software" endpoint),
   matching each detected technology/version pair against known CVEs.

Usage:
    python wapp_final.py <url> -k <vulners_api_key> [options]

Requirements:
    pip install wappalyzer requests colorama
    python -m playwright install chromium
"""

import argparse
import requests
from wappalyzer import analyze
from colorama import init, Fore, Style

# Enable ANSI color support on Windows terminals and auto-reset color codes
# after each print() call, so we don't have to manually reset styling everywhere.
init(autoreset=True)

# Approximate CVSS score thresholds used to bucket vulnerabilities into
# severity tiers. These are heuristic cutoffs (not an official CVSS standard)
# chosen to give sensible filtering behavior for the --severity flag.
SEVERITY_THRESHOLDS = {
    "low": 0.0,
    "medium": 4.0,
    "high": 7.0,
    "critical": 9.0,
}


def severity_color(cvss_score):
    """
    Map a CVSS score to a colorama color code for terminal output.

    Args:
        cvss_score: Numeric CVSS score (int/float), or a value that can be
            cast to float. Non-numeric or missing values fall back to white.

    Returns:
        str: A colorama Fore/Style escape sequence corresponding to the
        severity tier of the given score.
    """
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return Fore.WHITE
    if score >= 9.0:
        return Fore.MAGENTA + Style.BRIGHT
    if score >= 7.0:
        return Fore.RED
    if score >= 4.0:
        return Fore.YELLOW
    return Fore.GREEN


def print_header(text):
    """Print a centered, boxed section title (used for major report sections)."""
    width = 60
    print("\n" + Fore.CYAN + Style.BRIGHT + "=" * width)
    print(Fore.CYAN + Style.BRIGHT + text.center(width))
    print(Fore.CYAN + Style.BRIGHT + "=" * width)


def print_section(text):
    """Print a lightweight inline subsection divider (used within a report)."""
    print("\n" + Fore.BLUE + Style.BRIGHT + f"── {text} " + "─" * max(0, 55 - len(text)))


def print_banner():
    """
    Print the tool's ASCII art banner and tagline at startup.

    Purely cosmetic: has no effect on scan logic. Generated with pyfiglet
    ('slant' font) and hardcoded here to avoid adding pyfiglet as a runtime
    dependency just for a one-time banner.
    """
    banner = r"""
 _       __                 _____
| |     / /___ _____  ____ / ___/_________ _____
| | /| / / __ `/ __ \/ __ \\__ \/ ___/ __ `/ __ \
| |/ |/ / /_/ / /_/ / /_/ /__/ / /__/ /_/ / / / /
|__/|__/\__,_/ .___/ .___/____/\___/\__,_/_/ /_/
            /_/   /_/
"""
    lines = banner.strip("\n").split("\n")
    # Simple top-to-bottom color gradient for a bit of visual polish.
    colors = [Fore.CYAN, Fore.CYAN, Fore.BLUE, Fore.BLUE, Fore.MAGENTA, Fore.MAGENTA]
    print()
    for line, color in zip(lines, colors):
        print(color + Style.BRIGHT + line)
    print(Fore.WHITE + Style.DIM + "        Tech stack scanner & CVE lookup".center(50))
    print(Fore.WHITE + Style.DIM + "        powered by Wappalyzer-next + Vulners".center(50))
    print()


def main():
    """
    Entry point: parse CLI arguments, run the technology scan, then look up
    and report known vulnerabilities for each detected technology/version.
    """
    parser = argparse.ArgumentParser(
        prog="Wapp",
        description="Scan a web page to figure out the technologies used, and look for CVE"
    )

    parser.add_argument("url", help="Specify the target's URL (ex: http://10.10.10.10)")

    parser.add_argument(
        "-k", "--key",
        required=True,
        help="Your Vulners API Key"
    )

    parser.add_argument(
        "-s", "--severity",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Filter the CVE dangerosity (default: high)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose mode"
    )

    parser.add_argument(
        "--scan-type",
        choices=["fast", "balanced", "full"],
        default="full",
        help="Wappalyzer-next scan type. 'full' uses browser emulation and is the most accurate (default)"
    )

    parser.add_argument(
        "--min-confidence",
        type=int,
        default=50,
        help="Minimum confidence score (0-100) to keep a detected technology (default: 50)"
    )

    args = parser.parse_args()

    print_banner()

    if args.verbose:
        print(Fore.WHITE + Style.DIM + f"[DEBUG] Starting scan on {args.url} (scan_type={args.scan_type})...")

    # Step 1: fingerprint the target to get a dict of {tech_name: {version, confidence, ...}}
    detected_technos = scan(args.url, args.scan_type, args.min_confidence, args.verbose)

    # Step 2: for each detected technology with a known version, query Vulners for CVEs.
    # Results are accumulated here rather than printed immediately, so the final
    # report can be sorted by severity and summarized in one pass (see print_report).
    all_vulns = []              # Flat list of every vulnerability found, across all technologies
    techs_without_version = []  # Technologies detected but with no version string (can't be looked up)
    techs_no_vuln = []          # Technologies successfully checked, with no matching CVE above threshold

    if detected_technos:
        print_section("Vulnerability lookup")
        for tech_name, tech_info in detected_technos.items():
            version = tech_info.get("version")

            if not version:
                techs_without_version.append(tech_name)
                continue

            if args.verbose:
                print(Fore.WHITE + Style.DIM + f"[DEBUG] Checking CVE for {tech_name} version {version}")

            vulns = check_vulnerabilities(tech_name, version, args.key, args.severity)
            if vulns:
                # Tag each vulnerability with its origin so the flat report can
                # display which technology/version it applies to.
                for v in vulns:
                    v["tech"] = tech_name
                    v["version"] = version
                all_vulns.extend(vulns)
            else:
                techs_no_vuln.append(f"{tech_name} {version}")

        print_report(all_vulns, techs_no_vuln, techs_without_version, args.severity, args.verbose)
    else:
        print(Fore.RED + "[-] No technologies detected.")


def scan(url, scan_type="full", min_confidence=50, verbose=False):
    """
    Run a Wappalyzer-next technology scan against the given URL.

    Args:
        url: Target URL to scan (must include scheme, e.g. "https://...").
        scan_type: One of "fast" (single HTTP request, no browser),
            "balanced" (additional requests to .js/robots.txt/DNS, still no
            browser), or "full" (runs the official Wappalyzer extension in a
            headless Chromium via Playwright - most accurate, slowest).
        min_confidence: Minimum Wappalyzer confidence score (0-100) required
            to keep a detected technology. Helps filter out weak/ambiguous
            fingerprint matches.
        verbose: If True, print additional debug information (e.g. detected
            categories per technology).

    Returns:
        dict: {tech_name: {"version": str|None, "confidence": int, ...}}
        for technologies that passed the confidence filter. Empty dict on
        error or if nothing was detected.
    """
    try:
        # wappalyzer-next's analyze() returns a dict shaped like:
        #   {tech_name: {"version": ..., "confidence": ..., "categories": [...], "groups": [...]}}
        raw_results = analyze(
            url=url,
            scan_type=scan_type,
            timeout=30
        )

        # NOTE: analyze() actually wraps the per-technology dict under the
        # scanned URL as a top-level key, i.e. {url: {tech1: {...}, tech2: {...}}},
        # rather than returning the per-technology dict directly. We unwrap it here.
        results = raw_results.get(url, {})
        if not results and raw_results:
            # Fallback in case the URL key doesn't match exactly (e.g. due to a
            # redirect or a trailing slash difference) - take the first (and
            # normally only) value in the response instead.
            results = next(iter(raw_results.values()), {})

        # Drop low-confidence matches to reduce false positives before we
        # spend API calls looking up vulnerabilities for them.
        filtered_results = {
            tech: info for tech, info in results.items()
            if isinstance(info, dict) and info.get("confidence", 0) >= min_confidence
        }

        print_header(f"TECHNOLOGIES DETECTED ON {url}")

        if not raw_results or not results:
            print(Fore.RED + "[-] No technologies returned by analyze() for this URL "
                  "(site may use very few detectable signatures, or the scan found nothing).")
        elif not filtered_results:
            print(Fore.RED + "[-] Nothing above the confidence threshold.")
        else:
            # Display technologies with a known version first (most actionable),
            # then alphabetically within each group.
            sorted_techs = sorted(
                filtered_results.items(),
                key=lambda item: (item[1].get("version") is None, item[0].lower())
            )
            name_width = max(len(name) for name, _ in sorted_techs) + 2

            for techno, info in sorted_techs:
                version = info.get("version") or "-"
                confidence = info.get("confidence", "N/A")
                categories = ", ".join(info.get("categories", [])) or "-"

                # Highlight technologies with a known version in green, since
                # those are the ones that will actually be checked against Vulners.
                version_display = Fore.GREEN + version if info.get("version") else Fore.WHITE + Style.DIM + version
                print(f"  {Fore.WHITE}{techno:<{name_width}}"
                      f"{version_display:<20}{Style.RESET_ALL}"
                      f"{Fore.WHITE + Style.DIM}[{categories}] (confidence: {confidence}%)")

        return filtered_results

    except Exception as e:
        print(Fore.RED + f"[-] Error during web scanning: {e}")
        return {}


def check_vulnerabilities(tech_name, version, api_key, min_severity="high"):
    """
    Query the Vulners API for known vulnerabilities matching a given
    technology name and version.

    Args:
        tech_name: Technology/product name as detected by Wappalyzer
            (e.g. "WordPress"). Lowercased before sending, since Vulners
            expects lowercase product identifiers.
        version: Detected version string (e.g. "7.1").
        api_key: Vulners API key with the "api" scope.
        min_severity: One of the keys in SEVERITY_THRESHOLDS; results with
            a CVSS score below this threshold are discarded.

    Returns:
        list[dict]: Vulnerability records (as returned by the API) whose
        CVSS score meets the min_severity threshold. Returns an empty list
        on error, HTTP failure, or if nothing matched.

    Note:
        Uses Vulners API v4 (/api/v4/audit/software), which replaces the
        deprecated v3 "burp/softwareapi" endpoint. Authentication is done
        via the X-Api-Key header rather than an "apiKey" field in the body.
    """
    url = "https://vulners.com/api/v4/audit/software"

    payload = {
        "software": [
            {
                "product": tech_name.lower(),
                "version": version
            }
        ],
        "match": "partial",
        "fields": ["title", "short_description"]
    }

    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key
    }

    threshold = SEVERITY_THRESHOLDS.get(min_severity, 7.0)

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)

        if response.status_code != 200:
            print(Fore.RED + f"  [-] HTTP Error {response.status_code} for {tech_name} {version}")
            return []

        data = response.json()
        # The exact response shape can vary by endpoint/version; check both
        # known locations for the vulnerability list before giving up.
        vulnerabilities = data.get("data", {}).get("vulnerabilities", []) or data.get("result", [])

        # Support both CVSS v2 ("cvss.score") and CVSS v3 ("cvss3.cvssV3.baseScore")
        # formats, since different vulnerability records may only populate one.
        filtered = [
            v for v in vulnerabilities
            if v.get("cvss", {}).get("score", v.get("cvss3", {}).get("cvssV3", {}).get("baseScore", 0)) >= threshold
        ]

        return filtered

    except Exception as e:
        print(Fore.RED + f"  [-] Error during API request for {tech_name} {version}: {e}")
        return []


def print_report(all_vulns, techs_no_vuln, techs_without_version, min_severity, verbose):
    """
    Render the final scan report: all discovered vulnerabilities sorted by
    descending CVSS score, followed by a summary of scan coverage.

    Args:
        all_vulns: Flat list of vulnerability dicts, each expected to carry
            "tech" and "version" keys (added by main()) in addition to the
            fields returned by the Vulners API (id, title, cvss/cvss3, ...).
        techs_no_vuln: List of "name version" strings for technologies that
            were checked but had no vulnerability above min_severity.
        techs_without_version: List of technology names that were detected
            but skipped because no version could be determined.
        min_severity: The severity threshold used for filtering, shown in
            the report header for context.
        verbose: If True, print the detailed technology lists behind the
            summary counters.
    """
    if all_vulns:
        def get_score(v):
            """Extract a comparable CVSS score, supporting both v2 and v3 formats."""
            return v.get("cvss", {}).get("score", v.get("cvss3", {}).get("cvssV3", {}).get("baseScore", 0)) or 0

        # Most critical findings first.
        all_vulns.sort(key=get_score, reverse=True)

        print_header(f"VULNERABILITIES FOUND (>= {min_severity})")
        for vuln in all_vulns:
            score = get_score(vuln)
            color = severity_color(score)
            cve_id = vuln.get("id", "N/A")
            title = vuln.get("title", "No title")
            print(f"  {color}[{score:>4}] {Style.BRIGHT}{cve_id:<18}{Style.NORMAL}"
                  f"{Fore.WHITE} {vuln.get('tech')} {vuln.get('version')} {Fore.WHITE + Style.DIM}- {title}")
    else:
        print_header("VULNERABILITIES FOUND")
        print(Fore.GREEN + f"[+] No vulnerabilities >= '{min_severity}' severity found across all technologies.")

    # Scan coverage summary: helps the user quickly gauge how thorough the
    # scan was (e.g. many "skipped" entries may indicate a need to rerun
    # with --scan-type full for better version detection).
    print_section("Summary")
    print(f"  {Fore.MAGENTA}Critical/High/Medium/Low vulnerabilities : {Fore.WHITE}{len(all_vulns)}")
    print(f"  {Fore.GREEN}Technologies scanned with no matching vuln : {Fore.WHITE}{len(techs_no_vuln)}")
    print(f"  {Fore.WHITE + Style.DIM}Technologies skipped (no version detected) : {len(techs_without_version)}")

    if verbose and techs_without_version:
        print(Fore.WHITE + Style.DIM + f"    -> {', '.join(techs_without_version)}")
    if verbose and techs_no_vuln:
        print(Fore.WHITE + Style.DIM + f"    -> {', '.join(techs_no_vuln)}")


if __name__ == "__main__":
    main()
