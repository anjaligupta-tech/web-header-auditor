import argparse
import json
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces secure (HTTPS) connections.",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (should be 'nosniff').",
    "X-Frame-Options": "Protects against clickjacking attacks.",
    "Referrer-Policy": "Controls referrer information sent in HTTP requests.",
    "Permissions-Policy": "Restricts browser features like camera and geolocation."
}

def audit_security_headers(headers):
    results = {"present": {}, "missing": []}
    for header, purpose in SECURITY_HEADERS.items():
        matched_key = next((k for k in headers if k.lower() == header.lower()), None)
        if matched_key:
            results["present"][header] = headers[matched_key]
        else:
            results["missing"].append({"header": header, "purpose": purpose})
    return results

def audit_cors_policy(target_url):
    test_origin = "https://example-test.com"
    findings = []
    
    try:
        response = requests.options(
            target_url,
            headers={"Origin": test_origin, "Access-Control-Request-Method": "GET"},
            timeout=8
        )
        cors_headers = response.headers
    except requests.RequestException:
        try:
            response = requests.get(target_url, headers={"Origin": test_origin}, timeout=8)
            cors_headers = response.headers
        except requests.RequestException as err:
            return {"status": "Error", "details": str(err)}

    acao = cors_headers.get("Access-Control-Allow-Origin")
    acac = cors_headers.get("Access-Control-Allow-Credentials")

    if not acao:
        findings.append("No Access-Control-Allow-Origin header found (standard/strict behavior).")
    elif acao == "*":
        findings.append("Wildcard origin ('*') allowed. Public access permitted.")
    elif acao == test_origin:
        findings.append(f"Origin reflection detected with supplied test origin: {test_origin}")
        if acac and acac.lower() == "true":
            findings.append("HIGH RISK: Origin reflected with Access-Control-Allow-Credentials: true.")

    return {
        "status": "Checked",
        "acao_header": acao,
        "acac_header": acac,
        "findings": findings
    }

def scan_target(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    report = {
        "url": url,
        "status": "Success",
        "headers_audit": {},
        "cors_audit": {}
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        report["headers_audit"] = audit_security_headers(response.headers)
        report["cors_audit"] = audit_cors_policy(url)
    except requests.RequestException as exc:
        report["status"] = "Failed"
        report["error"] = str(exc)

    return report

def main():
    parser = argparse.ArgumentParser(description="Web Security Header & CORS Auditor")
    parser.add_argument("-u", "--url", help="Single target URL to scan")
    parser.add_argument("-f", "--file", help="Text file containing list of URLs")
    parser.add_argument("-o", "--output", default="audit_report.json", help="Path to save JSON output")
    args = parser.parse_args()

    targets = []
    if args.url:
        targets.append(args.url.strip())
    elif args.file:
        try:
            with open(args.file, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[-] Error: File '{args.file}' nahi mili.")
            return
    else:
        print("[-] Error: URL provide karein using -u <URL> ya -f <file.txt>")
        return

    all_reports = []
    print(f"\n[+] Total targets: {len(targets)}")
    print("=" * 60)

    for idx, target in enumerate(targets, 1):
        print(f"[{idx}/{len(targets)}] Scanning: {target} ...")
        result = scan_target(target)
        all_reports.append(result)

    with open(args.output, "w", encoding="utf-8") as json_file:
        json.dump(all_reports, json_file, indent=4)

    print("=" * 60)
    print(f"[✓] Scan complete! Report saved to: {args.output}\n")

if __name__ == "__main__":
    main()