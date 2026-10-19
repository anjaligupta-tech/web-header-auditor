# Automated Web Security Header & CORS Auditor

A Python-based defensive security tool designed to audit websites for baseline HTTP security headers and CORS (Cross-Origin Resource Sharing) misconfigurations.

## Features
- **Security Headers Check:** Analyzes presence of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **CORS Misconfiguration Analysis:** Flags wildcard origins, origin reflections, and permissive credential leaks.
- **Multi-target & JSON Output:** Supports single URL or batch list scanning and exports structured findings to JSON.

## Setup & Installation
```bash
pip install -r requirements.txt 
```
## How to Run
Scan a single website:

``` bash
python scanner.py -u https://example.com -o audit_report.json
 ```

Scan multiple sites from a text file:

``` bash
python scanner.py -f targets.txt -o audit_report.json
```
##Sample Output
Generated reports are exported in clean structured JSON:

``` JSON
{
    "url": "https://example.com",
    "status": "Success",
    "headers_audit": { ... },
    "cors_audit": { ... }
}
```