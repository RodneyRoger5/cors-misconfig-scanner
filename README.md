# CORS Misconfiguration Scanner

A lightweight Python tool that tests web endpoints for insecure
Cross-Origin Resource Sharing (CORS) configurations.

> ⚠️ **Disclaimer:** For educational purposes and authorized security
> testing only. Do not scan systems you don't own or have written
> permission to test. The author is not responsible for misuse.

## Features
- Arbitrary origin reflection detection
- `null` origin trust
- Wildcard (`*`) and wildcard + credentials checks
- Weak origin validation (prefix/suffix match, regex dot bypass)
- HTTP origin and arbitrary subdomain trust
- Preflight (`OPTIONS`) method/header checks
- Missing `Vary: Origin` detection
- Severity ratings, JSON reports, CI-friendly exit codes

## Installation
```bash
git clone https://github.com/RodneyRoger5/cors-misconfig-scanner.git
cd cors-misconfig-scanner
pip install requests
```

## Usage

# Single URL
```bash
python3 cors_check.py https://example.com/api/user
```

# Authenticated endpoint, since CORS issues matter most where cookies or tokens are involved
```bash
python3 cors_check.py https://example.com/api/me --cookie "session=abc123"
python3 cors_check.py https://example.com/api/me -H "Authorization: Bearer TOKEN"
```

# Many URLs, saving a JSON report
```bash
python3 cors_check.py -f urls.txt -o report.json
```

# Self-signed certificate
```bash
python3 cors_check.py https://staging.local/api -k
```

| Option | Description |
|---|---|
| `-f, --file` | File containing URLs (one per line) |
| `-H, --header` | Extra header (repeatable) |
| `--cookie` | Cookie header value |
| `-m, --method` | HTTP method (default `GET`) |
| `-k, --insecure` | Skip TLS verification |
| `-o, --output` | Save JSON report |

## Severity Guide
| Level | Meaning |
|---|---|
| CRITICAL | Untrusted origin reflected with credentials allowed |
| HIGH | `null` / weak validation with credentials |
| MEDIUM | Reflection without credentials, insecure scheme |
| LOW | Wildcard on public resources |
