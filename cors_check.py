#!/usr/bin/env python3
"""
cors_check.py - Simple CORS misconfiguration scanner.

Only use against systems you own or are explicitly authorized to test.

Checks performed:
  1. Arbitrary origin reflection
  2. "null" origin allowed
  3. Wildcard (*) origin, and wildcard combined with credentials
  4. Weak origin validation (prefix/suffix match, unescaped-dot regex)
  5. Trust of insecure (http://) origin scheme
  6. Trust of arbitrary subdomains
  7. Preflight (OPTIONS) allowing dangerous methods/headers for untrusted origins
  8. Missing "Vary: Origin" when ACAO is dynamic (cache poisoning risk)

Usage:
  python3 cors_check.py https://example.com/api/user
  python3 cors_check.py -f urls.txt -H "Authorization: Bearer xxx" -o report.json
  python3 cors_check.py https://example.com --cookie "session=abc" --insecure

Requires: pip install requests
"""

import argparse
import json
import sys
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COLORS = {
    "CRITICAL": "\033[95m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
    "OK": "\033[92m",
    "END": "\033[0m",
}


def color(level, text):
    if not sys.stdout.isatty():
        return text
    return f"{COLORS.get(level, '')}{text}{COLORS['END']}"


def build_test_origins(url, attacker="evil.com"):
    """Build a list of (label, origin) pairs to test against the target."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"

    tests = [
        ("arbitrary origin", f"https://{attacker}"),
        ("null origin", "null"),
        ("prefix match bypass (target.attacker)", f"{scheme}://{host}.{attacker}"),
        ("suffix match bypass (attackertarget)", f"{scheme}://{attacker.split('.')[0]}{host}"),
        ("arbitrary subdomain", f"{scheme}://cors-test-xyz.{host}"),
        ("insecure http scheme", f"http://{host}"),
        ("special char bypass", f"{scheme}://{host}_.{attacker}"),
    ]

    # Unescaped-dot regex bypass: example.com -> examplexcom
    if "." in host:
        left, _, right = host.rpartition(".")
        tests.append(("unescaped dot regex bypass", f"{scheme}://{left}x{right}"))

    return tests


def send(session, method, url, origin, extra_headers, timeout, verify, preflight_method=None):
    headers = dict(extra_headers)
    headers["Origin"] = origin
    if method == "OPTIONS":
        headers["Access-Control-Request-Method"] = preflight_method or "PUT"
        headers["Access-Control-Request-Headers"] = "authorization,x-custom-header,content-type"
    try:
        return session.request(
            method, url, headers=headers, timeout=timeout,
            verify=verify, allow_redirects=False,
        )
    except requests.RequestException as e:
        return e


def analyze(label, origin, resp):
    """Return a finding dict or None."""
    h = {k.lower(): v for k, v in resp.headers.items()}
    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    vary = h.get("vary", "").lower()

    if not acao:
        return None

    reflected = acao == origin
    finding = None

    if acao == "*":
        if acac:
            finding = ("MEDIUM", "Wildcard ACAO with Allow-Credentials: true "
                                 "(invalid combo; browsers block it, but indicates a sloppy config)")
        else:
            finding = ("LOW", "Wildcard ACAO (fine for public, unauthenticated resources only)")
    elif origin == "null" and acao == "null":
        sev = "HIGH" if acac else "MEDIUM"
        finding = (sev, "Origin 'null' is trusted"
                        + (" with credentials (exploitable via sandboxed iframe)" if acac else ""))
    elif reflected:
        if label in ("arbitrary subdomain",):
            sev = "HIGH" if acac else "LOW"
            finding = (sev, "Any subdomain is trusted"
                            + (" with credentials (XSS/takeover on any subdomain = data theft)" if acac else ""))
        elif label == "insecure http scheme":
            sev = "MEDIUM" if acac else "LOW"
            finding = (sev, "HTTP origin trusted (MITM attacker can read HTTPS responses)")
        elif label == "arbitrary origin":
            sev = "CRITICAL" if acac else "MEDIUM"
            finding = (sev, "Arbitrary origin reflected"
                            + (" with credentials -> full cross-origin data theft" if acac else ""))
        else:
            sev = "CRITICAL" if acac else "HIGH"
            finding = (sev, f"Weak origin validation ({label})"
                            + (" with credentials" if acac else ""))

        if finding and "origin" not in vary:
            finding = (finding[0], finding[1] + " | Missing 'Vary: Origin' (cache poisoning risk)")

    if not finding:
        return None

    return {
        "severity": finding[0],
        "issue": finding[1],
        "test": label,
        "origin_sent": origin,
        "acao": acao,
        "acac": acac,
        "status": resp.status_code,
    }


def analyze_preflight(label, origin, resp):
    h = {k.lower(): v for k, v in resp.headers.items()}
    acao = h.get("access-control-allow-origin")
    methods = h.get("access-control-allow-methods", "")
    headers = h.get("access-control-allow-headers", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"

    if not acao or acao not in (origin, "*"):
        return None

    dangerous = [m for m in ("PUT", "DELETE", "PATCH") if m in methods.upper()]
    wildcard_hdrs = headers.strip() == "*"
    if not (dangerous or wildcard_hdrs):
        return None

    detail = []
    if dangerous:
        detail.append(f"methods allowed: {', '.join(dangerous)}")
    if wildcard_hdrs:
        detail.append("Allow-Headers: *")

    return {
        "severity": "HIGH" if (acac and acao == origin) else "MEDIUM",
        "issue": f"Preflight permits untrusted origin with {'; '.join(detail)}",
        "test": f"preflight / {label}",
        "origin_sent": origin,
        "acao": acao,
        "acac": acac,
        "status": resp.status_code,
    }


def scan(url, args):
    session = requests.Session()
    extra = {"User-Agent": "cors-check/1.0"}
    for hdr in args.header or []:
        if ":" in hdr:
            k, v = hdr.split(":", 1)
            extra[k.strip()] = v.strip()
    if args.cookie:
        extra["Cookie"] = args.cookie

    verify = not args.insecure
    findings = []
    errors = []

    for label, origin in build_test_origins(url, args.attacker):
        # Simple request
        resp = send(session, args.method, url, origin, extra, args.timeout, verify)
        if isinstance(resp, Exception):
            errors.append(f"{label}: {resp}")
            continue
        f = analyze(label, origin, resp)
        if f:
            findings.append(f)

        # Preflight
        pre = send(session, "OPTIONS", url, origin, extra, args.timeout, verify)
        if not isinstance(pre, Exception):
            pf = analyze_preflight(label, origin, pre)
            if pf:
                findings.append(pf)

    return {"url": url, "findings": findings, "errors": errors}


def print_result(result):
    print(f"\n[*] Target: {result['url']}")
    if result["errors"] and not result["findings"]:
        for e in result["errors"]:
            print(color("INFO", f"    error: {e}"))
        return
    if not result["findings"]:
        print(color("OK", "    No CORS misconfiguration detected."))
        return
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for f in sorted(result["findings"], key=lambda x: order.index(x["severity"])):
        print(color(f["severity"], f"    [{f['severity']}] {f['issue']}"))
        print(f"        test={f['test']} | Origin: {f['origin_sent']} -> ACAO: {f['acao']} "
              f"| ACAC: {f['acac']} | HTTP {f['status']}")


def main():
    p = argparse.ArgumentParser(description="CORS misconfiguration scanner (authorized testing only)")
    p.add_argument("url", nargs="?", help="Target URL")
    p.add_argument("-f", "--file", help="File with one URL per line")
    p.add_argument("-m", "--method", default="GET", help="HTTP method for simple requests (default GET)")
    p.add_argument("-H", "--header", action="append", help="Extra header, e.g. 'Authorization: Bearer x' (repeatable)")
    p.add_argument("--cookie", help="Cookie header value")
    p.add_argument("--attacker", default="evil.com", help="Attacker domain used in test origins")
    p.add_argument("-t", "--timeout", type=int, default=10)
    p.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("-o", "--output", help="Write JSON report to file")
    args = p.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file) as fh:
            urls += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not urls:
        p.error("provide a URL or --file")

    results = []
    for u in urls:
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        r = scan(u, args)
        print_result(r)
        results.append(r)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n[+] Report saved to {args.output}")

    # Non-zero exit if anything HIGH/CRITICAL found (useful in CI)
    bad = any(f["severity"] in ("HIGH", "CRITICAL") for r in results for f in r["findings"])
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
