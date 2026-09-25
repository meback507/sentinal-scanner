"""
Sentinel AppSec - Live DAST & HTTP Security Header Auditor
Performs non-intrusive dynamic security audits of web endpoints, evaluating
security headers, TLS posture, cookie flags, and CORS configurations.
"""

import requests
import urllib.parse
import ssl
import socket
import time
from typing import Dict, Any, List, Optional


class DASTEngine:
    """
    Automated Dynamic Application Security Testing (DAST) probe for HTTP/HTTPS endpoints.
    """

    @classmethod
    def audit_url(cls, target_url: str, timeout: int = 6) -> Dict[str, Any]:
        """
        Performs a comprehensive defensive security audit of the target URL.
        """
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urllib.parse.urlparse(target_url)
        host = parsed.netloc.split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        findings: List[Dict[str, Any]] = []
        headers_analyzed: Dict[str, str] = {}
        cookies_analyzed: List[Dict[str, Any]] = []
        tls_info: Dict[str, Any] = {"is_https": parsed.scheme == "https"}

        # 1. Dispatch defensive HTTP GET probe
        req_headers = {
            "User-Agent": "Sentinel-AppSec-DAST-Scanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            "Origin": f"{parsed.scheme}://evil-origin.example.com"  # CORS reflection probe
        }

        try:
            resp = requests.get(target_url, headers=req_headers, timeout=timeout, allow_redirects=True, verify=False)
            status_code = resp.status_code
            headers_analyzed = dict(resp.headers)
            normalized_headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as e:
            return {
                "target_url": target_url,
                "status": "error",
                "error": f"Failed to connect to endpoint: {str(e)}",
                "score": 0,
                "grade": "F",
                "findings": [],
                "audited_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            }

        # 2. Audit HTTPS & Transport Security
        if parsed.scheme != "https":
            findings.append({
                "id": "DAST-TLS-001",
                "title": "Cleartext HTTP Transport Without Transport Layer Security (TLS)",
                "type": "dast",
                "severity": "HIGH",
                "cvss_score": 7.4,
                "epss_score": 0.18,
                "cwe_id": "CWE-319",
                "owasp": "OWASP:A02:2021",
                "standards": ["ISO-27001:A.8.24", "PCI-DSS:Req-4.1", "NIST-SSDF:PW.7"],
                "description": "The endpoint communicates over unencrypted cleartext HTTP, allowing network eavesdroppers to intercept passwords, tokens, and session cookies.",
                "remediation": "Enforce HTTPS redirection and obtain a trusted TLS certificate.",
                "evidence": f"URL scheme: {parsed.scheme}"
            })
        else:
            # Audit HSTS
            hsts = normalized_headers.get("strict-transport-security")
            if not hsts:
                findings.append({
                    "id": "DAST-HDR-HSTS",
                    "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
                    "type": "dast",
                    "severity": "MEDIUM",
                    "cvss_score": 5.3,
                    "epss_score": 0.09,
                    "cwe_id": "CWE-319",
                    "owasp": "OWASP:A05:2021",
                    "standards": ["ISO-27001:A.8.24", "PCI-DSS:Req-4.1"],
                    "description": "Missing HSTS header leaves users vulnerable to SSL-stripping and man-in-the-middle downgrade attacks on initial visit.",
                    "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "evidence": "Strict-Transport-Security header not present in response"
                })
            elif "max-age" in hsts and int("".join(filter(str.isdigit, hsts.split("max-age=")[1].split(";")[0])) or 0) < 15768000:
                findings.append({
                    "id": "DAST-HDR-HSTS-SHORT",
                    "title": "Insufficient HSTS max-age Duration (< 6 Months)",
                    "type": "dast",
                    "severity": "LOW",
                    "cvss_score": 3.7,
                    "epss_score": 0.02,
                    "cwe_id": "CWE-319",
                    "owasp": "OWASP:A05:2021",
                    "standards": ["ISO-27001:A.8.24"],
                    "description": "HSTS max-age is set to a short duration, weakening long-term protection against downgrade attacks.",
                    "remediation": "Set max-age to at least 31536000 seconds (1 year).",
                    "evidence": f"Header value: {hsts}"
                })

        # 3. Audit Content-Security-Policy (CSP)
        csp = normalized_headers.get("content-security-policy")
        if not csp:
            findings.append({
                "id": "DAST-HDR-CSP",
                "title": "Missing Content-Security-Policy (CSP) Header",
                "type": "dast",
                "severity": "HIGH",
                "cvss_score": 6.8,
                "epss_score": 0.14,
                "cwe_id": "CWE-1021",
                "owasp": "OWASP:A05:2021",
                "standards": ["ISO-27001:A.8.28", "OWASP:A03:2021"],
                "description": "Missing CSP allows Cross-Site Scripting (XSS), data injection, and rogue script execution from unauthorized origins.",
                "remediation": "Implement a restrictive CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
                "evidence": "Content-Security-Policy header not present"
            })
        elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append({
                "id": "DAST-HDR-CSP-UNSAFE",
                "title": "Weak Content-Security-Policy Permitting Unsafe-Inline / Eval",
                "type": "dast",
                "severity": "MEDIUM",
                "cvss_score": 5.4,
                "epss_score": 0.08,
                "cwe_id": "CWE-79",
                "owasp": "OWASP:A05:2021",
                "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28"],
                "description": "CSP includes 'unsafe-inline' or 'unsafe-eval', significantly eroding XSS execution barriers.",
                "remediation": "Eliminate inline scripts and eval; use cryptographic nonces or SHA-256 hashes instead.",
                "evidence": f"Header value: {csp[:120]}"
            })

        # 4. Audit X-Frame-Options (Clickjacking)
        xfo = normalized_headers.get("x-frame-options")
        if not xfo and (not csp or "frame-ancestors" not in csp):
            findings.append({
                "id": "DAST-HDR-XFO",
                "title": "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                "type": "dast",
                "severity": "MEDIUM",
                "cvss_score": 5.4,
                "epss_score": 0.06,
                "cwe_id": "CWE-1021",
                "owasp": "OWASP:A05:2021",
                "standards": ["ISO-27001:A.8.28", "OWASP:A05:2021"],
                "description": "Without X-Frame-Options: DENY or frame-ancestors 'self', an attacker can embed this portal inside a hidden <iframe> on a malicious site to hijack user clicks.",
                "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
                "evidence": "Neither X-Frame-Options nor CSP frame-ancestors configured"
            })

        # 5. Audit X-Content-Type-Options (MIME Sniffing)
        xcto = normalized_headers.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            findings.append({
                "id": "DAST-HDR-XCTO",
                "title": "Missing X-Content-Type-Options: nosniff Header",
                "type": "dast",
                "severity": "LOW",
                "cvss_score": 3.5,
                "epss_score": 0.03,
                "cwe_id": "CWE-16",
                "owasp": "OWASP:A05:2021",
                "standards": ["ISO-27001:A.8.28"],
                "description": "Browser may attempt to infer content types (MIME-sniffing), treating user-uploaded text as executable HTML or script.",
                "remediation": "Add header: X-Content-Type-Options: nosniff",
                "evidence": f"Header value: {xcto or 'None'}"
            })

        # 6. Audit Referrer-Policy
        ref_pol = normalized_headers.get("referrer-policy")
        if not ref_pol:
            findings.append({
                "id": "DAST-HDR-REF",
                "title": "Missing Referrer-Policy Header",
                "type": "dast",
                "severity": "LOW",
                "cvss_score": 3.1,
                "epss_score": 0.02,
                "cwe_id": "CWE-116",
                "owasp": "OWASP:A05:2021",
                "standards": ["ISO-27001:A.8.12"],
                "description": "Missing Referrer-Policy may cause browsers to leak sensitive URL tokens or internal query paths to external third parties.",
                "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
                "evidence": "Referrer-Policy header not present"
            })

        # 7. Audit Server Banner / Version Disclosure
        server_header = normalized_headers.get("server") or normalized_headers.get("x-powered-by")
        if server_header and any(char.isdigit() for char in server_header):
            findings.append({
                "id": "DAST-INFO-LEAK",
                "title": "Web Server Detailed Version Disclosure in Response Header",
                "type": "dast",
                "severity": "LOW",
                "cvss_score": 3.2,
                "epss_score": 0.04,
                "cwe_id": "CWE-200",
                "owasp": "OWASP:A05:2021",
                "standards": ["ISO-27001:A.8.28", "CIS:Server:1.1"],
                "description": "Server reveals exact version information in response headers, simplifying reconnaissance for attackers researching version-specific CVEs.",
                "remediation": "Suppress server banners (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
                "evidence": f"Exposed header: {server_header}"
            })

        # 8. Audit Cookies (Set-Cookie security flags)
        raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
        for cookie_str in raw_cookies:
            c_lower = cookie_str.lower()
            c_name = cookie_str.split("=")[0].strip()
            cookies_analyzed.append({"cookie": c_name})

            if "secure" not in c_lower and parsed.scheme == "https":
                findings.append({
                    "id": f"DAST-COOKIE-SECURE-{c_name[:12]}",
                    "title": f"Cookie '{c_name}' Missing 'Secure' Attribute",
                    "type": "dast",
                    "severity": "MEDIUM",
                    "cvss_score": 5.3,
                    "epss_score": 0.07,
                    "cwe_id": "CWE-614",
                    "owasp": "OWASP:A05:2021",
                    "standards": ["ISO-27001:A.8.24", "PCI-DSS:Req-6.5.10"],
                    "description": f"Cookie '{c_name}' is set without the 'Secure' flag, allowing transmission across unencrypted connections.",
                    "remediation": f"Append '; Secure' to Set-Cookie: {c_name}=...; Secure; HttpOnly; SameSite=Lax",
                    "evidence": cookie_str[:100]
                })

            if "httponly" not in c_lower:
                findings.append({
                    "id": f"DAST-COOKIE-HTTPONLY-{c_name[:12]}",
                    "title": f"Cookie '{c_name}' Missing 'HttpOnly' Flag",
                    "type": "dast",
                    "severity": "MEDIUM",
                    "cvss_score": 5.0,
                    "epss_score": 0.05,
                    "cwe_id": "CWE-1004",
                    "owasp": "OWASP:A05:2021",
                    "standards": ["ISO-27001:A.8.28", "OWASP:A03:2021"],
                    "description": f"Cookie '{c_name}' can be accessed by client-side JavaScript via document.cookie, enabling session hijacking via XSS.",
                    "remediation": f"Append '; HttpOnly' to Set-Cookie: {c_name}",
                    "evidence": cookie_str[:100]
                })

            if "samesite" not in c_lower:
                findings.append({
                    "id": f"DAST-COOKIE-SAMESITE-{c_name[:12]}",
                    "title": f"Cookie '{c_name}' Missing 'SameSite' Attribute",
                    "type": "dast",
                    "severity": "LOW",
                    "cvss_score": 4.1,
                    "epss_score": 0.03,
                    "cwe_id": "CWE-352",
                    "owasp": "OWASP:A01:2021",
                    "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28"],
                    "description": f"Cookie '{c_name}' lacks SameSite=Lax or SameSite=Strict, increasing exposure to Cross-Site Request Forgery (CSRF).",
                    "remediation": f"Append '; SameSite=Lax' to Set-Cookie: {c_name}",
                    "evidence": cookie_str[:100]
                })

        # 9. Audit Insecure CORS Wildcard Reflection
        cors_origin = normalized_headers.get("access-control-allow-origin")
        cors_creds = normalized_headers.get("access-control-allow-credentials")
        if cors_origin == "*" and cors_creds == "true":
            findings.append({
                "id": "DAST-CORS-WILDCARD-CREDS",
                "title": "Dangerous CORS Configuration: Wildcard Origin With Credentials",
                "type": "dast",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "epss_score": 0.16,
                "cwe_id": "CWE-942",
                "owasp": "OWASP:A01:2021",
                "standards": ["ISO-27001:A.8.28", "OWASP:A01:2021"],
                "description": "Server permits credentials across wildcard origins, potentially allowing third-party sites to steal private session data.",
                "remediation": "Restrict Access-Control-Allow-Origin to authorized domain whitelist.",
                "evidence": f"Allow-Origin: {cors_origin}, Allow-Credentials: {cors_creds}"
            })
        elif cors_origin == "http://evil-origin.example.com" or cors_origin == "https://evil-origin.example.com":
            findings.append({
                "id": "DAST-CORS-REFLECTED",
                "title": "Insecure CORS Arbitrary Origin Reflection",
                "type": "dast",
                "severity": "HIGH",
                "cvss_score": 7.8,
                "epss_score": 0.22,
                "cwe_id": "CWE-942",
                "owasp": "OWASP:A01:2021",
                "standards": ["ISO-27001:A.8.28"],
                "description": "Server reflects arbitrary Origin headers back into Access-Control-Allow-Origin, nullifying Same-Origin Policy protections.",
                "remediation": "Validate the incoming Origin against a strict whitelist before echoing.",
                "evidence": f"Reflected arbitrary origin: {cors_origin}"
            })

        # 10. Compute Posture Score & Letter Grade
        # Base 100, deductions: Critical = -25, High = -15, Medium = -8, Low = -3
        crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")
        med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low_count = sum(1 for f in findings if f["severity"] == "LOW")

        deduction = (crit_count * 25) + (high_count * 15) + (med_count * 8) + (low_count * 3)
        score = max(0, min(100, 100 - deduction))

        if score >= 95:
            grade = "A+"
        elif score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "target_url": target_url,
            "status": "success",
            "http_status": status_code,
            "score": score,
            "grade": grade,
            "summary": {
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
                "low": low_count,
                "total": len(findings)
            },
            "findings": findings,
            "headers_analyzed": headers_analyzed,
            "cookies_found": len(cookies_analyzed),
            "audited_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        }
