"""Passive web security analysis: TLS certificate inspection and HTTP header grading."""

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests

USER_AGENT = "RudyNET/1.1 (+https://github.com/r4venrudy/RudyNET)"

# header -> points deducted when missing
HEADER_WEIGHTS = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy": 20,
    "X-Content-Type-Options": 10,
    "X-Frame-Options": 10,
    "Referrer-Policy": 10,
    "Permissions-Policy": 5,
}

LEAKY_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def normalize_url(url: str) -> str:
    """Add https:// when no scheme is given and reject anything that isn't an http(s) URL with a host."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"Invalid URL: {url}")
    return url


def _name(rdn_seq: Tuple) -> str:
    parts = dict(item for rdn in rdn_seq for item in rdn)
    return parts.get("commonName") or parts.get("organizationName") or ", ".join(f"{k}={v}" for k, v in parts.items())


def check_hsts(value: str) -> Tuple[bool, str]:
    """Pass when max-age is at least 180 days; report includeSubDomains/preload when present."""
    directives = {d.strip().split("=")[0].lower(): d.strip() for d in value.split(";") if d.strip()}
    max_age = 0
    if "max-age" in directives:
        try:
            max_age = int(directives["max-age"].split("=", 1)[1].strip('"'))
        except (IndexError, ValueError):
            return False, "max-age is not a number"
    if max_age < 15552000:
        return False, f"max-age={max_age} is below 180 days"
    extra = [d for d in ("includesubdomains", "preload") if d in directives]
    return True, f"max-age={max_age}" + (f" ({', '.join(extra)})" if extra else "")


def check_csp(value: str) -> Tuple[bool, str]:
    """Fail a CSP that allows unsafe-inline/unsafe-eval or has no default-src/script-src."""
    lowered = value.lower()
    problems = [tok for tok in ("'unsafe-inline'", "'unsafe-eval'") if tok in lowered]
    if "default-src" not in lowered and "script-src" not in lowered:
        problems.append("no default-src or script-src")
    if problems:
        return False, "present but weak: " + ", ".join(problems)
    return True, "present"


def check_frame_options(value: str) -> Tuple[bool, str]:
    """Only DENY and SAMEORIGIN are valid X-Frame-Options values.

    A header sent twice arrives joined ("SAMEORIGIN, SAMEORIGIN"); browsers accept that when every copy agrees.
    """
    values = {v.strip().upper() for v in value.split(",")}
    if len(values) == 1 and values <= {"DENY", "SAMEORIGIN"}:
        return True, values.pop()
    return False, f"unexpected value '{value}'"


def check_referrer_policy(value: str) -> Tuple[bool, str]:
    """Browsers apply the last policy they understand in a comma list, so grade that one."""
    policies = [p.strip().lower() for p in value.split(",") if p.strip()]
    effective = policies[-1] if policies else ""
    return effective not in ("", "unsafe-url", "no-referrer-when-downgrade"), value


def evaluate_headers(headers: Dict[str, str], https: bool = True) -> Dict[str, Any]:
    """Grade a response's headers. `headers` must be a case-insensitive mapping.

    Browsers ignore Strict-Transport-Security on plain HTTP responses, so it earns nothing there.
    """
    checks: List[Dict[str, Any]] = []
    deductions = 0
    csp = headers.get("Content-Security-Policy")

    for header, weight in HEADER_WEIGHTS.items():
        value = headers.get(header)
        if value is None:
            if header == "X-Frame-Options" and csp and "frame-ancestors" in csp.lower():
                checks.append({"header": header, "ok": True, "detail": "covered by CSP frame-ancestors"})
                continue
            checks.append({"header": header, "ok": False, "detail": "missing"})
            deductions += weight
            continue
        if header == "Strict-Transport-Security":
            ok, detail = check_hsts(value) if https else (False, "ignored over plain HTTP")
        elif header == "Content-Security-Policy":
            ok, detail = check_csp(value)
        elif header == "X-Content-Type-Options":
            ok, detail = (value.lower() == "nosniff", value)
        elif header == "X-Frame-Options":
            ok, detail = check_frame_options(value)
        elif header == "Referrer-Policy":
            ok, detail = check_referrer_policy(value)
        else:
            ok, detail = True, "present"
        if not ok:
            deductions += weight // 2
        checks.append({"header": header, "ok": ok, "detail": detail})

    leaks = [f"{h}: {headers[h]}" for h in LEAKY_HEADERS if headers.get(h)]
    deductions += 5 * len(leaks)

    return {"checks": checks, "leaks": leaks, "deductions": deductions}


def evaluate_cookies(set_cookie_values: List[str], https: bool) -> List[str]:
    """List cookies missing Secure (on HTTPS), HttpOnly or SameSite."""
    issues = []
    for raw in set_cookie_values:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=")[0].lower() for a in raw.split(";")[1:]}
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            issues.append(f"{name} missing {', '.join(missing)}")
    return issues


def grade(score: int) -> str:
    """Map a 0-100 score to A+ .. F."""
    for threshold, letter in ((95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D")):
        if score >= threshold:
            return letter
    return "F"


class WebSecurity:
    def __init__(self, url: str, timeout: float = 10.0):
        self.url = normalize_url(url)
        parsed = urlparse(self.url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.https = parsed.scheme == "https"
        self.timeout = timeout

    def check_tls(self) -> Dict[str, Any]:
        tls_port = self.port if self.https else 443
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((self.host, tls_port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    cert = tls.getpeercert()
                    protocol = tls.version()
                    cipher = tls.cipher()
        except ssl.SSLCertVerificationError as e:
            return {"error": f"Certificate verification failed: {e.verify_message}", "valid": False}
        except (OSError, ssl.SSLError) as e:
            return {"error": f"TLS connection failed: {e}", "valid": False}

        not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

        issues = []
        if days_left < 0:
            issues.append("Certificate has expired")
        elif days_left < 14:
            issues.append(f"Certificate expires in {days_left} days")
        if protocol in WEAK_PROTOCOLS:
            issues.append(f"Weak protocol negotiated: {protocol}")

        return {
            "valid": True,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "subject": _name(cert.get("subject", ())),
            "issuer": _name(cert.get("issuer", ())),
            "not_after": not_after.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "san_count": len(sans),
            "issues": issues,
        }

    def check_headers(self) -> Dict[str, Any]:
        try:
            resp = requests.get(self.url, timeout=self.timeout, allow_redirects=True,
                                headers={"User-Agent": USER_AGENT})
        except requests.RequestException as e:
            return {"error": f"HTTP request failed: {e}"}

        final_https = resp.url.startswith("https://")
        result = evaluate_headers(resp.headers, final_https)
        cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
        result.update({
            "final_url": resp.url,
            "status": resp.status_code,
            "redirects_to_https": final_https,
            "cookie_issues": evaluate_cookies(cookies, final_https),
        })
        if not final_https:
            result["deductions"] += 20
        result["deductions"] += 3 * len(result["cookie_issues"])
        return result

    def check_ssl_only(self) -> Dict[str, Any]:
        tls = self.check_tls()
        score = 0 if not tls.get("valid") else max(0, 100 - 25 * len(tls["issues"]))
        return {"target": self.url, "tls": tls, "score": score, "grade": grade(score)}

    def full_analysis(self) -> Dict[str, Any]:
        tls = self.check_tls()
        headers = self.check_headers()
        deductions = headers.get("deductions", 40)
        if not tls.get("valid"):
            deductions += 30
        else:
            deductions += 15 * len(tls["issues"])
        score = max(0, 100 - deductions)
        return {"target": self.url, "tls": tls, "headers": headers, "score": score, "grade": grade(score)}
