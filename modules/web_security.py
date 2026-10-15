"""Passive web security analysis: TLS certificate inspection and HTTP header grading."""

import re
import socket
import ssl
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests

USER_AGENT = "RudyNET/1.2 (+https://github.com/r4venrudy/RudyNET)"

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
    detail = f"max-age={max_age}" + (f" ({', '.join(extra)})" if extra else "")
    # hstspreload.org only accepts the preload flag with includeSubDomains and max-age of a year or more
    if "preload" in directives and ("includesubdomains" not in directives or max_age < 31536000):
        detail += "; preload requested but not eligible (needs includeSubDomains and max-age >= 1 year)"
    return True, detail


def check_csp(value: str) -> Tuple[bool, str]:
    """Fail a CSP that allows unsafe-inline/unsafe-eval or has no default-src/script-src."""
    lowered = value.lower()
    problems = [tok for tok in ("'unsafe-inline'", "'unsafe-eval'") if tok in lowered]
    # CSP level 2+: browsers ignore 'unsafe-inline' when the policy also has a nonce or hash
    if "'unsafe-inline'" in problems and re.search(r"'(nonce-|sha256-|sha384-|sha512-)", lowered):
        problems.remove("'unsafe-inline'")
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
            ok, detail = ({v.strip().lower() for v in value.split(",")} == {"nosniff"}, value)
        elif header == "X-Frame-Options":
            ok, detail = check_frame_options(value)
        elif header == "Referrer-Policy":
            ok, detail = check_referrer_policy(value)
        else:
            ok, detail = True, "present"
        if not ok:
            deductions += weight // 2
        checks.append({"header": header, "ok": ok, "detail": detail})

    # "Server: nginx" or "Server: cloudflare" says little; a version number ("nginx/1.18.0") is the leak
    leaks = [f"{h}: {headers[h]}" for h in LEAKY_HEADERS
             if headers.get(h) and (h != "Server" or re.search(r"\d", headers[h]))]
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
        # browsers reject prefixed cookies that break the prefix rules, so the cookie silently isn't set
        path = next((a.strip().split("=", 1)[1].strip() for a in raw.split(";")[1:]
                     if a.strip().lower().startswith("path=")), None)
        if name.startswith("__Host-") and ("secure" not in attrs or "domain" in attrs or path != "/"):
            issues.append(f"{name} breaks __Host- rules (needs Secure, Path=/ and no Domain)")
        elif name.startswith("__Secure-") and "secure" not in attrs:
            issues.append(f"{name} breaks __Secure- rules (needs Secure)")
    return issues


def collect_set_cookies(resp: Any) -> List[str]:
    """Set-Cookie headers from every hop, since login and tracking cookies are often set on a redirect."""
    cookies: List[str] = []
    for r in list(getattr(resp, "history", [])) + [resp]:
        headers = getattr(r.raw, "headers", None)
        if headers is not None and hasattr(headers, "getlist"):
            cookies.extend(headers.getlist("Set-Cookie"))
    return cookies


def parse_security_txt(text: str) -> Dict[str, Any]:
    """Contact and Expires fields from an RFC 9116 security.txt (comments and PGP armor skipped)."""
    fields: Dict[str, List[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    return {"contact": fields.get("contact", []), "expires": (fields.get("expires") or [None])[0]}


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
        elif self.accepts_legacy_tls():
            issues.append("Server still accepts TLS 1.0/1.1")

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

    def accepts_legacy_tls(self) -> Any:
        """True when the server still completes a TLS 1.0/1.1 handshake, False when it refuses,
        None when this machine's OpenSSL can't offer those versions at all (so it wasn't tested)."""
        tls_port = self.port if self.https else 443
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)  # deprecated on purpose: that's the test
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            return None
        try:
            with socket.create_connection((self.host, tls_port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return True
        except ssl.SSLError as e:
            # our side refusing to offer the protocol says nothing about the server
            if "NO_PROTOCOLS_AVAILABLE" in str(e) or "UNSUPPORTED_PROTOCOL" in str(e) and "alert" not in str(e).lower():
                return None
            return False
        except OSError:
            return False

    def check_headers(self) -> Dict[str, Any]:
        try:
            resp = requests.get(self.url, timeout=self.timeout, allow_redirects=True,
                                headers={"User-Agent": USER_AGENT})
        except requests.RequestException as e:
            return {"error": f"HTTP request failed: {e}"}

        final_https = resp.url.startswith("https://")
        result = evaluate_headers(resp.headers, final_https)
        cookies = collect_set_cookies(resp)
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

    def check_http_redirect(self) -> Any:
        """For an https:// target, whether plain http:// on the same host ends up on HTTPS.
        None when port 80 doesn't answer (nothing to redirect) or the target is already http://."""
        if not self.https:
            return None
        try:
            resp = requests.get(f"http://{self.host}/", timeout=self.timeout, allow_redirects=True,
                                headers={"User-Agent": USER_AGENT})
        except requests.RequestException:
            return None
        return resp.url.startswith("https://")

    def check_security_txt(self) -> Dict[str, Any]:
        """Whether the site publishes /.well-known/security.txt (how to report a vulnerability). Not scored."""
        url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}/.well-known/security.txt"
        try:
            resp = requests.get(url, timeout=self.timeout, allow_redirects=True, headers={"User-Agent": USER_AGENT})
        except requests.RequestException:
            return {"found": False}
        # many sites answer every path with their HTML homepage, so require plain text with a Contact line
        if resp.status_code != 200 or "text/plain" not in resp.headers.get("Content-Type", ""):
            return {"found": False}
        info = parse_security_txt(resp.text[:20000])
        if not info["contact"]:
            return {"found": False}
        return {"found": True, **info}

    def full_analysis(self) -> Dict[str, Any]:
        tls = self.check_tls()
        headers = self.check_headers()
        deductions = headers.get("deductions", 40)
        if not tls.get("valid"):
            deductions += 30
        else:
            deductions += 15 * len(tls["issues"])
        score = max(0, 100 - deductions)
        return {"target": self.url, "tls": tls, "headers": headers, "security_txt": self.check_security_txt(),
                "http_redirects_to_https": self.check_http_redirect(),
                "score": score, "grade": grade(score)}
