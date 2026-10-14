import os
import sys
import unittest

from requests.structures import CaseInsensitiveDict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.web_security import (  # noqa: E402
    check_csp, collect_set_cookies, check_frame_options, check_referrer_policy, check_hsts, evaluate_cookies, evaluate_headers, grade, normalize_url,
)
from utils.output import render  # noqa: E402

STRONG = CaseInsensitiveDict({
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
})


class NormalizeUrlTests(unittest.TestCase):
    def test_adds_https_scheme(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_keeps_explicit_port_and_path(self):
        self.assertEqual(normalize_url(" http://example.com:8080/login "), "http://example.com:8080/login")

    def test_rejects_other_schemes(self):
        with self.assertRaises(ValueError):
            normalize_url("ftp://example.com")


class HeaderTests(unittest.TestCase):
    def test_strong_headers_have_no_deductions(self):
        result = evaluate_headers(STRONG)
        self.assertEqual(result["deductions"], 0)
        self.assertTrue(all(c["ok"] for c in result["checks"]))

    def test_frame_ancestors_covers_x_frame_options(self):
        xfo = next(c for c in evaluate_headers(STRONG)["checks"] if c["header"] == "X-Frame-Options")
        self.assertIn("frame-ancestors", xfo["detail"])

    def test_missing_headers_are_penalised(self):
        result = evaluate_headers(CaseInsensitiveDict({}))
        self.assertEqual(result["deductions"], 75)

    def test_header_lookup_is_case_insensitive(self):
        result = evaluate_headers(CaseInsensitiveDict({"x-content-type-options": "nosniff"}))
        xcto = next(c for c in result["checks"] if c["header"] == "X-Content-Type-Options")
        self.assertTrue(xcto["ok"])

    def test_leaky_headers_reported(self):
        result = evaluate_headers(CaseInsensitiveDict({**STRONG, "X-Powered-By": "PHP/7.4"}))
        self.assertEqual(result["leaks"], ["X-Powered-By: PHP/7.4"])

    def test_short_hsts_fails(self):
        ok, detail = check_hsts("max-age=3600")
        self.assertFalse(ok)
        self.assertIn("180 days", detail)

    def test_hsts_details(self):
        self.assertEqual(check_hsts('max-age="31536000"; includeSubDomains; preload'),
                         (True, "max-age=31536000 (includesubdomains, preload)"))
        self.assertEqual(check_hsts("max-age=abc"), (False, "max-age is not a number"))
        self.assertEqual(check_hsts("includeSubDomains"), (False, "max-age=0 is below 180 days"))

    def test_unsafe_csp_fails(self):
        ok, detail = check_csp("default-src 'self' 'unsafe-inline'")
        self.assertFalse(ok)
        self.assertIn("unsafe-inline", detail)


class FrameAndReferrerTests(unittest.TestCase):
    def test_unsafe_inline_with_nonce_is_ignored(self):
        self.assertEqual(check_csp("script-src 'self' 'unsafe-inline' 'nonce-abc123'"), (True, "present"))
        self.assertEqual(check_csp("script-src 'unsafe-inline' 'sha256-xyz='"), (True, "present"))
        self.assertFalse(check_csp("script-src 'unsafe-inline' 'nonce-abc' 'unsafe-eval'")[0])

    def test_frame_options_values(self):
        self.assertEqual(check_frame_options("deny"), (True, "DENY"))
        self.assertEqual(check_frame_options("sameorigin"), (True, "SAMEORIGIN"))
        self.assertFalse(check_frame_options("ALLOW-FROM https://x")[0])

    def test_frame_options_sent_twice(self):
        self.assertEqual(check_frame_options("SAMEORIGIN, sameorigin"), (True, "SAMEORIGIN"))
        self.assertFalse(check_frame_options("DENY, SAMEORIGIN")[0])

    def test_nosniff_sent_twice(self):
        result = evaluate_headers(CaseInsensitiveDict({**STRONG, "X-Content-Type-Options": "nosniff, nosniff"}))
        xcto = next(c for c in result["checks"] if c["header"] == "X-Content-Type-Options")
        self.assertTrue(xcto["ok"])

    def test_hsts_over_plain_http_does_not_count(self):
        result = evaluate_headers(CaseInsensitiveDict(STRONG), https=False)
        hsts = next(c for c in result["checks"] if c["header"] == "Strict-Transport-Security")
        self.assertEqual(hsts, {"header": "Strict-Transport-Security", "ok": False, "detail": "ignored over plain HTTP"})

    def test_referrer_policy_list_uses_last_value(self):
        self.assertFalse(check_referrer_policy("strict-origin, unsafe-url")[0])
        self.assertTrue(check_referrer_policy("unsafe-url, strict-origin-when-cross-origin")[0])
        self.assertFalse(check_referrer_policy(" , ")[0])

    def test_unsafe_referrer_policy_is_penalised(self):
        headers = CaseInsensitiveDict({**STRONG, "Referrer-Policy": "unsafe-url"})
        result = evaluate_headers(headers)
        ref = next(c for c in result["checks"] if c["header"] == "Referrer-Policy")
        self.assertFalse(ref["ok"])
        self.assertEqual(result["deductions"], 5)


class CookieTests(unittest.TestCase):
    def test_flags_missing_attributes(self):
        issues = evaluate_cookies(["sid=abc; Path=/", "ok=1; Secure; HttpOnly; SameSite=Lax"], https=True)
        self.assertEqual(issues, ["sid missing Secure, HttpOnly, SameSite"])

    def test_secure_not_required_over_plain_http(self):
        self.assertEqual(evaluate_cookies(["a=1; HttpOnly; SameSite=Strict"], https=False), [])


class GradeAndOutputTests(unittest.TestCase):
    def test_grade_bands(self):
        self.assertEqual(grade(100), "A+")
        self.assertEqual(grade(72), "B")
        self.assertEqual(grade(10), "F")

    def test_csv_and_txt_flatten_nested_results(self):
        data = {"tls": {"protocol": "TLSv1.3"}, "leaks": ["Server: nginx"]}
        self.assertIn("tls.protocol,TLSv1.3", render(data, "csv"))
        self.assertIn("leaks.0: Server: nginx", render(data, "txt"))


if __name__ == "__main__":
    unittest.main()


class _Headers:
    def __init__(self, cookies):
        self.cookies = cookies

    def getlist(self, name):
        return list(self.cookies) if name == "Set-Cookie" else []


class _Resp:
    def __init__(self, cookies, history=()):
        self.raw = type("Raw", (), {"headers": _Headers(cookies)})()
        self.history = list(history)


class RedirectCookieTests(unittest.TestCase):
    def test_cookies_from_redirect_hops_are_included(self):
        resp = _Resp(["final=1; Secure"], history=[_Resp(["session=abc"])])
        self.assertEqual(collect_set_cookies(resp), ["session=abc", "final=1; Secure"])
