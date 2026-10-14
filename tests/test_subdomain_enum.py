import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import subdomain_enum  # noqa: E402
from modules.subdomain_enum import SubdomainEnum, crtsh_names, load_wordlist, normalize_domain  # noqa: E402


class FakeResolverEnum(SubdomainEnum):
    """SubdomainEnum with DNS answers served from a dict."""

    def __init__(self, records, wildcard=()):
        super().__init__("example.com", threads=4)
        self.records = records
        self.wildcard = list(wildcard)

    def _resolve(self, name, rtype="A"):
        if rtype == "A" and name.split(".")[0] not in self.words and name not in self.records:
            return self.wildcard
        return self.records.get((name, rtype), self.records.get(name, []) if rtype == "A" else [])


class SubdomainTests(unittest.TestCase):
    def test_normalize_domain_strips_url_parts(self):
        self.assertEqual(normalize_domain("https://Example.com:8443/login"), "example.com")
        self.assertEqual(normalize_domain(" example.com. "), "example.com")
        for bad in ("", "localhost", "https:///"):
            with self.assertRaises(ValueError):
                normalize_domain(bad)

    def test_default_wordlist_loads(self):
        words = load_wordlist(None)
        self.assertIn("www", words)
        self.assertEqual(words, sorted(set(words)))

    def test_reports_hits_with_cname(self):
        enum = FakeResolverEnum({
            "www.example.com": ["93.184.216.34"],
            ("www.example.com", "CNAME"): ["edge.example.net."],
        })
        result = enum.enumerate()
        self.assertEqual(result["found"], [
            {"subdomain": "www.example.com", "ips": ["93.184.216.34"], "cname": "edge.example.net"},
        ])

    def test_ipv6_only_hosts_are_found(self):
        enum = FakeResolverEnum({("www.example.com", "AAAA"): ["2001:db8::10"]})
        result = enum.enumerate()
        self.assertEqual(result["found"], [{"subdomain": "www.example.com", "ips": ["2001:db8::10"], "cname": None}])

    def test_wildcard_answers_are_filtered(self):
        records = {f"{w}.example.com": ["10.0.0.1"] for w in ("www", "mail")}
        records["api.example.com"] = ["10.0.0.9"]
        enum = FakeResolverEnum(records, wildcard=["10.0.0.1"])
        result = enum.enumerate()
        self.assertEqual(result["wildcard"], ["10.0.0.1"])
        self.assertEqual([r["subdomain"] for r in result["found"]], ["api.example.com"])

    def test_crtsh_names_are_cleaned_and_scoped(self):
        fake = mock.Mock()
        fake.json.return_value = [
            {"name_value": "*.example.com\nvpn.example.com"},
            {"name_value": "WWW.Example.com"},
            {"name_value": "evil-example.com"},
        ]
        with mock.patch.object(subdomain_enum.requests, "get", return_value=fake):
            self.assertEqual(crtsh_names("example.com"), ["example.com", "vpn.example.com", "www.example.com"])


if __name__ == "__main__":
    unittest.main()
