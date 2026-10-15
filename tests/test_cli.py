import os
import sys
import unittest
from unittest import mock

from click.testing import CliRunner

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rudynet  # noqa: E402


class _FakeWeb:
    def __init__(self, url, timeout):
        pass

    def full_analysis(self):
        return {"target": "https://example.com", "score": 62, "grade": "C"}


class FailUnderTests(unittest.TestCase):
    def run_web(self, *args):
        with mock.patch.object(rudynet, "load_module", return_value=_FakeWeb):
            return CliRunner().invoke(rudynet.cli, ["web", "-u", "example.com", *args])

    def test_exit_code_2_below_threshold(self):
        self.assertEqual(self.run_web("--fail-under", "70").exit_code, 2)

    def test_exit_code_0_at_or_above_threshold(self):
        self.assertEqual(self.run_web("--fail-under", "62").exit_code, 0)
        self.assertEqual(self.run_web().exit_code, 0)


class _FakeSub:
    def __init__(self, domain, wordlist, threads, timeout, nameservers=None):
        self.domain = domain

    def enumerate(self, extra):
        return {"domain": self.domain, "tried": 0, "wildcard": [], "found": []}


def _split_runner():
    """CliRunner with stdout and stderr captured separately (the default from Click 8.2; Python 3.9 gets 8.1)."""
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()


class CrtshPipeTests(unittest.TestCase):
    def test_crtsh_failure_keeps_json_stdout_clean(self):
        import json
        with mock.patch.object(rudynet, "load_module", return_value=_FakeSub), \
                mock.patch("modules.subdomain_enum.crtsh_names", side_effect=RuntimeError("down")):
            result = _split_runner().invoke(rudynet.cli, ["subdomain", "-d", "example.com", "--crtsh", "-o", "json"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(json.loads(result.stdout)["domain"], "example.com")
        self.assertIn("crt.sh lookup failed", result.stderr)


class ResolverOptionTests(unittest.TestCase):
    def test_parse_resolvers(self):
        self.assertEqual(rudynet.parse_resolvers("1.1.1.1, 2606:4700:4700::1111"), ["1.1.1.1", "2606:4700:4700::1111"])
        for bad in ("dns.google", " , "):
            with self.assertRaises(ValueError):
                rudynet.parse_resolvers(bad)

    def test_resolvers_reach_the_resolver(self):
        from modules.subdomain_enum import SubdomainEnum
        enum = SubdomainEnum("example.com", nameservers=["9.9.9.9"])
        self.assertEqual(enum.resolver.nameservers, ["9.9.9.9"])
