import json
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


class _FakeScanner:
    seen = None

    def __init__(self, target, timeout, banner, workers, rate):
        pass

    def scan(self, ports, scan_type):
        _FakeScanner.seen = ports
        return {"target": "h", "ip": "127.0.0.1", "scanned": len(ports), "scan_type": scan_type, "open": []}


class ExcludeTests(unittest.TestCase):
    def test_excluded_ports_are_not_scanned(self):
        with mock.patch.object(rudynet, "load_module", return_value=_FakeScanner):
            result = CliRunner().invoke(rudynet.cli, ["scan", "-t", "127.0.0.1", "-p", "1-10", "-x", "3,5-9"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(_FakeScanner.seen, [1, 2, 4, 10])

    def test_excluding_everything_is_an_error(self):
        with mock.patch.object(rudynet, "load_module", return_value=_FakeScanner):
            result = CliRunner().invoke(rudynet.cli, ["scan", "-t", "127.0.0.1", "-p", "80", "-x", "80"])
        self.assertEqual(result.exit_code, 1)

    def test_nonfinite_scan_rate_is_rejected_before_opening_ports(self):
        result = CliRunner().invoke(
            rudynet.cli,
            ["scan", "-t", "127.0.0.1", "-p", "80", "--rate", "nan"],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("finite non-negative", result.stderr)


class _NetScanner:
    scanned = []

    def __init__(self, target, timeout, banner, workers, rate):
        self.target = target

    def scan(self, ports, scan_type):
        _NetScanner.scanned.append(self.target)
        found = [{"port": 22, "protocol": "tcp", "service": "ssh"}] if self.target.endswith(".2") else []
        return {"target": self.target, "ip": self.target, "scanned": len(ports), "scan_type": scan_type, "open": found}


class NetworkTargetTests(unittest.TestCase):
    def test_expand_targets(self):
        self.assertEqual(rudynet.expand_targets("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(rudynet.expand_targets("10.0.0.5/32"), ["10.0.0.5"])
        self.assertEqual(rudynet.expand_targets("example.com"), ["example.com"])
        self.assertEqual(rudynet.expand_targets("https://example.com/a/b"), ["https://example.com/a/b"])
        with self.assertRaises(ValueError):
            rudynet.expand_targets("10.0.0.0/16")

    def test_network_scan_lists_hosts_with_open_ports(self):
        _NetScanner.scanned = []
        with mock.patch.object(rudynet, "load_module", return_value=_NetScanner):
            result = _split_runner().invoke(rudynet.cli, ["scan", "-t", "10.0.0.0/29", "-p", "22", "-o", "json"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(_NetScanner.scanned), 6)
        report = json.loads(result.stdout)
        self.assertEqual(report["scanned_hosts"], 6)
        self.assertEqual([h["ip"] for h in report["hosts"]], ["10.0.0.2"])
