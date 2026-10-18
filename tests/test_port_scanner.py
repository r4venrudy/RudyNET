import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.port_scanner import UDP_PROBES, PortScanner, RateLimiter, clean_banner, clean_target, udp_banner  # noqa: E402
from rudynet import parse_ports  # noqa: E402


def _greeting_server(greeting: bytes, family=socket.AF_INET, host="127.0.0.1"):
    srv = socket.socket(family)
    srv.bind((host, 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.sendall(greeting)

    threading.Thread(target=serve, daemon=True).start()
    return srv


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PortScannerTests(unittest.TestCase):
    def test_finds_open_port_and_banner(self):
        srv = _greeting_server(b"SSH-2.0-OpenSSH_9.6\r\n")
        port = srv.getsockname()[1]
        try:
            result = PortScanner("127.0.0.1", timeout=0.5, banner=True).scan([port, _free_port()])
        finally:
            srv.close()
        self.assertEqual([r["port"] for r in result["open"]], [port])
        self.assertEqual(result["open"][0]["banner"], "SSH-2.0-OpenSSH_9.6")

    @unittest.skipUnless(shutil.which("openssl"), "openssl is needed to make a test certificate")
    def test_banner_over_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-keyout", key, "-out", cert],
                           check=True, capture_output=True)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def serve():
            try:
                conn, _ = srv.accept()
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(b"* OK IMAP4rev1 ready\r\n")
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        port = srv.getsockname()[1]
        scanner = PortScanner("127.0.0.1", timeout=2, banner=True)
        scanner.tls_ports = {port}
        try:
            result = scanner.scan([port])
        finally:
            srv.close()
        self.assertEqual(result["open"][0]["banner"], "* OK IMAP4rev1 ready")

    def test_udp_service_answers_its_probe(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        received = []

        def serve():
            data, addr = srv.recvfrom(1024)
            received.append(data)
            srv.sendto(b"\x30\x00", addr)

        threading.Thread(target=serve, daemon=True).start()
        with mock.patch.dict(UDP_PROBES, {port: UDP_PROBES[161]}):
            try:
                result = PortScanner("127.0.0.1", timeout=1).scan([port], "udp")
            finally:
                srv.close()
        self.assertEqual([r["port"] for r in result["open"]], [port])
        self.assertEqual(received, [UDP_PROBES[161]])

    @unittest.skipUnless(socket.has_ipv6, "no IPv6 support")
    def test_ipv6_target(self):
        try:
            srv = _greeting_server(b"hello\r\n", socket.AF_INET6, "::1")
        except OSError:
            self.skipTest("::1 is not available")
        port = srv.getsockname()[1]
        try:
            result = PortScanner("::1", timeout=0.5, banner=True).scan([port])
        finally:
            srv.close()
        self.assertEqual(result["ip"], "::1")
        self.assertEqual([r["port"] for r in result["open"]], [port])

    def test_closed_ports_are_not_reported(self):
        result = PortScanner("127.0.0.1", timeout=0.3).scan([_free_port()])
        self.assertEqual(result["open"], [])

    def test_clean_target_accepts_urls(self):
        self.assertEqual(clean_target("https://Example.com:8443/login"), "example.com")
        self.assertEqual(clean_target(" [::1] "), "::1")
        self.assertEqual(clean_target("10.0.0.5"), "10.0.0.5")
        with self.assertRaises(ValueError):
            clean_target("https://")

    def test_clean_banner_keeps_first_line(self):
        self.assertEqual(clean_banner(b"220 mail ESMTP\r\nmore"), "220 mail ESMTP")


class ParsePortsTests(unittest.TestCase):
    def test_range_list_and_single(self):
        self.assertEqual(parse_ports("20-22"), [20, 21, 22])
        self.assertEqual(parse_ports("80, 443"), [80, 443])
        self.assertEqual(parse_ports("8080"), [8080])

    def test_mixed_list_and_ranges(self):
        self.assertEqual(parse_ports("22,80-82,81"), [22, 80, 81, 82])

    def test_top100_in_a_list_and_all_ports(self):
        ports = parse_ports("top100,8081")
        self.assertIn(8081, ports)
        self.assertIn(443, ports)
        self.assertEqual(len(parse_ports("-")), 65535)

    def test_top100(self):
        ports = parse_ports("TOP100")
        self.assertEqual(len(ports), 100)
        self.assertIn(443, ports)
        self.assertEqual(ports, sorted(set(ports)))

    def test_rejects_empty(self):
        for bad in ("", ",", " , "):
            with self.assertRaises(ValueError):
                parse_ports(bad)

    def test_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_ports("0-70000")


if __name__ == "__main__":
    unittest.main()


class RateLimiterTests(unittest.TestCase):
    def test_spaces_calls_out(self):
        now = [100.0]
        slept = []

        def sleep(s):
            slept.append(round(s, 3))

        limiter = RateLimiter(4, clock=lambda: now[0], sleep=sleep)
        for _ in range(3):
            limiter.wait()
        self.assertEqual(slept, [0.25, 0.5])

    def test_zero_means_unlimited(self):
        limiter = RateLimiter(0, sleep=lambda s: self.fail("should not sleep"))
        limiter.wait()

    def test_rejects_negative_and_nonfinite_rates(self):
        for invalid in (-1, float("nan"), float("inf"), float("-inf")):
            with self.subTest(rate=invalid), self.assertRaisesRegex(ValueError, "finite non-negative"):
                RateLimiter(invalid)


class UdpBannerTests(unittest.TestCase):
    def test_ssdp_server_header(self):
        reply = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: Linux/5.4 UPnP/1.0 MiniUPnPd/2.2\r\n\r\n"
        self.assertEqual(udp_banner(1900, reply), "Linux/5.4 UPnP/1.0 MiniUPnPd/2.2")

    def test_snmp_sysdescr(self):
        descr = b"RouterOS RB750"
        varbind = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x04" + bytes([len(descr)]) + descr
        reply = b"\x30\x2f\x02\x01\x00\x04\x06public\xa2\x22\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x17\x30\x15" + varbind
        self.assertEqual(udp_banner(161, reply), "RouterOS RB750")
        self.assertEqual(udp_banner(53, reply), "")
