import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.port_scanner import PortScanner, clean_banner  # noqa: E402
from rudynet import parse_ports  # noqa: E402


def _greeting_server(greeting: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
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

    def test_closed_ports_are_not_reported(self):
        result = PortScanner("127.0.0.1", timeout=0.3).scan([_free_port()])
        self.assertEqual(result["open"], [])

    def test_clean_banner_keeps_first_line(self):
        self.assertEqual(clean_banner(b"220 mail ESMTP\r\nmore"), "220 mail ESMTP")


class ParsePortsTests(unittest.TestCase):
    def test_range_list_and_single(self):
        self.assertEqual(parse_ports("20-22"), [20, 21, 22])
        self.assertEqual(parse_ports("80, 443"), [80, 443])
        self.assertEqual(parse_ports("8080"), [8080])

    def test_mixed_list_and_ranges(self):
        self.assertEqual(parse_ports("22,80-82,81"), [22, 80, 81, 82])

    def test_rejects_empty(self):
        for bad in ("", ",", " , "):
            with self.assertRaises(ValueError):
                parse_ports(bad)

    def test_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_ports("0-70000")


if __name__ == "__main__":
    unittest.main()
