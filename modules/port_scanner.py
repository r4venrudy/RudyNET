"""TCP connect and UDP port scanning with optional banner grabbing."""

import ipaddress
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# 100 commonly open TCP ports (web, mail, file sharing, databases, remote access), used by `-p top100`
TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110,
    111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
    3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153,
    49154, 49155, 49156, 49157,
]

# Probes that make common services answer on connect.
PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
}

# Ports that speak TLS from the first byte (HTTPS, SMTPS, IMAPS, POP3S); a plain read only gets handshake noise
TLS_PORTS = {443, 465, 993, 995, 8443}

UDP_PROBES = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01",  # DNS root NS query
    123: b"\x1b" + 47 * b"\x00",  # NTP client request
    # NetBIOS node status query for "*"
    137: b"\x80\xf0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + b"CK" + 30 * b"A" + b"\x00\x00\x21\x00\x01",
    # SNMPv1 GetRequest for sysDescr.0 with the default "public" community
    161: bytes.fromhex("302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500"),
    # SSDP discovery (UPnP devices such as routers and printers)
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
}


def service_name(port: int, proto: str = "tcp") -> str:
    """Well-known service for a port from the system services database, or 'unknown'."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def clean_banner(raw: bytes, limit: int = 120) -> str:
    """First line of a service banner, decoded leniently and cut to `limit` characters."""
    text = raw.decode("utf-8", errors="replace").strip()
    first = text.splitlines()[0] if text else ""
    return first[:limit]


def udp_banner(port: int, data: bytes) -> str:
    """Readable part of a UDP reply: the SSDP SERVER header or the SNMP sysDescr string."""
    if port == 1900:
        for line in data.decode("latin-1").splitlines():
            if line.lower().startswith("server:"):
                return clean_banner(line.split(":", 1)[1].encode("latin-1"))
        return ""
    if port == 161:
        # the requested value is the last OCTET STRING (tag 0x04) in the response
        at = data.rfind(b"\x04")
        while at > 0:
            length = data[at + 1] if at + 1 < len(data) else 0
            if length < 0x80 and at + 2 + length == len(data):
                return clean_banner(data[at + 2:])
            at = data.rfind(b"\x04", 0, at)
        return ""
    return ""


def clean_target(target: str) -> str:
    """Reduce "https://host:8443/path" or "[::1]" to the bare host so URLs can be pasted as targets."""
    host = target.strip()
    if "://" in host:
        host = urlparse(host).hostname or ""
    host = host.strip("[]")
    if not host:
        raise ValueError(f"Invalid target: {target}")
    return host


class RateLimiter:
    """Spaces out calls from all worker threads to at most `rate` per second (0 means no limit)."""

    def __init__(self, rate: float, clock=time.monotonic, sleep=time.sleep):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.clock = clock
        self.sleep = sleep
        self.lock = threading.Lock()
        self.next_at = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self.lock:
            now = self.clock()
            at = max(now, self.next_at)
            self.next_at = at + self.interval
        if at > now:
            self.sleep(at - now)


class PortScanner:
    def __init__(self, target: str, timeout: float = 1.0, banner: bool = False, workers: int = 200, rate: float = 0):
        self.target = clean_target(target)
        self.timeout = timeout
        self.banner = banner
        self.workers = workers
        self.tls_ports = TLS_PORTS
        self.limiter = RateLimiter(rate)
        # getaddrinfo also returns IPv6 addresses (gethostbyname only knew IPv4); prefer IPv4 when a host has both
        infos = socket.getaddrinfo(self.target, None, type=socket.SOCK_STREAM)
        family, _, _, _, sockaddr = sorted(infos, key=lambda i: i[0] != socket.AF_INET)[0]
        self.family = family
        self.ip = sockaddr[0]

    def _tcp(self, port: int) -> Optional[Dict[str, Any]]:
        self.limiter.wait()
        try:
            with socket.create_connection((self.ip, port), timeout=self.timeout) as sock:
                result: Dict[str, Any] = {"port": port, "protocol": "tcp", "state": "open",
                                          "service": service_name(port)}
                if self.banner:
                    result["banner"] = self._grab(sock, port)
                return result
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _grab(self, sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(self.timeout)
            if port in self.tls_ports:
                return self._grab_tls(sock, port)
            if port in PROBES:
                sock.sendall(PROBES[port])
                return clean_banner(sock.recv(1024))
            try:
                # Services like SSH and SMTP greet first; give them a chance.
                return clean_banner(sock.recv(1024))
            except socket.timeout:
                # Silent service: many unknown ports are HTTP, so ask politely.
                sock.sendall(PROBES[80])
                return clean_banner(sock.recv(1024))
        except OSError:
            return ""

    def _grab_tls(self, sock: socket.socket, port: int) -> str:
        # Only reading a banner, not judging the certificate (web_security does that)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ipaddress.ip_address(self.target)
            sni = None
        except ValueError:
            sni = self.target
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            if port in (443, 8443):
                tls.sendall(f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode())
            return clean_banner(tls.recv(1024))

    def _udp(self, port: int) -> Optional[Dict[str, Any]]:
        self.limiter.wait()
        with socket.socket(self.family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.sendto(UDP_PROBES.get(port, b"\x00"), (self.ip, port))
                data, _ = sock.recvfrom(1024)
            except socket.timeout:
                # No reply: UDP can't tell open from filtered without one.
                return None
            except OSError:
                return None  # ICMP port unreachable => closed
            result: Dict[str, Any] = {"port": port, "protocol": "udp", "state": "open",
                                      "service": service_name(port, "udp"), "bytes": len(data)}
            if self.banner and udp_banner(port, data):
                result["banner"] = udp_banner(port, data)
            return result

    def scan(self, ports: List[int], scan_type: str = "tcp") -> Dict[str, Any]:
        """Scan `ports` with 'tcp', 'udp' or 'both' and return only the open ones, sorted."""
        jobs = []
        if scan_type in ("tcp", "both"):
            jobs += [(self._tcp, p) for p in ports]
        if scan_type in ("udp", "both"):
            jobs += [(self._udp, p) for p in ports]
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=min(self.workers, max(1, len(jobs)))) as pool:
            found = [r for r in pool.map(lambda j: j[0](j[1]), jobs) if r]
        found.sort(key=lambda r: (r["protocol"], r["port"]))
        return {"target": self.target, "ip": self.ip, "scanned": len(ports), "scan_type": scan_type,
                "seconds": round(time.monotonic() - started, 2), "open": found}
