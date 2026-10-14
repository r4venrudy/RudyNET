"""TCP connect and UDP port scanning with optional banner grabbing."""

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Probes that make common services answer on connect.
PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
}

UDP_PROBES = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01",  # DNS root NS query
    123: b"\x1b" + 47 * b"\x00",  # NTP client request
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


def clean_target(target: str) -> str:
    """Reduce "https://host:8443/path" or "[::1]" to the bare host so URLs can be pasted as targets."""
    host = target.strip()
    if "://" in host:
        host = urlparse(host).hostname or ""
    host = host.strip("[]")
    if not host:
        raise ValueError(f"Invalid target: {target}")
    return host


class PortScanner:
    def __init__(self, target: str, timeout: float = 1.0, banner: bool = False, workers: int = 200):
        self.target = clean_target(target)
        self.timeout = timeout
        self.banner = banner
        self.workers = workers
        # getaddrinfo also returns IPv6 addresses (gethostbyname only knew IPv4); prefer IPv4 when a host has both
        infos = socket.getaddrinfo(self.target, None, type=socket.SOCK_STREAM)
        family, _, _, _, sockaddr = sorted(infos, key=lambda i: i[0] != socket.AF_INET)[0]
        self.family = family
        self.ip = sockaddr[0]

    def _tcp(self, port: int) -> Optional[Dict[str, Any]]:
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

    def _udp(self, port: int) -> Optional[Dict[str, Any]]:
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
            return {"port": port, "protocol": "udp", "state": "open",
                    "service": service_name(port, "udp"), "bytes": len(data)}

    def scan(self, ports: List[int], scan_type: str = "tcp") -> Dict[str, Any]:
        """Scan `ports` with 'tcp', 'udp' or 'both' and return only the open ones, sorted."""
        jobs = []
        if scan_type in ("tcp", "both"):
            jobs += [(self._tcp, p) for p in ports]
        if scan_type in ("udp", "both"):
            jobs += [(self._udp, p) for p in ports]
        with ThreadPoolExecutor(max_workers=min(self.workers, max(1, len(jobs)))) as pool:
            found = [r for r in pool.map(lambda j: j[0](j[1]), jobs) if r]
        found.sort(key=lambda r: (r["protocol"], r["port"]))
        return {"target": self.target, "ip": self.ip, "scanned": len(ports), "scan_type": scan_type, "open": found}
