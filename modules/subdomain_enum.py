"""DNS subdomain enumeration with wildcard detection and optional certificate-transparency lookup."""

import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Set

import dns.exception
import dns.resolver

DEFAULT_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "wordlists", "subdomains.txt")


def load_wordlist(path: Optional[str]) -> List[str]:
    with open(path or DEFAULT_WORDLIST, encoding="utf-8", errors="ignore") as fh:
        words = {line.strip().lower() for line in fh if line.strip() and not line.startswith("#")}
    return sorted(words)


class SubdomainEnum:
    def __init__(self, domain: str, wordlist: Optional[str] = None, threads: int = 50, timeout: float = 3.0):
        self.domain = domain.strip().lower().rstrip(".")
        self.words = load_wordlist(wordlist)
        self.threads = threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout

    def _resolve(self, name: str, rtype: str = "A") -> List[str]:
        try:
            return sorted(r.to_text() for r in self.resolver.resolve(name, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.name.LabelTooLong, dns.name.EmptyLabel):
            return []

    def wildcard_ips(self) -> Set[str]:
        """Addresses a random label resolves to; hits matching these are wildcard noise."""
        probe = f"{secrets.token_hex(8)}.{self.domain}"
        return set(self._resolve(probe))

    def _check(self, name: str, wildcard: Set[str]) -> Optional[Dict[str, Any]]:
        ips = self._resolve(name)
        if not ips or (wildcard and set(ips) <= wildcard):
            return None
        cname = self._resolve(name, "CNAME")
        return {"subdomain": name, "ips": ips, "cname": cname[0].rstrip(".") if cname else None}

    def enumerate(self, extra: Optional[List[str]] = None) -> Dict[str, Any]:
        wildcard = self.wildcard_ips()
        names = {f"{w}.{self.domain}" for w in self.words}
        names.update(extra or [])
        with ThreadPoolExecutor(max_workers=max(1, self.threads)) as pool:
            found = [r for r in pool.map(lambda n: self._check(n, wildcard), sorted(names)) if r]
        return {
            "domain": self.domain,
            "tried": len(names),
            "wildcard": sorted(wildcard),
            "found": sorted(found, key=lambda r: r["subdomain"]),
        }
