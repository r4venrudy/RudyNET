"""DNS subdomain enumeration with wildcard detection and optional certificate-transparency lookup."""

import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Set

import dns.exception
import dns.resolver
import requests

DEFAULT_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "data", "subdomains.txt")


# Hosting services where a CNAME left pointing at a deleted site/bucket can be claimed by someone else
TAKEOVER_SUFFIXES = (
    ".github.io", ".herokuapp.com", ".herokudns.com", ".s3.amazonaws.com", ".cloudfront.net",
    ".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net", ".blob.core.windows.net",
    ".pantheonsite.io", ".netlify.app", ".fly.dev", ".surge.sh", ".bitbucket.io", ".ghost.io",
    ".myshopify.com", ".wpengine.com", ".zendesk.com", ".readthedocs.io",
)


def load_wordlist(path: Optional[str]) -> List[str]:
    """Read a wordlist (or the bundled data/subdomains.txt), lowercased, deduplicated, comments skipped."""
    with open(path or DEFAULT_WORDLIST, encoding="utf-8", errors="ignore") as fh:
        words = {line.strip().lower() for line in fh if line.strip() and not line.startswith("#")}
    return sorted(words)


def crtsh_names(domain: str, timeout: float = 20.0) -> List[str]:
    """Passive discovery: hostnames seen in public certificate-transparency logs."""
    resp = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=timeout)
    resp.raise_for_status()
    names: Set[str] = set()
    for entry in resp.json():
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                names.add(name)
    return sorted(names)


def normalize_domain(value: str) -> str:
    """Turn "https://Example.com/path" or "example.com." into "example.com"."""
    domain = value.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if not domain or "." not in domain:
        raise ValueError(f"Invalid domain: {value}")
    return domain


class SubdomainEnum:
    def __init__(self, domain: str, wordlist: Optional[str] = None, threads: int = 50, timeout: float = 3.0,
                 nameservers: Optional[List[str]] = None):
        self.domain = normalize_domain(domain)
        self.words = load_wordlist(wordlist)
        self.threads = threads
        # explicit resolvers help when the local one filters, caches stale answers or rate-limits
        self.resolver = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.lifetime = timeout

    def _resolve(self, name: str, rtype: str = "A") -> List[str]:
        try:
            return sorted(r.to_text() for r in self.resolver.resolve(name, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.name.LabelTooLong, dns.name.EmptyLabel):
            return []

    def wildcard_ips(self, probes: int = 3) -> Set[str]:
        """Addresses random labels resolve to; hits matching these are wildcard noise.

        Several probes, because wildcard records behind a CDN or round-robin DNS answer with a
        different subset of addresses each time, and one probe would miss some of them.
        """
        found: Set[str] = set()
        for _ in range(probes):
            probe = f"{secrets.token_hex(8)}.{self.domain}"
            found |= set(self._resolve(probe)) | set(self._resolve(probe, "AAAA"))
            if not found:
                break  # no answer for the first random name: there is no wildcard
        return found

    def _check(self, name: str, wildcard: Set[str]) -> Optional[Dict[str, Any]]:
        """Resolve both address families; drop a name only when every answer is wildcard noise."""
        ips = sorted(set(self._resolve(name, "A")) | set(self._resolve(name, "AAAA")))
        if not ips:
            # a CNAME to a hosting service whose target no longer resolves is a takeover candidate
            cname = self._resolve(name, "CNAME")
            target = cname[0].rstrip(".").lower() if cname else ""
            if target.endswith(TAKEOVER_SUFFIXES):
                return {"subdomain": name, "ips": [], "cname": target, "dangling": True}
            return None
        if wildcard and set(ips) <= wildcard:
            return None
        cname = self._resolve(name, "CNAME")
        return {"subdomain": name, "ips": ips, "cname": cname[0].rstrip(".") if cname else None}

    def enumerate(self, extra: Optional[List[str]] = None) -> Dict[str, Any]:
        """Resolve every wordlist name plus `extra` full hostnames (e.g. from crt.sh) in parallel."""
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
