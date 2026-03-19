"""Whitelist of known-safe IPs and domains that should never be alerted on."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Known-safe destination IPs — major CDNs, DNS resolvers, update servers
_SAFE_IPS: set[str] = {
    "8.8.8.8",        # Google DNS
    "8.8.4.4",        # Google DNS
    "1.1.1.1",        # Cloudflare DNS
    "1.0.0.1",        # Cloudflare DNS
    "9.9.9.9",        # Quad9 DNS
    "208.67.222.222", # OpenDNS
    "208.67.220.220", # OpenDNS
    "13.107.4.50",    # Microsoft
    "13.107.6.152",   # Microsoft
    "52.96.0.0",      # Microsoft 365
    "142.250.0.0",    # Google
    "172.217.0.0",    # Google
    "31.13.64.0",     # Facebook/Meta
    "157.240.0.0",    # Facebook/Meta
}

# Known-safe SNI domains
_SAFE_DOMAINS: set[str] = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "microsoft.com",
    "office365.com",
    "microsoftonline.com",
    "windows.com",
    "windowsupdate.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "akamai.com",
    "fastly.com",
    "amazonaws.com",
    "amazon.com",
    "github.com",
    "githubusercontent.com",
}


class Whitelist:
    """Check IPs and domains against known-safe lists."""

    def __init__(self) -> None:
        """Initialize whitelist with built-in safe entries."""
        self._safe_ips = set(_SAFE_IPS)
        self._safe_domains = set(_SAFE_DOMAINS)
        logger.info(
            "Whitelist initialized — %d safe IPs, %d safe domains",
            len(self._safe_ips), len(self._safe_domains),
        )

    def is_safe_ip(self, ip: str) -> bool:
        """Return True if this IP is whitelisted."""
        return ip.strip() in self._safe_ips

    def is_safe_domain(self, domain: str | None) -> bool:
        """Return True if this domain or any parent domain is whitelisted."""
        if domain is None:
            return False
        domain = domain.strip().lower()
        if domain in self._safe_domains:
            return True
        # Check parent domains (e.g. "api.google.com" → "google.com")
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._safe_domains:
                return True
        return False

    def is_whitelisted(self, dst_ip: str, dst_domain: str | None = None) -> bool:
        """Return True if the destination is whitelisted by IP or domain."""
        if self.is_safe_ip(dst_ip):
            logger.debug("Whitelisted IP: %s", dst_ip)
            return True
        if self.is_safe_domain(dst_domain):
            logger.debug("Whitelisted domain: %s", dst_domain)
            return True
        return False

    def add_ip(self, ip: str) -> None:
        """Add a custom IP to the whitelist at runtime."""
        self._safe_ips.add(ip.strip())

    def add_domain(self, domain: str) -> None:
        """Add a custom domain to the whitelist at runtime."""
        self._safe_domains.add(domain.strip().lower())
