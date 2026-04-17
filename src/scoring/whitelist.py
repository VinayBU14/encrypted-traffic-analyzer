"""Whitelist of known-safe IPs and domains that should never be alerted on."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Known-safe destination IPs – major CDNs, DNS resolvers, update servers
_SAFE_IPS: set[str] = {
    # Google DNS
    "8.8.8.0/24",
    "8.8.4.0/24",
    
    # Google Services
    "142.250.0.0/15",          # Google main services [[10]]
    "172.217.0.0/16",          # Google services [[10]]
    "172.253.0.0/16",          # Google services [[10]]
    "74.125.0.0/16",           # Google services [[10]]
    "216.58.192.0/19",         # Google services [[10]]
    "64.233.160.0/19",         # Google services [[10]]
    "66.249.64.0/19",          # Googlebot [[10]]
    "108.177.0.0/17",          # Google services [[10]]
    "209.85.128.0/17",         # Google services [[10]]
    
    # Cloudflare
    "103.21.244.0/22",         # Cloudflare [[17]]
    "103.22.200.0/22",         # Cloudflare [[17]]
    "104.16.0.0/13",           # Cloudflare [[17]]
    "104.24.0.0/14",           # Cloudflare [[17]]
    "108.162.192.0/18",        # Cloudflare [[17]]
    "141.101.64.0/18",         # Cloudflare [[17]]
    "162.158.0.0/15",          # Cloudflare [[17]]
    "172.64.0.0/13",           # Cloudflare [[17]]
    "173.245.48.0/20",         # Cloudflare [[17]]
    "188.114.96.0/20",         # Cloudflare [[17]]
    "190.93.240.0/20",         # Cloudflare [[17]]
    "197.234.240.0/22",        # Cloudflare [[17]]
    "198.41.128.0/17",         # Cloudflare [[17]]
    
    # Cloudflare DNS (1.1.1.1)
    "1.1.1.0/24",
    "1.0.0.0/24",
    
    # Quad9 DNS
    "9.9.9.0/24",              # Quad9 DNS [[48]]
    "149.112.112.0/24",        # Quad9 DNS [[48]]
    
    # OpenDNS/Cisco
    "208.67.222.0/24",         # OpenDNS [[66]]
    "208.67.220.0/24",         # OpenDNS [[66]]
    "146.112.0.0/16",          # Cisco OpenDNS [[66]]
    
    # Microsoft/Office 365
    "13.107.0.0/16",           # Microsoft services
    "52.96.0.0/19",            # Microsoft 365
    "40.96.0.0/12",            # Office 365
    "52.108.0.0/14",           # Office 365
    
    # Facebook/Meta
    "31.13.64.0/18",           # Meta/Facebook [[43]]
    "57.141.0.0/16",           # Meta Platforms [[43]]
    "57.144.0.0/14",           # Meta Platforms [[43]]
    "66.220.144.0/20",         # Facebook [[43]]
    "69.63.176.0/20",          # Facebook [[43]]
    "69.171.224.0/19",         # Facebook [[43]]
    "129.134.0.0/16",          # Facebook [[43]]
    "157.240.0.0/16",          # Facebook [[43]]
    "173.252.64.0/18",         # Facebook [[43]]
    
    # AWS (Amazon)
    "52.0.0.0/11",             # AWS EC2
    "54.0.0.0/8",              # AWS EC2
    
    # GitHub
    "192.30.252.0/22",         # GitHub [[128]]
    "185.199.108.0/22",        # GitHub Pages
    
    # Fastly CDN
    "151.101.0.0/16",          # Fastly [[96]]
    
    # Akamai CDN
    "104.64.0.0/10",           # Akamai [[79]]
    
    # Netflix CDN
    "23.246.0.0/18",           # Netflix [[99]]
    "45.57.0.0/17",            # Netflix [[99]]
    "64.120.128.0/17",         # Netflix [[99]]
    "66.197.128.0/17",         # Netflix [[99]]
    
    # Twitter/X
    "199.16.156.0/22",         # Twitter/X [[111]]
    "199.59.148.0/22",         # Twitter/X [[111]]
    
    # LinkedIn
    "144.2.0.0/19",            # LinkedIn [[117]]
    "108.174.0.0/16",          # LinkedIn [[126]]
    
    # Apple
    "17.0.0.0/8",              # Apple Inc [[73]]
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
