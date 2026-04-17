"""Whitelist of known-safe IPs and domains that should never be alerted on."""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)

# Known-safe CIDR ranges — major CDNs, DNS resolvers, update servers
# FIXED: Previously stored as plain strings and checked with `ip in set` which
# NEVER matched any real IP address (CIDR string != dotted-decimal IP).
# Now parsed into ip_network objects and checked with `addr in network`.
_SAFE_CIDR_LIST: list[str] = [
    # Google DNS
    "8.8.8.0/24",
    "8.8.4.0/24",
    # Google Services
    "142.250.0.0/15",
    "172.217.0.0/16",
    "172.253.0.0/16",
    "74.125.0.0/16",
    "216.58.192.0/19",
    "64.233.160.0/19",
    "108.177.0.0/17",
    "209.85.128.0/17",
    # Cloudflare
    "103.21.244.0/22",
    "103.22.200.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    # Cloudflare DNS
    "1.1.1.0/24",
    "1.0.0.0/24",
    # Quad9 DNS
    "9.9.9.0/24",
    "149.112.112.0/24",
    # OpenDNS
    "208.67.222.0/24",
    "208.67.220.0/24",
    "146.112.0.0/16",
    # Microsoft / Office 365
    "13.107.0.0/16",
    "52.96.0.0/19",
    "40.96.0.0/12",
    "52.108.0.0/14",
    # Facebook / Meta
    "31.13.64.0/18",
    "57.141.0.0/16",
    "57.144.0.0/14",
    "66.220.144.0/20",
    "69.63.176.0/20",
    "69.171.224.0/19",
    "129.134.0.0/16",
    "157.240.0.0/16",
    "173.252.64.0/18",
    # AWS
    "52.0.0.0/11",
    "54.0.0.0/8",
    # GitHub
    "192.30.252.0/22",
    "185.199.108.0/22",
    # Fastly CDN
    "151.101.0.0/16",
    # Akamai CDN
    "104.64.0.0/10",
    # Netflix CDN
    "23.246.0.0/18",
    "45.57.0.0/17",
    "64.120.128.0/17",
    "66.197.128.0/17",
    # Twitter/X
    "199.16.156.0/22",
    "199.59.148.0/22",
    # LinkedIn
    "144.2.0.0/19",
    "108.174.0.0/16",
    # Apple
    "17.0.0.0/8",
]

# Known-safe SNI domains
_SAFE_DOMAINS: set[str] = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googlevideo.com",
    "youtube.com",
    "ytimg.com",
    "microsoft.com",
    "office365.com",
    "microsoftonline.com",
    "windows.com",
    "windowsupdate.com",
    "live.com",
    "outlook.com",
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "cloudflare.com",
    "akamai.com",
    "akamaihd.net",
    "fastly.com",
    "fastly.net",
    "amazonaws.com",
    "amazon.com",
    "github.com",
    "githubusercontent.com",
    "twitter.com",
    "x.com",
    "t.co",
    "facebook.com",
    "fbcdn.net",
    "instagram.com",
    "whatsapp.com",
    "whatsapp.net",
    "linkedin.com",
    "licdn.com",
    "netflix.com",
    "nflxvideo.net",
    "spotify.com",
    "scdn.co",
    "dropbox.com",
    "dropboxstatic.com",
    "slack.com",
    "slack-edge.com",
    "zoom.us",
    "zoomgov.com",
}


class Whitelist:
    """Check IPs and domains against known-safe lists."""

    def __init__(self) -> None:
        """Build ip_network objects from CIDR list once at startup."""
        self._safe_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._safe_domains = set(_SAFE_DOMAINS)

        for cidr in _SAFE_CIDR_LIST:
            try:
                self._safe_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as exc:
                logger.warning("Skipping invalid CIDR in whitelist: %s — %s", cidr, exc)

        logger.info(
            "Whitelist initialized — %d safe networks, %d safe domains",
            len(self._safe_networks),
            len(self._safe_domains),
        )

    def is_safe_ip(self, ip: str) -> bool:
        """Return True if this IP falls inside any whitelisted CIDR range."""
        try:
            addr = ipaddress.ip_address(ip.strip())
            return any(addr in net for net in self._safe_networks)
        except ValueError:
            return False

    def is_safe_domain(self, domain: str | None) -> bool:
        """Return True if this domain or any parent domain is whitelisted."""
        if domain is None:
            return False
        domain = domain.strip().lower()
        if domain in self._safe_domains:
            return True
        # Check parent domains: "api.google.com" → "google.com"
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
        """Add a custom IP or CIDR to the whitelist at runtime."""
        try:
            if "/" in ip:
                self._safe_networks.append(ipaddress.ip_network(ip.strip(), strict=False))
            else:
                # Single host — wrap as /32
                self._safe_networks.append(
                    ipaddress.ip_network(f"{ip.strip()}/32", strict=False)
                )
        except ValueError as exc:
            logger.warning("Could not add IP to whitelist: %s — %s", ip, exc)

    def add_domain(self, domain: str) -> None:
        """Add a custom domain to the whitelist at runtime."""
        self._safe_domains.add(domain.strip().lower())