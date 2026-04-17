
"""
Seed threat intelligence databases from real public feeds.

Downloads and merges:
- Abuse.ch SSL Blacklist JA3 fingerprints (malicious)
- Abuse.ch URLhaus IP blocklist
- Feodo Tracker botnet C2 IPs

Usage:
    python scripts/seed_threat_intel.py

Writes updated JSON files to data/threat_intel/
"""

from __future__ import annotations

import json
import logging
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

THREAT_INTEL_DIR = PROJECT_ROOT / "data" / "threat_intel"

# Abuse.ch SSL Blacklist JA3 fingerprints (CSV: ja3_md5,first_seen,last_seen,listing_reason)
SSLBL_JA3_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"

# Feodo Tracker botnet C2 IPs (JSON)
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def _fetch(url: str, timeout: int = 15) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Spectra/1.0 ThreatIntelSeeder"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


def seed_ja3() -> int:
    """Fetch Abuse.ch SSL Blacklist JA3s and merge into ja3_malicious.json."""
    existing_path = THREAT_INTEL_DIR / "ja3_malicious.json"
    existing: dict = {}
    if existing_path.exists():
        try:
            existing = json.loads(existing_path.read_text())
        except Exception:
            pass

    content = _fetch(SSLBL_JA3_URL)
    if content is None:
        logger.warning("Could not fetch SSLBL JA3 list — using existing file")
        return 0

    added = 0
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 1:
            continue
        ja3_hash = parts[0].strip().lower()
        if len(ja3_hash) != 32:
            continue  # not an MD5
        label = parts[3].strip() if len(parts) >= 4 else "sslbl_abuse_ch"
        if ja3_hash not in existing:
            existing[ja3_hash] = {"label": label, "source": "sslbl.abuse.ch"}
            added += 1

    existing_path.write_text(json.dumps(existing, indent=2))
    logger.info("JA3 malicious: %d total entries (+%d new)", len(existing), added)
    return added


def seed_ip_reputation() -> int:
    """Fetch Feodo Tracker botnet IPs and merge into ip_reputation.json."""
    existing_path = THREAT_INTEL_DIR / "ip_reputation.json"
    existing: dict = {}
    if existing_path.exists():
        try:
            existing = json.loads(existing_path.read_text())
        except Exception:
            pass

    content = _fetch(FEODO_URL)
    if content is None:
        logger.warning("Could not fetch Feodo Tracker — using existing file")
        return 0

    added = 0
    try:
        data = json.loads(content)
        for entry in data:
            ip = str(entry.get("ip_address", "")).strip()
            if not ip:
                continue
            malware = str(entry.get("malware", "unknown"))
            if ip not in existing:
                existing[ip] = {
                    "score": 1.0,
                    "label": f"Feodo:{malware}",
                    "source": "feodotracker.abuse.ch",
                }
                added += 1
    except Exception as exc:
        logger.warning("Failed to parse Feodo JSON: %s", exc)

    existing_path.write_text(json.dumps(existing, indent=2))
    logger.info("IP reputation: %d total entries (+%d new)", len(existing), added)
    return added


def main() -> int:
    THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)

    print("Seeding threat intelligence databases...")
    ja3_added = seed_ja3()
    ip_added = seed_ip_reputation()

    print(f"\n[OK] Threat intel updated:")
    print(f"  JA3 malicious entries added: {ja3_added}")
    print(f"  IP reputation entries added: {ip_added}")
    print(f"  Files written to: {THREAT_INTEL_DIR}")
    print("\nRestart the API server to use the updated threat intel.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())