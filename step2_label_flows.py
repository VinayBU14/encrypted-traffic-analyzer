"""
Step 2 — Label flows for supervised ML training.

Reads the flow CSV from step1, applies labeling rules from Spectra's
threat intel files and traffic heuristics, and outputs a labeled CSV.

Labeling strategies (applied in order, first match wins):
  1. Known malicious IPs from data/threat_intel/ip_reputation.json -> malicious
  2. Known C2 server IPs                                           -> malicious
  3. TOR exit node IPs                                             -> malicious
  4. Suspicious destination ports (common C2/RAT ports)           -> suspicious (label=0.5, filtered out for binary)
  5. Very high RST ratio (port scanning pattern)                  -> malicious
  6. Everything else                                               -> benign

For binary classification (benign=0 / malicious=1), suspicious flows
are excluded from training to keep labels clean.

Usage:
    python step2_label_flows.py
    python step2_label_flows.py --flows data/processed/tcp_flows.csv --out data/processed/labeled_flows.csv
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Ports commonly used by malware/RATs for C2 (beyond standard TLS ports)
SUSPICIOUS_DST_PORTS = {
    4444,   # Metasploit default
    1337,   # Common RAT
    6666, 6667, 6668,  # IRC-based botnets
    8888,   # Common backdoor
    31337,  # Common backdoor
    12345,  # NetBus RAT
    54321,  # Reverse shells
    9001, 9030,  # TOR default
    2222,   # Common SSH brute target
    4000,   # Common backdoor
    1080,   # SOCKS proxy abuse
}

# High packet volume + tiny payload = likely port scan or keepalive beacon
def is_scan_pattern(row) -> bool:
    if row["total_packets"] < 10:
        return False
    if row["total_bytes"] == 0:
        return False
    avg_size = row["avg_packet_size"]
    rst_ratio = row["rst_count"] / row["total_packets"]
    # High RST ratio with small packets = scan
    return rst_ratio > 0.4 and avg_size < 100


def load_threat_intel(project_root: Path) -> tuple[set, set, set]:
    ip_rep_path = project_root / "data" / "threat_intel" / "ip_reputation.json"
    if not ip_rep_path.exists():
        logger.warning("ip_reputation.json not found, using empty sets")
        return set(), set(), set()

    data = json.loads(ip_rep_path.read_text())
    malicious = set(data.get("malicious_ips", []))
    tor_exits = set(data.get("tor_exit_nodes", []))
    c2_servers = set(data.get("known_c2_servers", []))
    logger.info("Threat intel loaded: %d malicious IPs, %d TOR exits, %d C2 servers",
                len(malicious), len(tor_exits), len(c2_servers))
    return malicious, tor_exits, c2_servers


def label_row(row, malicious_ips: set, tor_exits: set, c2_servers: set) -> str:
    """Return 'malicious', 'benign', or 'suspicious' for one flow row."""
    src_ip = str(row["src_ip"])
    dst_ip = str(row["dst_ip"])
    dst_port = int(row["dst_port"])

    # Rule 1: Known malicious IPs
    if src_ip in malicious_ips or dst_ip in malicious_ips:
        return "malicious"

    # Rule 2: Known C2 servers
    if src_ip in c2_servers or dst_ip in c2_servers:
        return "malicious"

    # Rule 3: TOR exit nodes
    if src_ip in tor_exits or dst_ip in tor_exits:
        return "malicious"

    # Rule 4: Suspicious ports
    if dst_port in SUSPICIOUS_DST_PORTS or int(row["src_port"]) in SUSPICIOUS_DST_PORTS:
        return "suspicious"

    # Rule 5: Scan-like pattern
    if is_scan_pattern(row):
        return "malicious"

    return "benign"


def main():
    parser = argparse.ArgumentParser(description="Label TCP flows for ML training")
    parser.add_argument("--flows", default="data/processed/tcp_flows.csv")
    parser.add_argument("--out", default="data/processed/labeled_flows.csv")
    parser.add_argument("--project-root", default=".", help="Project root (where configs/ and data/ live)")
    parser.add_argument("--keep-suspicious", action="store_true",
                        help="Include suspicious flows as malicious instead of dropping them")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    df = pd.read_csv(args.flows)
    logger.info("Loaded %d flows from %s", len(df), args.flows)

    malicious_ips, tor_exits, c2_servers = load_threat_intel(project_root)

    df["label_str"] = df.apply(
        lambda row: label_row(row, malicious_ips, tor_exits, c2_servers), axis=1
    )

    # Print distribution before filtering
    dist = df["label_str"].value_counts()
    logger.info("Label distribution before filtering:\n%s", dist.to_string())

    if args.keep_suspicious:
        df.loc[df["label_str"] == "suspicious", "label_str"] = "malicious"
    else:
        n_suspicious = (df["label_str"] == "suspicious").sum()
        df = df[df["label_str"] != "suspicious"].copy()
        logger.info("Dropped %d suspicious flows (use --keep-suspicious to include as malicious)", n_suspicious)

    df["label"] = (df["label_str"] == "malicious").astype(int)

    final_dist = df["label"].value_counts()
    logger.info("Final label distribution:\n  benign (0): %d\n  malicious (1): %d",
                final_dist.get(0, 0), final_dist.get(1, 0))

    if final_dist.get(1, 0) == 0:
        logger.warning(
            "WARNING: 0 malicious flows found! Your PCAP appears to be clean benign traffic.\n"
            "Options:\n"
            "  1. Combine with CICIDS2017 dataset for malicious samples\n"
            "  2. Run step3_train_model.py with --mode unsupervised (IsolationForest)\n"
            "  3. Generate synthetic attacks in a VM and capture a new PCAP"
        )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    logger.info("Saved labeled flows to %s", out_path)


if __name__ == "__main__":
    main()