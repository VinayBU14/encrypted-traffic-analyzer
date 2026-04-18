"""
Step 1 — Extract TCP flows from raw PCAP using Scapy.

This script bypasses Spectra's PacketFilter (which only keeps TLS ports 443/8443)
and instead keeps ALL TCP packets, groups them into bidirectional 5-tuple flows,
extracts the same flow features Spectra uses (FLOW_FEATURE_COLUMNS from schema.py),
and saves them to a CSV ready for ML training.

Usage:
    python step1_extract_tcp_flows.py --pcap data/raw/pcap/real_traffic.pcap
    python step1_extract_tcp_flows.py --pcap data/raw/pcap/test_sample.pcap
"""

from __future__ import annotations

import argparse
import logging
from collections import defaultdict
from pathlib import Path

import socket

import dpkt
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# These match Spectra's FLOW_FEATURE_COLUMNS exactly (src/features/schema.py)
FLOW_FEATURE_COLUMNS = [
    "duration_ms",
    "total_packets",
    "total_bytes",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "packet_rate_per_sec",
    "byte_rate_per_sec",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_iat_ms",
    "min_iat_ms",
    "max_iat_ms",
    "std_iat_ms",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
]


def canonical_key(src_ip, sport, dst_ip, dport) -> tuple:
    """Build a bidirectional canonical 5-tuple key (lower endpoint first)."""
    a = (src_ip, sport)
    b = (dst_ip, dport)
    if a <= b:
        return (src_ip, sport, dst_ip, dport)
    return (dst_ip, dport, src_ip, sport)


def safe_float(v) -> float:
    try:
        f = float(v)
        return 0.0 if (np.isnan(f) or np.isinf(f)) else f
    except Exception:
        return 0.0


def extract_features(key: tuple, pkts: list) -> dict:
    """Extract Spectra-compatible flow features from a list of (ts, pkt_len, ip, tcp) tuples."""
    src_ip, src_port, dst_ip, dst_port = key

    pkts = sorted(pkts, key=lambda x: x[0])
    times = [p[0] for p in pkts]
    sizes = [p[1] for p in pkts]

    duration_s = times[-1] - times[0] if len(times) > 1 else 0.0
    duration_ms = duration_s * 1000.0

    fwd_sizes = [p[1] for p in pkts if socket.inet_ntoa(p[2].src) == src_ip and p[3].sport == src_port]
    bwd_sizes = [p[1] for p in pkts if not (socket.inet_ntoa(p[2].src) == src_ip and p[3].sport == src_port)]

    fwd_bytes = sum(fwd_sizes)
    bwd_bytes = sum(bwd_sizes)
    total_bytes = sum(sizes)
    total_packets = len(pkts)

    packet_rate = (total_packets / duration_s) if duration_s > 0 else 0.0
    byte_rate = (total_bytes / duration_s) if duration_s > 0 else 0.0

    iats = [(times[i] - times[i - 1]) * 1000.0 for i in range(1, len(times))]

    # TCP flags (dpkt tcp.flags bitmask)
    syn = sum(1 for p in pkts if p[3].flags & dpkt.tcp.TH_SYN)
    ack = sum(1 for p in pkts if p[3].flags & dpkt.tcp.TH_ACK)
    fin = sum(1 for p in pkts if p[3].flags & dpkt.tcp.TH_FIN)
    rst = sum(1 for p in pkts if p[3].flags & dpkt.tcp.TH_RST)
    psh = sum(1 for p in pkts if p[3].flags & dpkt.tcp.TH_PUSH)

    arr = np.array(sizes, dtype=float)
    iat_arr = np.array(iats, dtype=float) if iats else np.array([0.0])

    row = {
        "flow_id": f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "duration_ms": safe_float(duration_ms),
        "total_packets": safe_float(total_packets),
        "total_bytes": safe_float(total_bytes),
        "fwd_packets": safe_float(len(fwd_sizes)),
        "bwd_packets": safe_float(len(bwd_sizes)),
        "fwd_bytes": safe_float(fwd_bytes),
        "bwd_bytes": safe_float(bwd_bytes),
        "packet_rate_per_sec": safe_float(packet_rate),
        "byte_rate_per_sec": safe_float(byte_rate),
        "avg_packet_size": safe_float(float(np.mean(arr))),
        "min_packet_size": safe_float(float(np.min(arr))),
        "max_packet_size": safe_float(float(np.max(arr))),
        "std_packet_size": safe_float(float(np.std(arr))) if len(arr) > 1 else 0.0,
        "mean_iat_ms": safe_float(float(np.mean(iat_arr))),
        "min_iat_ms": safe_float(float(np.min(iat_arr))),
        "max_iat_ms": safe_float(float(np.max(iat_arr))),
        "std_iat_ms": safe_float(float(np.std(iat_arr))) if len(iat_arr) > 1 else 0.0,
        "syn_count": safe_float(syn),
        "ack_count": safe_float(ack),
        "fin_count": safe_float(fin),
        "rst_count": safe_float(rst),
        "psh_count": safe_float(psh),
    }
    return row


def extract_flows(pcap_path: str, min_packets: int = 2) -> pd.DataFrame:
    logger.info("Reading PCAP: %s", pcap_path)

    flows: dict[tuple, list] = defaultdict(list)
    total = 0
    tcp_count = 0

    with open(pcap_path, "rb") as f:
        try:
            pcap = dpkt.pcapng.Reader(f)
        except ValueError:
            f.seek(0)
            pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            total += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp_count += 1
                tcp = ip.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                key = canonical_key(src, tcp.sport, dst, tcp.dport)
                flows[key].append((ts, len(buf), ip, tcp))
            except Exception:
                continue

    logger.info("Total packets: %d | TCP packets: %d", total, tcp_count)
    logger.info("Unique TCP flows (before min_packets filter): %d", len(flows))

    rows = []
    for key, pkts in flows.items():
        if len(pkts) < min_packets:
            continue
        rows.append(extract_features(key, pkts))

    logger.info("Flows kept (>= %d packets): %d", min_packets, len(rows))

    if not rows:
        raise ValueError("No flows extracted. Try lowering --min-packets or check your PCAP.")

    df = pd.DataFrame(rows)
    return df


def main():
    parser = argparse.ArgumentParser(description="Extract TCP flows from PCAP for ML training")
    parser.add_argument("--pcap", required=True, help="Path to input .pcap file")
    parser.add_argument("--out", default="data/processed/tcp_flows.csv", help="Output CSV path")
    parser.add_argument("--min-packets", type=int, default=2, help="Minimum packets per flow (default: 2)")
    args = parser.parse_args()

    df = extract_flows(args.pcap, min_packets=args.min_packets)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    logger.info("Saved %d flows to %s", len(df), out_path)
    logger.info("Columns: %s", list(df.columns))
    logger.info("\nFeature summary:\n%s", df[FLOW_FEATURE_COLUMNS].describe().to_string())


if __name__ == "__main__":
    main()