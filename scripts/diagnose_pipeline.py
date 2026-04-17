"""
Pipeline diagnostic tool — run this when flows=0 to find the blockage.

Usage:
    python scripts/diagnose_pipeline.py --pcap data/raw/pcap/real_traffic.pcap

Outputs a step-by-step breakdown showing:
- How many packets the PCAP contains
- How many pass the port filter (and which ports are seen)
- How many flows are reconstructed
- Whether TLS layers are present
- What features are produced
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pyshark

from src.flow.flow_tracker import FlowTracker
from src.ingestion.packet_filter import PacketFilter
from src.ingestion.packet_normalizer import PacketNormalizer

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose why flows=0 in your PCAP")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--max-packets", type=int, default=5000,
                        help="Max packets to inspect (default 5000)")
    args = parser.parse_args()

    pcap = Path(args.pcap)
    if not pcap.is_file():
        print(f"[ERROR] File not found: {pcap}")
        return 1

    print(f"\n=== Spectra Pipeline Diagnostics ===")
    print(f"  PCAP: {pcap}  ({pcap.stat().st_size / 1024 / 1024:.1f} MB)")

    normalizer = PacketNormalizer()
    pkt_filter = PacketFilter()
    tracker = FlowTracker()

    total_raw = 0
    normalize_ok = 0
    normalize_fail = 0
    filter_kept = 0
    filter_dropped = 0
    port_counter: Counter = Counter()
    proto_counter: Counter = Counter()
    tls_count = 0
    timestamp_errors = 0

    print(f"\n[1/4] Reading packets (max {args.max_packets})...")
    capture = pyshark.FileCapture(input_file=str(pcap), keep_packets=False)
    try:
        for pkt in capture:
            total_raw += 1
            if total_raw > args.max_packets:
                break

            # Check timestamp specifically
            ts = None
            for attr in ("sniff_timestamp", "frame_info.time_epoch"):
                try:
                    raw = getattr(pkt, attr, None)
                    if raw is not None:
                        ts = float(str(raw))
                        break
                except Exception:
                    pass
            if ts is None:
                timestamp_errors += 1

            # Check layers
            has_ip = hasattr(pkt, "ip") or hasattr(pkt, "ipv6")
            has_tcp = hasattr(pkt, "tcp")
            has_udp = hasattr(pkt, "udp")
            has_tls = hasattr(pkt, "tls") or hasattr(pkt, "ssl")

            if has_tls:
                tls_count += 1

            if has_tcp:
                proto_counter["TCP"] += 1
                try:
                    dport = int(str(pkt.tcp.dstport))
                    sport = int(str(pkt.tcp.srcport))
                    port_counter[f"TCP:{min(sport,dport)}"] += 1
                except Exception:
                    pass
            elif has_udp:
                proto_counter["UDP"] += 1
                try:
                    dport = int(str(pkt.udp.dstport))
                    port_counter[f"UDP:{dport}"] += 1
                except Exception:
                    pass
            elif not has_ip:
                proto_counter["OTHER"] += 1

            # Try normalize
            norm = normalizer.normalize(pkt)
            if norm is None:
                normalize_fail += 1
                continue
            normalize_ok += 1

            # Try filter
            if pkt_filter.should_keep(norm):
                filter_kept += 1
                completed = tracker.add_packet(norm)
            else:
                filter_dropped += 1
    finally:
        capture.close()

    # Force-flush remaining flows
    from src.flow.flow_tracker import FlowTracker as FT
    force_time = 999999999999.0
    timed_out = tracker.check_timeouts(force_time)
    stats = tracker.get_stats()

    print(f"\n[2/4] Packet breakdown (first {min(total_raw, args.max_packets)} packets):")
    print(f"  Total raw packets seen:     {total_raw}")
    print(f"  Timestamp parse errors:     {timestamp_errors}  {'[WARNING: will cause 0 flows!]' if timestamp_errors > total_raw * 0.5 else ''}")
    print(f"  Normalize success:          {normalize_ok}")
    print(f"  Normalize fail:             {normalize_fail}")
    print(f"  Protocol breakdown:         {dict(proto_counter.most_common(5))}")
    print(f"  TLS layer packets:          {tls_count}")

    print(f"\n[3/4] Port filter breakdown:")
    print(f"  Packets passed filter:      {filter_kept}")
    print(f"  Packets dropped by filter:  {filter_dropped}")
    print(f"  Configured TLS TCP ports:   {sorted(pkt_filter.tls_tcp_ports)}")
    print(f"\n  Top 15 port pairs seen:")
    for port_str, count in port_counter.most_common(15):
        in_filter = int(port_str.split(":")[1]) in pkt_filter.tls_tcp_ports
        flag = " <-- IN FILTER" if in_filter else ""
        print(f"    {port_str}: {count}{flag}")

    print(f"\n[4/4] Flow reconstruction:")
    print(f"  Active flows remaining:     {stats['active_flows']}")
    print(f"  Completed flows (FIN/RST):  {stats['completed_flows']}")
    print(f"  Timed-out flows (flushed):  {len(timed_out)}")
    total_flows = stats["completed_flows"] + len(timed_out)
    print(f"  TOTAL flows produced:       {total_flows}")

    print(f"\n=== Diagnosis ===")
    if total_raw == 0:
        print("  [FAIL] PCAP file has no packets — may be corrupt or wrong format")
    elif timestamp_errors > total_raw * 0.5:
        print("  [FAIL] >50% of packets have unparseable timestamps")
        print("         Re-export from Wireshark as .pcap (not .pcapng) and retry")
    elif filter_kept == 0:
        print("  [FAIL] ALL packets dropped by port filter")
        top_ports = [p.split(":")[1] for p, _ in port_counter.most_common(5)]
        print(f"         Your traffic uses ports: {top_ports}")
        print(f"         Add them to configs/default.yaml under network.tls_tcp_ports")
    elif total_flows == 0:
        print("  [FAIL] Packets pass filter but no flows form")
        print("         All connections may be single-packet (SYN only) or malformed")
        print("         Check that min_packets_per_flow = 1 in configs/default.yaml")
    else:
        print(f"  [OK]  Pipeline is working — {total_flows} flows would be produced")
        if tls_count == 0:
            print("  [WARN] No TLS handshake packets found — JA3/cert scoring will be 0")
            print("         Capture on an interface that sees TLS handshakes")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())