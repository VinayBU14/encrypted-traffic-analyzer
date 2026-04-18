"""Run live encrypted-traffic analysis from the command line.

This script wires the live capture pipeline into an argparse CLI for real-time scoring,
alert printing, optional database writes, and optional CSV export.

Usage examples:

    python live_analyze.py --list-interfaces
    python live_analyze.py --interface "Wi-Fi" --mode supervised
    python live_analyze.py --mode unsupervised --no-db --packet-limit 500
    python live_analyze.py --bpf-filter "tcp port 443" --out-csv data/processed/live_scored.csv
    python live_analyze.py --alert-only --batch-size 20 --flow-timeout 45
"""

from __future__ import annotations

import argparse
import csv
import logging
from pathlib import Path
from typing import Any

from live_capture_pipeline import LiveCapturePipeline
from step4_score_flows import _score_to_severity


class CsvAppender:
    """Append scored flow records to CSV incrementally."""

    def __init__(self, csv_path: str) -> None:
        """Initialize output path and deferred header state."""
        self.path = Path(csv_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fieldnames: list[str] | None = None

    def append_row(self, row: dict[str, Any]) -> None:
        """Append one row and write header once when needed."""
        if self._fieldnames is None:
            self._fieldnames = list(row.keys())

        file_exists = self.path.exists()
        should_write_header = (not file_exists) or (self.path.stat().st_size == 0)

        with self.path.open("a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=self._fieldnames, extrasaction="ignore")
            if should_write_header:
                writer.writeheader()
            writer.writerow(row)


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(description="Live encrypted traffic analysis")
    parser.add_argument("--interface", default="Wi-Fi", help="Network interface name")
    parser.add_argument(
        "--mode",
        choices=["supervised", "unsupervised"],
        default="supervised",
        help="Scoring mode",
    )
    parser.add_argument("--model-dir", default="models/ml", help="Model directory")
    parser.add_argument("--db", default="spectra.db", help="Path to spectra.db")
    parser.add_argument("--no-db", action="store_true", help="Skip database writes")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Flows to accumulate before scoring",
    )
    parser.add_argument(
        "--flow-timeout",
        type=int,
        default=60,
        help="Seconds before a flow is finalized",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        default=2,
        help="Minimum packets for a flow to be scored",
    )
    parser.add_argument(
        "--bpf-filter",
        default="",
        help="BPF filter string (example: tcp port 443)",
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=0,
        help="Stop after N packets (0 = infinite)",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Print available interfaces and exit",
    )
    parser.add_argument(
        "--out-csv",
        default="",
        help="Append scored flows to this CSV in real time",
    )
    parser.add_argument(
        "--alert-only",
        action="store_true",
        help="Only print non-BENIGN flows to stdout",
    )
    return parser


def _extract_score(flow: dict[str, Any]) -> float:
    """Choose a primary score for display and severity mapping."""
    if flow.get("anomaly_score") is not None:
        try:
            return float(flow.get("anomaly_score", 0.0))
        except Exception:
            return 0.0

    if flow.get("malicious_probability") is not None:
        try:
            return float(flow.get("malicious_probability", 0.0))
        except Exception:
            return 0.0

    return 0.0


def _format_alert_line(flow: dict[str, Any]) -> str:
    """Format one scored flow into the required alert output string."""
    score = _extract_score(flow)
    severity = _score_to_severity(score)

    src_ip = str(flow.get("src_ip", ""))
    src_port = flow.get("src_port", "")
    dst_ip = str(flow.get("dst_ip", ""))
    dst_port = flow.get("dst_port", "")
    verdict = str(flow.get("verdict", "UNKNOWN"))

    beacon = float(flow.get("beacon_score", 0.0) or 0.0)
    ja3 = float(flow.get("ja3_score", 0.0) or 0.0)

    return (
        f"[{severity}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
        f"| score={score:.2f} | verdict={verdict} | beacon={beacon:.2f} ja3={ja3:.2f}"
    )


def main() -> None:
    """CLI entrypoint for live capture and scoring."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logger = logging.getLogger(__name__)

    parser = build_parser()
    args = parser.parse_args()

    if args.list_interfaces:
        interfaces = LiveCapturePipeline.list_interfaces()
        if not interfaces:
            print("No interfaces found")
            return

        print("Available interfaces:")
        for idx, name in enumerate(interfaces, start=1):
            print(f"{idx}. {name}")
        return

    csv_appender = CsvAppender(args.out_csv) if args.out_csv else None

    def on_alert(scored_flow_dict: dict[str, Any]) -> None:
        """Print and optionally persist each non-benign flow from callback."""
        print(_format_alert_line(scored_flow_dict))
        if csv_appender is not None:
            csv_appender.append_row(scored_flow_dict)

    pipeline = LiveCapturePipeline(
        interface=args.interface,
        mode=args.mode,
        model_dir=args.model_dir,
        project_root=".",
        db_path=args.db,
        no_db=args.no_db,
        batch_size=args.batch_size,
        flow_timeout_seconds=args.flow_timeout,
        min_packets=args.min_packets,
        bpf_filter=args.bpf_filter,
        packet_limit=args.packet_limit,
        on_alert=on_alert,
    )

    # Capture all scored rows for stdout/CSV output without changing pipeline module.
    original_process_scored = pipeline._process_scored_results

    def patched_process_scored_results(scored_results: list[dict[str, Any]]) -> None:
        """Mirror scored rows to stdout/CSV, then run pipeline's original handling."""
        for scored_flow in scored_results:
            verdict = str(scored_flow.get("verdict", "BENIGN"))

            # Non-BENIGN rows are already handled by on_alert callback.
            # Handle BENIGN rows here so --out-csv can include all scored flows.
            if csv_appender is not None and verdict == "BENIGN":
                csv_appender.append_row(scored_flow)

            if (not args.alert_only) and verdict == "BENIGN":
                print(
                    f"[CLEAN] {scored_flow.get('src_ip', '')}:{scored_flow.get('src_port', '')} "
                    f"-> {scored_flow.get('dst_ip', '')}:{scored_flow.get('dst_port', '')} "
                    f"| verdict={verdict}"
                )

        original_process_scored(scored_results)

    pipeline._process_scored_results = patched_process_scored_results  # type: ignore[method-assign]

    print("=== Live Analyze Startup ===")
    print(f"Interface: {args.interface}")
    print(f"Mode: {args.mode}")
    print(f"DB: {args.db}{' (disabled)' if args.no_db else ''}")
    print(f"Batch size: {args.batch_size}")

    try:
        pipeline.run()
    except KeyboardInterrupt:
        print("Stopping capture...")
        pipeline.stop()
        logger.info("KeyboardInterrupt handled in CLI")

    stats = pipeline.get_stats()
    print("=== Final Stats ===")
    print(f"Packets captured: {stats['packets_captured']}")
    print(f"Flows completed: {stats['flows_completed']}")
    print(f"Flows scored: {stats['flows_scored']}")
    print(f"Alerts generated: {stats['alerts_generated']}")
    print(f"Active flows: {stats['active_flows']}")


if __name__ == "__main__":
    main()
