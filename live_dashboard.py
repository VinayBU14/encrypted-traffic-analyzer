"""Live terminal dashboard for encrypted traffic monitoring.

This CLI launches the live capture pipeline and renders a continuously updating
terminal dashboard using rich.

Usage examples:

    python live_dashboard.py --list-interfaces
    python live_dashboard.py --interface "Wi-Fi" --mode supervised
    python live_dashboard.py --mode unsupervised --no-db
    python live_dashboard.py --bpf-filter "tcp port 443" --batch-size 20 --flow-timeout 45
"""

from __future__ import annotations

import argparse
import threading
import time
from datetime import datetime
from typing import Any

from live_capture_pipeline import LiveCapturePipeline
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from step4_score_flows import _score_to_severity


def _primary_score(flow: dict[str, Any]) -> float:
    """Return a primary score value from known scoring outputs."""
    for key in ("anomaly_score", "malicious_probability"):
        value = flow.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except Exception:
            continue
    return 0.0


def _format_findings(flow: dict[str, Any]) -> str:
    """Build compact findings text for the dashboard table."""
    findings = flow.get("findings")
    if findings:
        return str(findings)

    tags: list[str] = []
    if float(flow.get("beacon_score", 0.0) or 0.0) >= 0.60:
        tags.append("Beacon")
    if float(flow.get("ja3_score", 0.0) or 0.0) >= 0.60:
        tags.append("JA3")
    if float(flow.get("cert_score", 0.0) or 0.0) >= 0.50:
        tags.append("Cert")
    if not tags:
        return "-"
    return ", ".join(tags)


def make_alert_table(alerts: list[dict[str, Any]]) -> Table:
    """Create a colorized rich table showing the latest alerts.

    The table displays the most recent 20 rows in descending time order.
    """
    table = Table(title="Live Alerts", expand=True)
    table.add_column("#", justify="right", width=4)
    table.add_column("Time", width=10)
    table.add_column("Src IP:Port", min_width=20)
    table.add_column("Dst IP:Port", min_width=20)
    table.add_column("Verdict", width=12)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Beacon", justify="right", width=8)
    table.add_column("JA3", justify="right", width=8)
    table.add_column("Cert", justify="right", width=8)
    table.add_column("Findings", overflow="fold")

    severity_colors: dict[str, str] = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "BENIGN": "green",
    }

    recent_alerts = list(reversed(alerts[-20:]))

    for idx, alert in enumerate(recent_alerts, start=1):
        score = _primary_score(alert)
        severity = _score_to_severity(score)
        color = severity_colors.get(severity, "white")

        ts = alert.get("timestamp")
        if ts is None:
            time_str = datetime.now().strftime("%H:%M:%S")
        else:
            try:
                time_str = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
            except Exception:
                time_str = datetime.now().strftime("%H:%M:%S")

        src = f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}"
        dst = f"{alert.get('dst_ip', '')}:{alert.get('dst_port', '')}"
        verdict = str(alert.get("verdict", "UNKNOWN"))
        beacon = float(alert.get("beacon_score", 0.0) or 0.0)
        ja3 = float(alert.get("ja3_score", 0.0) or 0.0)
        cert = float(alert.get("cert_score", 0.0) or 0.0)

        row_style = color
        table.add_row(
            str(idx),
            time_str,
            src,
            dst,
            verdict,
            f"{score:.3f}",
            f"{beacon:.3f}",
            f"{ja3:.3f}",
            f"{cert:.3f}",
            _format_findings(alert),
            style=row_style,
        )

    if not recent_alerts:
        table.add_row("-", "-", "-", "-", "-", "-", "-", "-", "-", "No alerts yet")

    return table


def make_stats_panel(stats: dict[str, Any]) -> Panel:
    """Create a one-line stats panel for the dashboard header."""
    line = (
        f"Packets: {int(stats.get('packets_captured', 0))}    "
        f"Flows Completed: {int(stats.get('flows_completed', 0))}    "
        f"Flows Scored: {int(stats.get('flows_scored', 0))}    "
        f"Alerts: {int(stats.get('alerts_generated', 0))}    "
        f"Active Flows: {int(stats.get('active_flows', 0))}"
    )
    return Panel(Text(line, style="bold white"), title="Live Stats")


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for live dashboard options."""
    parser = argparse.ArgumentParser(description="Live encrypted traffic dashboard")
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
        help="BPF filter string passed to tshark",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Print available interfaces and exit",
    )
    return parser


def main() -> None:
    """Entrypoint for the live terminal dashboard."""
    console = Console()
    args = build_parser().parse_args()

    if args.list_interfaces:
        interfaces = LiveCapturePipeline.list_interfaces()
        if not interfaces:
            console.print("No interfaces found")
            return
        console.print("Available interfaces:")
        for idx, name in enumerate(interfaces, start=1):
            console.print(f"{idx}. {name}")
        return

    alerts: list[dict[str, Any]] = []
    alerts_lock = threading.Lock()

    def on_alert(flow_dict: dict[str, Any]) -> None:
        """Collect incoming non-benign alerts for dashboard display."""
        with alerts_lock:
            alerts.append(dict(flow_dict))
            if len(alerts) > 200:
                del alerts[:-200]

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
        packet_limit=0,
        on_alert=on_alert,
    )

    worker = threading.Thread(target=pipeline.run, daemon=True)
    worker.start()

    layout = Layout()
    layout.split_column(
        Layout(name="top", size=3),
        Layout(name="bottom"),
    )

    try:
        with Live(layout, refresh_per_second=2, console=console, screen=True):
            while worker.is_alive():
                stats = pipeline.get_stats()
                with alerts_lock:
                    snapshot = list(alerts)

                layout["top"].update(make_stats_panel(stats))
                layout["bottom"].update(make_alert_table(snapshot))
                time.sleep(0.5)

    except KeyboardInterrupt:
        console.print("Stopping capture...")
        pipeline.stop()
        worker.join(timeout=5)

    finally:
        final_stats = pipeline.get_stats()
        console.print("Final stats:")
        console.print(
            f"packets_captured={final_stats.get('packets_captured', 0)} "
            f"flows_completed={final_stats.get('flows_completed', 0)} "
            f"flows_scored={final_stats.get('flows_scored', 0)} "
            f"alerts_generated={final_stats.get('alerts_generated', 0)} "
            f"active_flows={final_stats.get('active_flows', 0)}"
        )


if __name__ == "__main__":
    main()
