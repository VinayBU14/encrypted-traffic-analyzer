"""Live capture dashboard view for real-time packet interception demonstration."""

from __future__ import annotations

import datetime
import queue
import threading
import time
from typing import Any

import pandas as pd
import streamlit as st

from src.ingestion.live_capture import LiveCaptureReader

_packet_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=200)
_stop_event: threading.Event = threading.Event()


def _init_state() -> None:
    if "live_capture_running" not in st.session_state:
        st.session_state["live_capture_running"] = False
    if "live_packets" not in st.session_state:
        st.session_state["live_packets"] = []
    if "live_stats" not in st.session_state:
        st.session_state["live_stats"] = {
            "total_captured": 0,
            "tls_count": 0,
            "bytes_seen": 0,
            "flow_count": 0,
        }
    if "live_flow_keys" not in st.session_state:
        st.session_state["live_flow_keys"] = set()
    if "live_capture_error" not in st.session_state:
        st.session_state["live_capture_error"] = None


def _capture_worker(interface: str, bpf_filter: str) -> None:
    """Run in a background daemon thread. Captures packets and puts them into the queue."""
    try:
        reader = LiveCaptureReader(interface=interface, bpf_filter=bpf_filter)
        for raw_pkt in reader.start_capture():
            if _stop_event.is_set():
                reader.stop()
                break
            try:
                _packet_queue.put_nowait(raw_pkt)
            except queue.Full:
                continue
    except Exception as exc:
        try:
            _packet_queue.put_nowait({"error": str(exc)})
        except queue.Full:
            pass


def render() -> None:
    """Render the Live Capture page with controls, stats, and live packet feed."""
    _init_state()

    st.markdown(
        """
    <div class="page-header">
        <div class="page-header-icon" style="background:#0d1a1a;">◎</div>
        <div>
            <div class="page-header-title">Live Capture</div>
            <div class="page-header-sub">Real-time packet interception</div>
        </div>
    </div>""",
        unsafe_allow_html=True,
    )

    interfaces = LiveCaptureReader.get_available_interfaces() or ["Wi-Fi", "Ethernet", "lo"]

    left, right = st.columns([2, 2])
    with left:
        selected_interface = st.selectbox("Network Interface", options=interfaces, key="live_capture_interface")
    with right:
        button_col_1, button_col_2 = st.columns(2)
        with button_col_1:
            start_clicked = st.button("▶ Start Capture", use_container_width=True, key="live_capture_start")
        with button_col_2:
            stop_clicked = st.button("■ Stop Capture", use_container_width=True, key="live_capture_stop")

    bpf_filter = st.text_input(
        "Capture Filter (BPF)",
        value="",
        placeholder="Leave empty to capture all traffic",
        key="live_capture_bpf",
    )

    if start_clicked:
        st.session_state["live_capture_running"] = True
        st.session_state["live_interface"] = selected_interface
        st.session_state["live_capture_error"] = None
        st.session_state["live_packets"] = []
        st.session_state["live_stats"] = {
            "total_captured": 0,
            "tls_count": 0,
            "bytes_seen": 0,
            "flow_count": 0,
        }
        while not _packet_queue.empty():
            try:
                _packet_queue.get_nowait()
            except queue.Empty:
                break
        _stop_event.clear()
        threading.Thread(
            target=_capture_worker,
            args=(selected_interface, bpf_filter),
            daemon=True,
        ).start()
        st.rerun()

    if stop_clicked:
        _stop_event.set()
        st.session_state["live_capture_running"] = False
        st.rerun()

    stats = st.session_state["live_stats"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets Captured", int(stats.get("total_captured", 0)))
    c2.metric("TLS Packets", int(stats.get("tls_count", 0)))
    c3.metric("Bytes Seen", int(stats.get("bytes_seen", 0)))
    c4.metric("Active Flows", int(stats.get("flow_count", 0)))

    drained = 0
    while drained < 10 and not _packet_queue.empty():
        try:
            raw_pkt = _packet_queue.get_nowait()
        except queue.Empty:
            break
        drained += 1

        if isinstance(raw_pkt, dict) and "error" in raw_pkt:
            _stop_event.set()
            st.session_state["live_capture_running"] = False
            st.session_state["live_capture_error"] = str(raw_pkt["error"])
            break

        pkt = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "src_ip": raw_pkt.get("src_ip", "—"),
            "dst_ip": raw_pkt.get("dst_ip", "—"),
            "src_port": raw_pkt.get("src_port", 0),
            "dst_port": raw_pkt.get("dst_port", 0),
            "size": raw_pkt.get("packet_size", 0),
            "tls": raw_pkt.get("has_tls_layer", False),
            "protocol": raw_pkt.get("protocol", "—"),
        }
        st.session_state["live_packets"].append(pkt)
        if len(st.session_state["live_packets"]) > 50:
            st.session_state["live_packets"].pop(0)

        st.session_state["live_stats"]["total_captured"] += 1
        if pkt["tls"]:
            st.session_state["live_stats"]["tls_count"] += 1
        st.session_state["live_stats"]["bytes_seen"] += pkt["size"]

        flow_key = (
            str(pkt.get("src_ip", "—")),
            int(pkt.get("src_port", 0)),
            str(pkt.get("dst_ip", "—")),
            int(pkt.get("dst_port", 0)),
            str(pkt.get("protocol", "—")),
        )
        flow_keys: set[tuple[str, int, str, int, str]] = st.session_state["live_flow_keys"]
        flow_keys.add(flow_key)
        st.session_state["live_stats"]["flow_count"] = len(flow_keys)

    packets: list[dict[str, Any]] = st.session_state.get("live_packets", [])
    rows: list[dict[str, str | int]] = []
    for packet in packets[-50:]:
        tls_on = bool(packet.get("tls"))
        rows.append(
            {
                "Time": str(packet.get("time", "—")),
                "Src IP:Port": f"{packet.get('src_ip', '—')}:{packet.get('src_port', 0)}",
                "→": "→",
                "Dst IP:Port": f"{packet.get('dst_ip', '—')}:{packet.get('dst_port', 0)}",
                "Size": int(packet.get("size", 0)),
                "TLS": "TLS ✓" if tls_on else "—",
                "Flags": "—",
            }
        )

    df = pd.DataFrame(rows)
    if not df.empty:
        st.dataframe(
            df.style.apply(
                lambda row: [
                    "background-color: rgba(34,197,94,0.08)" if row["TLS"] == "TLS ✓" else ""
                    for _ in row
                ],
                axis=1,
            ),
            use_container_width=True,
            hide_index=True,
        )
    else:
        if st.session_state.get("live_capture_error"):
            st.error(f"Capture error: {st.session_state['live_capture_error']}")
            if st.button("Clear Error", key="live_capture_clear_error"):
                st.session_state["live_capture_error"] = None
                st.rerun()
        st.info("No live packets captured yet.")

    if st.session_state.get("live_capture_running", False):
        time.sleep(0.3)
        st.rerun()
