"""PCAP upload and on-demand analysis dashboard view."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _run_pipeline_thread(pcap_path: str, retrain: bool, result_holder: dict) -> None:
    """Run the pipeline in a background thread and store the result."""
    try:
        from src.pipeline.runner import run_pipeline
        summary = run_pipeline(pcap_path, retrain=retrain, clear=False)
        result_holder["summary"] = summary
        result_holder["done"] = True
        result_holder["error"] = None
    except Exception as exc:
        result_holder["done"] = True
        result_holder["error"] = str(exc)
        result_holder["summary"] = None


def _init_state() -> None:
    defaults = {
        "upload_running": False,
        "upload_done": False,
        "upload_error": None,
        "upload_summary": None,
        "upload_result_holder": {},
        "upload_thread": None,
        "upload_start_time": None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def render() -> None:
    """Render the PCAP upload and analysis view."""
    _init_state()

    st.markdown(
        """
    <div style="background:#080c14;border:1px solid #1e2a3a;border-radius:16px;
                padding:28px 36px;margin-bottom:24px;">
        <div style="font-family:'Syne',sans-serif;font-size:1.4rem;font-weight:800;
                    color:#e2e8f0;margin-bottom:6px;">⬆ PCAP Analysis</div>
        <div style="font-family:'Syne',sans-serif;font-size:0.85rem;color:#475569;">
            Upload a .pcap or .pcapng file to run the full Spectra pipeline and generate alerts.
        </div>
    </div>""",
        unsafe_allow_html=True,
    )

    # ── Upload widget ──────────────────────────────────────────────────────────
    uploaded_file = st.file_uploader(
        "Choose a PCAP file",
        type=["pcap", "pcapng"],
        help="Captured with Wireshark, tcpdump, or any libpcap-compatible tool",
    )

    col_retrain, col_btn = st.columns([2, 1])
    with col_retrain:
        retrain = st.checkbox(
            "Retrain anomaly model on this capture",
            value=False,
            help="Check this when uploading a known-clean baseline capture to improve detection accuracy",
        )

    # ── Check if background thread finished ───────────────────────────────────
    holder = st.session_state["upload_result_holder"]
    if st.session_state["upload_running"] and holder.get("done"):
        st.session_state["upload_running"] = False
        st.session_state["upload_done"] = True
        st.session_state["upload_summary"] = holder.get("summary")
        st.session_state["upload_error"] = holder.get("error")

    # ── Run button ─────────────────────────────────────────────────────────────
    with col_btn:
        btn_disabled = uploaded_file is None or st.session_state["upload_running"]
        if st.button(
            "▶ Analyze" if not st.session_state["upload_running"] else "⏳ Running...",
            disabled=btn_disabled,
            use_container_width=True,
        ):
            if uploaded_file is not None and not st.session_state["upload_running"]:
                # Save to temp file
                suffix = ".pcapng" if uploaded_file.name.endswith(".pcapng") else ".pcap"
                tmp = tempfile.NamedTemporaryFile(
                    delete=False, suffix=suffix, dir=str(PROJECT_ROOT / "data" / "demo")
                )
                tmp.write(uploaded_file.read())
                tmp.close()

                # Reset state
                result_holder: dict[str, Any] = {"done": False}
                st.session_state["upload_result_holder"] = result_holder
                st.session_state["upload_running"] = True
                st.session_state["upload_done"] = False
                st.session_state["upload_summary"] = None
                st.session_state["upload_error"] = None
                st.session_state["upload_start_time"] = time.time()

                thread = threading.Thread(
                    target=_run_pipeline_thread,
                    args=(tmp.name, retrain, result_holder),
                    daemon=True,
                )
                thread.start()
                st.session_state["upload_thread"] = thread
                st.rerun()

    # ── Progress indicator ─────────────────────────────────────────────────────
    if st.session_state["upload_running"]:
        elapsed = int(time.time() - (st.session_state["upload_start_time"] or time.time()))
        st.markdown(
            f"""
        <div style="background:#0d1117;border:1px solid #1e3a5f;border-radius:12px;
                    padding:20px;margin-top:16px;text-align:center;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;
                        color:#38bdf8;margin-bottom:8px;">⏳ Pipeline running... {elapsed}s</div>
            <div style="font-family:'Syne',sans-serif;font-size:0.8rem;color:#475569;">
                Reconstructing flows · Extracting TLS metadata · Scoring threats
            </div>
        </div>""",
            unsafe_allow_html=True,
        )
        time.sleep(2)
        st.rerun()

    # ── Results ────────────────────────────────────────────────────────────────
    if st.session_state["upload_done"]:
        if st.session_state["upload_error"]:
            st.markdown(
                f"""
            <div style="background:#1a0505;border:1px solid #7f1d1d;border-radius:12px;
                        padding:20px;margin-top:16px;">
                <div style="font-family:'Syne',sans-serif;font-size:1rem;font-weight:700;
                            color:#ef4444;margin-bottom:8px;">❌ Pipeline Error</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;
                            color:#fca5a5;">{st.session_state['upload_error']}</div>
            </div>""",
                unsafe_allow_html=True,
            )
        else:
            s = st.session_state["upload_summary"] or {}
            _render_summary(s)

        if st.button("Clear results"):
            st.session_state["upload_done"] = False
            st.session_state["upload_summary"] = None
            st.session_state["upload_error"] = None
            st.rerun()

    # ── Instructions ──────────────────────────────────────────────────────────
    if not st.session_state["upload_running"] and not st.session_state["upload_done"]:
        st.markdown(
            """
        <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:12px;
                    padding:20px;margin-top:24px;">
            <div style="font-family:'Syne',sans-serif;font-size:0.75rem;font-weight:700;
                        color:#334155;text-transform:uppercase;letter-spacing:0.1em;
                        margin-bottom:12px;">How to capture traffic</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#475569;
                        line-height:1.8;">
                <b style="color:#64748b;">Wireshark:</b><br>
                &nbsp;&nbsp;Capture filter: <span style="color:#38bdf8;">tcp port 443</span><br>
                &nbsp;&nbsp;Save as: <span style="color:#38bdf8;">File → Export Specified Packets → .pcap</span><br><br>
                <b style="color:#64748b;">tcpdump:</b><br>
                &nbsp;&nbsp;<span style="color:#38bdf8;">tcpdump -i any -w capture.pcap tcp port 443</span><br><br>
                <b style="color:#64748b;">Tips:</b><br>
                &nbsp;&nbsp;• Capture for at least 5 minutes to build behavioral baselines<br>
                &nbsp;&nbsp;• Include TLS traffic on 443, 8443, 993, 465<br>
                &nbsp;&nbsp;• Export as .pcap not .pcapng for best compatibility
            </div>
        </div>""",
            unsafe_allow_html=True,
        )


def _render_summary(s: dict) -> None:
    """Render a nicely formatted pipeline summary."""
    packets = s.get("packets_processed", 0)
    flows = s.get("flows_completed", 0)
    sessions = s.get("tls_sessions_saved", 0)
    alerts = s.get("alerts_created", 0)
    elapsed = s.get("elapsed_seconds", 0)
    whitelisted = s.get("alerts_whitelisted", 0)

    status_color = "#22c55e" if alerts >= 0 else "#ef4444"

    st.markdown(
        f"""
    <div style="background:#021208;border:1px solid #14532d;border-radius:12px;
                padding:20px;margin-top:16px;">
        <div style="font-family:'Syne',sans-serif;font-size:1rem;font-weight:700;
                    color:#22c55e;margin-bottom:16px;">✓ Analysis Complete ({elapsed:.1f}s)</div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;">
            <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;
                            font-weight:700;color:#38bdf8;">{packets:,}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.65rem;font-weight:700;
                            color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-top:4px;">Packets</div>
            </div>
            <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;
                            font-weight:700;color:#a78bfa;">{flows:,}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.65rem;font-weight:700;
                            color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-top:4px;">Flows</div>
            </div>
            <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;
                            font-weight:700;color:#fbbf24;">{sessions:,}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.65rem;font-weight:700;
                            color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-top:4px;">TLS Sessions</div>
            </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:12px;">
            <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;
                            font-weight:700;color:{status_color};">{alerts}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.65rem;font-weight:700;
                            color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-top:4px;">Alerts Generated</div>
            </div>
            <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;
                            font-weight:700;color:#475569;">{whitelisted}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.65rem;font-weight:700;
                            color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-top:4px;">Whitelisted (skipped)</div>
            </div>
        </div>
        <div style="margin-top:12px;font-family:'Syne',sans-serif;font-size:0.8rem;color:#475569;">
            Navigate to <b style="color:#e2e8f0;">Overview</b> or <b style="color:#e2e8f0;">Session Timeline</b>
            to review the new alerts.
        </div>
    </div>""",
        unsafe_allow_html=True,
    )