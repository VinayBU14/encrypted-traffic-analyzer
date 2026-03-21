
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import streamlit as st

from src.dashboard import api_client, state

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]
_SEVERITY_COLOR = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316",
    "MEDIUM": "#eab308", "LOW": "#3b82f6", "CLEAN": "#22c55e",
}
_SEVERITY_BG = {
    "CRITICAL": "#2d0a0a", "HIGH": "#2d1200",
    "MEDIUM": "#2d2000", "LOW": "#071e38", "CLEAN": "#052010",
}
_SEVERITY_BORDER = {
    "CRITICAL": "#7f1d1d", "HIGH": "#7c2d12",
    "MEDIUM": "#78350f", "LOW": "#1e3a5f", "CLEAN": "#14532d",
}
_REFRESH_OPTIONS = {"Off": 0, "5 s": 5, "15 s": 15, "30 s": 30, "60 s": 60}


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def _render_stats_bar(stats: dict[str, int]) -> None:
    total = sum(stats.values())
    cols = st.columns(6)
    for col, sev in zip(cols, _SEVERITY_ORDER):
        count = stats.get(sev, 0)
        c = _SEVERITY_COLOR[sev]
        bg = _SEVERITY_BG[sev]
        bd = _SEVERITY_BORDER[sev]
        with col:
            st.markdown(f"""
            <div style="background:{bg};border:1px solid {bd};border-radius:10px;
                        padding:14px 16px;position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;width:3px;height:100%;background:{c}"></div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;
                            font-weight:600;color:{c};line-height:1">{count}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                            color:#475569;text-transform:uppercase;letter-spacing:0.1em;
                            margin-top:4px">{sev}</div>
            </div>""", unsafe_allow_html=True)
    with cols[5]:
        st.markdown(f"""
        <div style="background:#080c14;border:1px solid #1e2a3a;border-radius:10px;
                    padding:14px 16px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;
                        font-weight:600;color:#334155;line-height:1">{total}</div>
            <div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                        color:#334155;text-transform:uppercase;letter-spacing:0.1em;
                        margin-top:4px">Total</div>
        </div>""", unsafe_allow_html=True)


def _build_dataframe(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for a in alerts:
        rows.append({
            "alert_id":        a.get("alert_id", ""),
            "timestamp":       _fmt_ts(a.get("timestamp", 0)),
            "severity":        a.get("severity", ""),
            "composite_score": round(float(a.get("composite_score", 0)), 4),
            "src_ip":          a.get("src_ip", ""),
            "dst_ip":          a.get("dst_ip", "") or "",
            "dst_domain":      a.get("dst_domain", "") or "",
            "is_suppressed":   bool(a.get("is_suppressed", False)),
        })
    return pd.DataFrame(rows)


def render() -> None:
    
    st.markdown("""
    <div class="page-header">
        <div class="page-header-icon" style="background:#0d1f35;">🛡️</div>
        <div>
            <div class="page-header-title">Live Monitor</div>
            <div class="page-header-sub">Real-time threat detection feed</div>
        </div>
    </div>""", unsafe_allow_html=True)

    
    c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
    with c1:
        severity_filter = st.selectbox("Filter severity", ["ALL"] + _SEVERITY_ORDER,
                                       key="lm_sev")
    with c2:
        limit = st.slider("Max alerts", 25, 500, 100, 25, key="lm_limit")
    with c3:
        refresh_label = st.selectbox("Auto-refresh", list(_REFRESH_OPTIONS.keys()),
                                     index=2, key="lm_refresh")
    with c4:
        st.markdown("<br>", unsafe_allow_html=True)
        show_suppressed = st.checkbox("Suppressed", value=False, key="lm_supp")
    refresh_interval = _REFRESH_OPTIONS[refresh_label]

    
    try:
        stats  = api_client.get_alert_stats()
        alerts = api_client.get_alerts(
            limit=limit,
            severity=severity_filter if severity_filter != "ALL" else None
        )
    except ConnectionError as exc:
        st.error(f"**API Unavailable** — {exc}")
        return
    except Exception as exc:
        st.error(f"Fetch failed: {exc}")
        return

    
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    _render_stats_bar(stats)
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    if not alerts:
        st.markdown("""
        <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;
                    padding:32px;text-align:center;">
            <div style="font-size:2rem;margin-bottom:8px">✓</div>
            <div style="font-family:'Syne',sans-serif;color:#334155;font-weight:600">
                No alerts for selected filter</div>
        </div>""", unsafe_allow_html=True)
        return

    df = _build_dataframe(alerts)
    if not show_suppressed:
        df = df[~df["is_suppressed"]]

    if df.empty:
        st.info("All alerts are suppressed. Enable 'Suppressed' to view them.")
        return

    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;align-items:center;
                margin-bottom:10px;">
        <div style="font-family:'Syne',sans-serif;font-size:0.72rem;font-weight:700;
                    color:#334155;text-transform:uppercase;letter-spacing:0.1em">
            {len(df)} alert(s)
        </div>
    </div>""", unsafe_allow_html=True)

    alert_by_id = {a.get("alert_id", ""): a for a in alerts}

    hcols = st.columns([1.1, 1.5, 1.2, 1.6, 2.5, 1.4, 1.0])
    for col, h in zip(
        hcols,
        ["Severity", "Score", "Source IP", "Destination", "Top Signal", "Time", "Actions"],
    ):
        col.markdown(
            f"""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;
            font-weight:700;color:#334155;text-transform:uppercase;
            letter-spacing:0.08em;padding:6px 0 8px">{h}</div>""",
            unsafe_allow_html=True,
        )

    for _, row in df.iterrows():
        sev = row["severity"]
        color = _SEVERITY_COLOR.get(sev, "#64748b")
        score = float(row["composite_score"])
        pct = int(score * 100)
        aid = row["alert_id"]
        raw = alert_by_id.get(aid, {})
        findings = raw.get("findings") or []
        if findings:
            top_signal = str(findings[0])
            if len(top_signal) > 40:
                top_signal = f"{top_signal[:40]}…"
        else:
            top_signal = f"JA3:{float(raw.get('ja3_score', 0.0)):.2f} BCN:{float(raw.get('beacon_score', 0.0)):.2f}"
        destination = row["dst_domain"] or row["dst_ip"] or "—"

        c1, c2, c3, c4, c5, c6, c7 = st.columns([1.1, 1.5, 1.2, 1.6, 2.5, 1.4, 1.0])
        c1.markdown(
            f'<div style="padding:6px 0"><span class="badge badge-{sev.lower()}">{sev}</span></div>',
            unsafe_allow_html=True,
        )
        c2.markdown(
            f"""
        <div style="padding:4px 0">
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;
                        color:{color};font-weight:600">{score:.3f}</div>
            <div class="score-track">
                <div class="score-fill" style="width:{pct}%;background:{color}"></div>
            </div>
        </div>""",
            unsafe_allow_html=True,
        )
        c3.markdown(f'<div class="mono" style="padding:6px 0">{row["src_ip"]}</div>', unsafe_allow_html=True)
        c4.markdown(
            f'<div class="mono" style="padding:6px 0;color:#94a3b8" title="{destination}">{destination}</div>',
            unsafe_allow_html=True,
        )
        c5.markdown(
            f'<div class="mono" style="padding:6px 0;color:#64748b" title="{top_signal}">{top_signal}</div>',
            unsafe_allow_html=True,
        )
        c6.markdown(f'<div class="mono" style="padding:6px 0">{row["timestamp"]}</div>', unsafe_allow_html=True)

        a1, a2 = c7.columns(2)
        if a1.button("→", key=f"lm_open_{aid}", use_container_width=True):
            state.set_selected_alert(aid)
            st.rerun()
        if a2.button("✕", key=f"lm_sup_{aid}", use_container_width=True):
            try:
                api_client.suppress_alert(aid)
                st.rerun()
            except Exception as exc:
                st.error(f"Suppress failed: {exc}")

        st.markdown('<div style="border-bottom:1px solid #0f1923;margin:0 0 2px"></div>', unsafe_allow_html=True)

    # ── Auto-refresh ──
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    if refresh_interval > 0:
        ph = st.empty()
        for remaining in range(refresh_interval, 0, -1):
            ph.markdown(f'<div class="mono" style="color:#1e2a3a;font-size:0.75rem">'
                        f'↻ refreshing in {remaining}s</div>', unsafe_allow_html=True)
            time.sleep(1)
        ph.empty()
        st.rerun()
    else:
        if st.button("↻  Refresh now", key="lm_manual"):
            st.rerun()
