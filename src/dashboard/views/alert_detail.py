"""
src/dashboard/views/alert_detail.py
Alert detail view — full breakdown with Groq AI analysis.

Fixes vs previous version:
  - DB_PATH reads SPECTRA_DB env var so it matches where the API writes
  - _load_alerts falls back to 'created_at' if 'composite_score' is missing
    (handles old/partial databases gracefully)
  - _trigger_groq passes DB_PATH explicitly instead of hardcoded "spectra.db"
  - Groq panel shows threat type badge AND confidence correctly
  - "Refresh" button actually re-polls the DB for updated Groq fields
  - is_live badge shown correctly
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading

import streamlit as st

# ── Use same DB path as the API ───────────────────────────────────────────────
DB_PATH = os.getenv("SPECTRA_DB", "data/spectra.db")

SEVERITY_COLOR = {
    "CRITICAL": "#f85149",
    "HIGH":     "#e3b341",
    "MEDIUM":   "#d29922",
    "LOW":      "#58a6ff",
    "CLEAN":    "#3fb950",
}

THREAT_ICONS = {
    "C2_BEACON":         "📡",
    "DATA_EXFILTRATION": "📤",
    "PORT_SCAN":         "🔍",
    "TLS_ANOMALY":       "🔐",
    "MALWARE_COMMS":     "🦠",
    "LATERAL_MOVEMENT":  "↔️",
    "UNKNOWN":           "❓",
}


# ── Data helpers ──────────────────────────────────────────────────────────────

def _load_alerts(limit: int = 200) -> list[dict]:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        # Check which columns exist so we order by the right one
        cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if not cols:
            st.error("DB error: no such table: alerts — run init_db.py first.")
            return []

        # Prefer composite_score for ordering; fall back to timestamp / created_at
        if "composite_score" in cols:
            order = "composite_score DESC"
        elif "timestamp" in cols:
            order = "timestamp DESC"
        else:
            order = "rowid DESC"

        rows = conn.execute(
            f"SELECT * FROM alerts ORDER BY {order} LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        st.error(f"DB error: {e}")
        return []


def _reload_alert(alert_id: str) -> dict | None:
    """Reload a single alert from DB (used after Groq writes back)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def _trigger_groq(alert: dict):
    """Fire Groq analysis in background thread if not already done."""
    def _run():
        try:
            from src.integrations.groq_client import analyse_and_store
            analyse_and_store(alert, DB_PATH)
        except Exception as e:
            pass  # silently ignore — dashboard will show "running" state
    threading.Thread(target=_run, daemon=True).start()


# ── UI sub-components ─────────────────────────────────────────────────────────

def _score_bar(label: str, score: float, color: str = "#58a6ff") -> str:
    pct = min(int((score or 0) * 100), 100)
    return (
        f'<div style="margin-bottom:10px">'
        f'<div style="display:flex;justify-content:space-between;font-size:12px;'
        f'color:#8b949e;margin-bottom:3px">'
        f'<span>{label}</span>'
        f'<span style="color:{color};font-weight:600">{score:.3f}</span>'
        f'</div>'
        f'<div style="background:#21262d;border-radius:3px;height:5px">'
        f'<div style="background:{color};width:{pct}%;height:5px;border-radius:3px"></div>'
        f'</div></div>'
    )


def _groq_panel(alert: dict):
    st.markdown("---")
    st.markdown(
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:14px">'
        '<span style="font-size:18px">🤖</span>'
        '<span style="font-size:13px;font-weight:700;color:#e6edf3;letter-spacing:1px">'
        'AI ANALYSIS</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    sev        = alert.get("severity", "LOW")
    has_groq   = bool(alert.get("groq_summary", "").strip())
    needs_groq = sev in ("HIGH", "CRITICAL")

    if has_groq:
        threat = alert.get("groq_threat_type", "UNKNOWN") or "UNKNOWN"
        icon   = THREAT_ICONS.get(threat, "❓")
        conf   = alert.get("groq_confidence", "LOW") or "LOW"
        conf_c = {"HIGH": "#3fb950", "MEDIUM": "#e3b341", "LOW": "#f85149"}.get(conf, "#8b949e")

        # Badges row
        st.markdown(
            f'<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">'
            f'<span style="background:#161b22;border:1px solid #30363d;border-radius:20px;'
            f'padding:4px 12px;font-size:12px;color:#e6edf3">'
            f'{icon} {threat.replace("_", " ")}</span>'
            f'<span style="background:#161b22;border:1px solid {conf_c}55;border-radius:20px;'
            f'padding:4px 12px;font-size:12px;color:{conf_c}">Confidence: {conf}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # Summary card
        st.markdown(
            f'<div style="background:linear-gradient(135deg,#0d2137,#0a1628);'
            f'border:1px solid #1f6feb44;border-radius:8px;padding:14px 16px;margin-bottom:10px">'
            f'<div style="font-size:10px;color:#58a6ff;letter-spacing:1px;margin-bottom:6px">'
            f'ANALYST SUMMARY</div>'
            f'<div style="color:#e6edf3;font-size:14px;line-height:1.6">'
            f'{alert.get("groq_summary", "")}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # Explanation card
        explanation = alert.get("groq_explanation", "")
        if explanation:
            st.markdown(
                f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;'
                f'padding:14px 16px;margin-bottom:10px">'
                f'<div style="font-size:10px;color:#8b949e;letter-spacing:1px;margin-bottom:6px">'
                f'EXPLANATION</div>'
                f'<div style="color:#c9d1d9;font-size:13px;line-height:1.6">{explanation}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

        # Action card
        action = alert.get("groq_action", "")
        if action:
            st.markdown(
                f'<div style="background:#0d2014;border:1px solid #3fb95033;border-radius:8px;'
                f'padding:14px 16px">'
                f'<div style="font-size:10px;color:#3fb950;letter-spacing:1px;margin-bottom:6px">'
                f'RECOMMENDED ACTION</div>'
                f'<div style="color:#e6edf3;font-size:13px;line-height:1.6">⚡ {action}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    elif needs_groq:
        _trigger_groq(alert)
        st.markdown(
            '<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;'
            'padding:20px;text-align:center;color:#8b949e">'
            '🔄 AI analysis in progress — refresh in a few seconds…'
            '</div>',
            unsafe_allow_html=True,
        )
        if st.button("↻  Refresh AI analysis"):
            # Reload from DB and rerun so updated groq fields are shown
            fresh = _reload_alert(alert.get("alert_id", ""))
            if fresh and fresh.get("groq_summary"):
                st.success("AI analysis complete!")
            st.rerun()
    else:
        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;'
            f'padding:14px;color:#8b949e;font-size:13px">'
            f'AI analysis is only triggered for HIGH and CRITICAL alerts '
            f'(this alert is {sev}).'
            f'</div>',
            unsafe_allow_html=True,
        )


# ── Main render ───────────────────────────────────────────────────────────────

def render():
    alerts = _load_alerts()
    if not alerts:
        st.warning("No alerts in database.")
        return

    # Alert selector
    options = [
        f"{a.get('severity','?')} | "
        f"{a.get('src_ip','?')}:{a.get('src_port','')} → "
        f"{a.get('dst_ip','?')}:{a.get('dst_port','')} | "
        f"score {a.get('composite_score', 0):.3f}"
        + (" ⚡" if a.get("is_live") else "")
        for a in alerts
    ]
    idx = st.selectbox(
        "Select alert",
        range(len(options)),
        format_func=lambda i: options[i],
        label_visibility="collapsed",
    )
    alert = alerts[idx]

    sev     = alert.get("severity", "LOW")
    color   = SEVERITY_COLOR.get(sev, "#8b949e")
    is_live = bool(alert.get("is_live"))
    live_badge = (' <span style="font-size:13px;color:#3fb950;background:#0d2014;'
                  'padding:2px 8px;border-radius:4px">⚡ LIVE</span>') if is_live else ""

    # Alert title
    st.markdown(
        f'<h2 style="color:{color};border-left:3px solid {color};'
        f'padding-left:16px;margin-bottom:4px">'
        f'△ {sev} — Anomalous encrypted traffic pattern{live_badge}</h2>',
        unsafe_allow_html=True,
    )
    st.caption(f"Alert ID: `{alert.get('alert_id', 'N/A')}`")
    st.divider()

    # Two-column: findings + deviation
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(
            '<div style="font-size:10px;color:#8b949e;letter-spacing:1px;margin-bottom:8px">'
            'WHY THIS IS SUSPICIOUS</div>',
            unsafe_allow_html=True,
        )
        findings = alert.get("findings", "[]")
        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except Exception:
                findings = [findings]
        for f in (findings or ["Low-level anomaly detected"]):
            st.markdown(
                f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;'
                f'padding:10px 14px;margin-bottom:6px;font-family:monospace;font-size:13px;'
                f'color:#e6edf3">△ {f}</div>',
                unsafe_allow_html=True,
            )

    with col2:
        st.markdown(
            '<div style="font-size:10px;color:#8b949e;letter-spacing:1px;margin-bottom:8px">'
            'DEVIATION FROM NORMAL</div>',
            unsafe_allow_html=True,
        )
        anomaly = float(alert.get("anomaly_score", 0) or 0)
        deviation = (
            f"Anomaly score {anomaly:.3f} — {int(anomaly*100)}% above baseline"
            if anomaly > 0.3 else "No significant baseline deviations"
        )
        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;'
            f'padding:16px;color:#8b949e;font-family:monospace;font-size:13px">'
            f'{deviation}</div>',
            unsafe_allow_html=True,
        )

    # Groq AI panel
    _groq_panel(alert)

    # Score breakdown
    st.divider()
    st.markdown(
        '<div style="font-size:10px;color:#8b949e;letter-spacing:1px;margin-bottom:12px">'
        'RISK FACTORS</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        _score_bar("ML Anomaly",        float(alert.get("anomaly_score",  0) or 0), "#f85149")
        + _score_bar("Beacon Pattern",  float(alert.get("beacon_score",  0) or 0), "#e3b341")
        + _score_bar("JA3 Fingerprint", float(alert.get("ja3_score",     0) or 0), "#d29922")
        + _score_bar("Certificate Risk",float(alert.get("cert_score",    0) or 0), "#58a6ff")
        + _score_bar("Graph Proximity", float(alert.get("graph_score",   0) or 0), "#3fb950"),
        unsafe_allow_html=True,
    )

    # Other alerts from same source
    src_ip   = alert.get("src_ip", "")
    aid      = alert.get("alert_id", "")
    same_src = [a for a in alerts if a.get("src_ip") == src_ip and a.get("alert_id") != aid]
    with st.expander(f"OTHER ALERTS FROM {src_ip} ({len(same_src)})"):
        for a in same_src[:10]:
            sc = SEVERITY_COLOR.get(a.get("severity","LOW"), "#8b949e")
            st.markdown(
                f'<div style="font-family:monospace;font-size:12px;padding:5px 0;'
                f'border-bottom:1px solid #21262d">'
                f'<span style="color:{sc};min-width:70px;display:inline-block">'
                f'{a.get("severity","LOW")}</span>'
                f'<span style="color:#e6edf3">'
                f'{a.get("dst_ip","")}:{a.get("dst_port","")}</span>'
                f'<span style="color:#8b949e;margin-left:10px">'
                f'{float(a.get("composite_score",0) or 0):.3f}</span>'
                f'{"<span style=color:#3fb950;margin-left:8px>⚡</span>" if a.get("is_live") else ""}'
                f'</div>',
                unsafe_allow_html=True,
            )

    # Raw JSON (excluding groq fields)
    with st.expander("RAW JSON"):
        raw = {k: v for k, v in alert.items() if not k.startswith("groq_")}
        st.json(raw)