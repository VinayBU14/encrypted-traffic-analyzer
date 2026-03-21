

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import streamlit as st

from src.dashboard import api_client, state

_SEVERITY_COLOR  = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#3b82f6","CLEAN":"#22c55e"}
_SEVERITY_BG     = {"CRITICAL":"#2d0a0a","HIGH":"#2d1200","MEDIUM":"#2d2000","LOW":"#071e38","CLEAN":"#052010"}
_SEVERITY_BORDER = {"CRITICAL":"#7f1d1d","HIGH":"#7c2d12","MEDIUM":"#78350f","LOW":"#1e3a5f","CLEAN":"#14532d"}


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _score_color(v: float) -> str:
    if v >= 0.75: return "#ef4444"
    if v >= 0.50: return "#f97316"
    if v >= 0.30: return "#eab308"
    return "#22c55e"


def _render_score_card(label: str, value: float | None, hint: str = "") -> None:
    v = max(0.0, min(1.0, float(value or 0)))
    c = _score_color(v)
    pct = int(v * 100)
    st.markdown(f"""
    <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;
                padding:14px 16px;height:100%">
        <div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                    color:#334155;text-transform:uppercase;letter-spacing:0.08em;
                    margin-bottom:8px" title="{hint}">{label}</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:1.4rem;
                    font-weight:600;color:{c};line-height:1">{v:.4f}</div>
        <div style="background:#131c2b;border-radius:3px;height:4px;margin-top:8px">
            <div style="width:{pct}%;background:{c};height:4px;border-radius:3px"></div>
        </div>
    </div>""", unsafe_allow_html=True)


def _render_meta_chip(label: str, value: str) -> str:
    return f"""
    <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;
                padding:10px 14px;flex:1;min-width:0">
        <div style="font-family:'Syne',sans-serif;font-size:0.65rem;font-weight:700;
                    color:#334155;text-transform:uppercase;letter-spacing:0.1em;
                    margin-bottom:4px">{label}</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;
                    color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"
             title="{value}">{value}</div>
    </div>"""


def render() -> None:
    alert_id = state.get_selected_alert()

   
    bcol, tcol = st.columns([1, 9])
    if bcol.button("← Back", key="ad_back"):
        state.clear_selected_alert()
        st.rerun()
    tcol.markdown("""
    <div class="page-header" style="padding-bottom:0;border-bottom:none;">
        <div class="page-header-icon" style="background:#1a0d2b;">◈</div>
        <div>
            <div class="page-header-title">Alert Detail</div>
            <div class="page-header-sub">Full threat signal breakdown</div>
        </div>
    </div>""", unsafe_allow_html=True)

    st.markdown('<div style="border-bottom:1px solid #1e2a3a;margin:12px 0 20px"></div>',
                unsafe_allow_html=True)

    if not alert_id:
        st.markdown("""
        <div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:12px;
                    padding:40px;text-align:center;">
            <div style="font-size:2.5rem;margin-bottom:12px">◈</div>
            <div style="font-family:'Syne',sans-serif;color:#334155;font-weight:700;
                        font-size:1rem;margin-bottom:8px">No alert selected</div>
            <div style="font-family:'Syne',sans-serif;color:#1e2a3a;font-size:0.82rem">
                Go to Live Monitor and click → on any alert row</div>
        </div>""", unsafe_allow_html=True)
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        manual_id = st.text_input("Or enter Alert ID manually", key="ad_manual")
        if st.button("Load alert", key="ad_load") and manual_id.strip():
            state.set_selected_alert(manual_id.strip())
            st.rerun()
        return

    try:
        alert = api_client.get_alert(alert_id)
    except ConnectionError as exc:
        st.error(f"API Unavailable — {exc}")
        return
    except Exception as exc:
        st.error(f"Could not load alert: {exc}")
        state.clear_selected_alert()
        return

    sev      = alert.get("severity", "UNKNOWN")
    color    = _SEVERITY_COLOR.get(sev, "#64748b")
    bg       = _SEVERITY_BG.get(sev, "#0d1117")
    border   = _SEVERITY_BORDER.get(sev, "#1e2a3a")
    composite = float(alert.get("composite_score", 0))
    pct      = int(composite * 100)

    
    st.markdown(f"""
    <div style="background:{bg};border:1px solid {border};border-left:4px solid {color};
                border-radius:12px;padding:22px 28px;display:flex;
                align-items:center;gap:32px;margin-bottom:20px;">
        <div style="flex-shrink:0">
            <div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                        color:#475569;text-transform:uppercase;letter-spacing:0.1em;
                        margin-bottom:6px">Composite Risk Score</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:3.2rem;
                        font-weight:600;color:{color};line-height:1">{composite:.4f}</div>
            <div style="margin-top:10px">
                <span class="badge badge-{sev.lower()}">{sev}</span>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                             color:#334155;margin-left:10px">{alert_id[:20]}…</span>
            </div>
        </div>
        <div style="flex:1">
            <div style="background:#0d1117;border-radius:4px;height:8px;margin-bottom:6px">
                <div style="width:{pct}%;background:{color};height:8px;border-radius:4px;
                             transition:width .4s ease"></div>
            </div>
            <div style="font-family:'Syne',sans-serif;font-size:0.72rem;
                        color:#1e2a3a;text-align:right">{pct}% risk</div>
        </div>
    </div>""", unsafe_allow_html=True)

    
    sub_keys = [
        ("ja3_score",    "JA3",     "TLS fingerprint threat score"),
        ("beacon_score", "Beacon",  "Periodic C2 callout"),
        ("cert_score",   "Cert",    "Certificate anomalies"),
        ("graph_score",  "Graph",   "Graph proximity"),
        ("anomaly_score","Anomaly", "ML isolation forest"),
    ]
    cols = st.columns(5)
    for col, (key, label, hint) in zip(cols, sub_keys):
        with col:
            _render_score_card(label, alert.get(key), hint)

    st.markdown('<div style="height:20px"></div>', unsafe_allow_html=True)

    
    chips = _render_meta_chip("Source IP", alert.get("src_ip") or "—")
    chips += _render_meta_chip("Destination IP", alert.get("dst_ip") or "—")
    chips += _render_meta_chip("Domain", alert.get("dst_domain") or "—")
    chips += _render_meta_chip("Timestamp", _fmt_ts(alert.get("timestamp", 0)))
    if alert.get("flow_id"):
        chips += _render_meta_chip("Flow ID", alert["flow_id"][:24] + "…")
    st.markdown(f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px">{chips}</div>',
                unsafe_allow_html=True)

    
    left, right = st.columns([1, 1])
    with left:
        findings: list[str] = alert.get("findings") or []
        st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;
                       font-weight:700;color:#334155;text-transform:uppercase;
                       letter-spacing:0.1em;margin-bottom:10px">Findings</div>""",
                    unsafe_allow_html=True)
        if findings:
            items_html = "".join(
                f'<div style="display:flex;align-items:flex-start;gap:10px;'
                f'padding:8px 0;border-bottom:1px solid #0f1923">'
                f'<div style="color:#334155;margin-top:1px;flex-shrink:0">▸</div>'
                f'<div style="font-family:\'Syne\',sans-serif;font-size:0.82rem;'
                f'color:#64748b;line-height:1.5">{f}</div></div>'
                for f in findings
            )
            st.markdown(f'<div style="background:#0d1117;border:1px solid #1e2a3a;'
                        f'border-radius:10px;padding:6px 14px">{items_html}</div>',
                        unsafe_allow_html=True)
        else:
            st.markdown('<div style="font-family:\'Syne\',sans-serif;color:#1e2a3a;'
                        'font-size:0.82rem">No findings recorded.</div>',
                        unsafe_allow_html=True)

    with right:
        action = alert.get("recommended_action") or "Review manually."
        st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;
                       font-weight:700;color:#334155;text-transform:uppercase;
                       letter-spacing:0.1em;margin-bottom:10px">Recommended action</div>""",
                    unsafe_allow_html=True)
        st.markdown(f"""
        <div style="background:#071e38;border:1px solid #1e3a5f;border-radius:10px;
                    padding:16px 18px;">
            <div style="font-size:1.2rem;margin-bottom:6px">💡</div>
            <div style="font-family:'Syne',sans-serif;font-size:0.88rem;
                        color:#60a5fa;line-height:1.6">{action}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown('<div style="height:20px"></div>', unsafe_allow_html=True)

   
    is_suppressed = bool(alert.get("is_suppressed", False))
    if is_suppressed:
        st.markdown("""
        <div style="background:#2d2000;border:1px solid #78350f;border-radius:10px;
                    padding:14px 18px;font-family:'Syne',sans-serif;font-size:0.85rem;
                    color:#fbbf24;">⚠ This alert is currently suppressed.</div>""",
                    unsafe_allow_html=True)
    else:
        sb, nb = st.columns([1, 4])
        if sb.button("🔕  Suppress alert", key=f"supp_{alert_id}", type="secondary"):
            try:
                api_client.suppress_alert(alert_id)
                st.success("Alert suppressed successfully.")
                st.rerun()
            except Exception as exc:
                st.error(f"Suppress failed: {exc}")
        nb.markdown('<div style="font-family:\'Syne\',sans-serif;font-size:0.78rem;'
                    'color:#334155;padding-top:10px">Removes from active feed. '
                    'Flow data is preserved.</div>', unsafe_allow_html=True)

    st.markdown('<div style="height:22px"></div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Syne',sans-serif;font-size:0.72rem;font-weight:700;
                color:#334155;text-transform:uppercase;letter-spacing:0.12em;
                margin-bottom:12px">Threat Explanation</div>
    """, unsafe_allow_html=True)

    explanation: dict[str, Any] | None = None
    explanation_unavailable = False
    try:
        explanation = api_client._get(f"/alerts/{alert_id}/explain")
    except ConnectionError:
        explanation_unavailable = True
    except Exception:
        explanation = {}

    if explanation_unavailable:
        st.markdown(
            '<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;'
            'padding:12px 14px;font-family:\'Syne\',sans-serif;color:#64748b">'
            'Explanation unavailable</div>',
            unsafe_allow_html=True,
        )
    else:
        explanation = explanation or {}
        ex_sev = str(explanation.get("severity", sev)).upper()
        ex_headline = str(explanation.get("headline", f"{ex_sev} — Anomalous encrypted traffic pattern"))
        ex_color = _SEVERITY_COLOR.get(ex_sev, "#eab308")
        findings = explanation.get("technical_findings") or []
        deviations = explanation.get("deviations") or []
        plain_english = str(explanation.get("plain_english", "")).strip() or "AI analysis not available"
        risk_factors = explanation.get("risk_factors") or []

        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #1e2a3a;border-left:4px solid {ex_color};'
            f'border-radius:10px;padding:14px 16px;margin-bottom:14px;">'
            f'<div style="font-family:\'Syne\',sans-serif;font-size:1.1rem;font-weight:800;color:{ex_color};">'
            f'⚠ {ex_headline}</div></div>',
            unsafe_allow_html=True,
        )

        lcol, rcol = st.columns([1, 1])
        with lcol:
            st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                           color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px">
                           Why this is suspicious</div>""", unsafe_allow_html=True)
            if findings:
                findings_html = "".join(
                    f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.74rem;'
                    f'color:#94a3b8;line-height:1.55;padding:5px 0">⚠ {item}</div>'
                    for item in findings
                )
            else:
                findings_html = (
                    "<div style=\"font-family:'JetBrains Mono',monospace;font-size:0.74rem;"
                    "color:#64748b\">⚠ No technical findings available</div>"
                )
            st.markdown(
                f'<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;'
                f'padding:10px 12px;min-height:145px">{findings_html}</div>',
                unsafe_allow_html=True,
            )

        with rcol:
            st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                           color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px">
                           Deviation from normal</div>""", unsafe_allow_html=True)
            if deviations:
                dev_rows = ""
                for d in deviations:
                    label = str(d.get("label", d.get("feature", "Feature")))
                    observed = float(d.get("observed", 0.0))
                    mean = float(d.get("baseline_mean", 0.0))
                    std = float(d.get("baseline_std", 0.0))
                    anomalous = bool(d.get("is_anomalous", False))
                    observed_color = "#ef4444" if anomalous else "#94a3b8"
                    dev_rows += (
                        "<div style=\"display:grid;grid-template-columns:1.2fr 0.8fr 0.6fr 1.3fr;"
                        "gap:8px;padding:6px 0;border-bottom:1px solid #0f1923\">"
                        f"<div style=\"font-family:'Syne',sans-serif;font-size:0.74rem;color:#64748b\">{label}</div>"
                        f"<div style=\"font-family:'JetBrains Mono',monospace;font-size:0.74rem;color:{observed_color}\">{observed:.1f}</div>"
                        "<div style=\"font-family:'Syne',sans-serif;font-size:0.72rem;color:#334155\">vs</div>"
                        f"<div style=\"font-family:'JetBrains Mono',monospace;font-size:0.74rem;color:#94a3b8\">{mean:.1f} ± {std:.1f}</div>"
                        "</div>"
                    )
            else:
                dev_rows = (
                    "<div style=\"font-family:'JetBrains Mono',monospace;font-size:0.74rem;"
                    "color:#64748b\">No baseline deviations available</div>"
                )
            st.markdown(
                f'<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;'
                f'padding:10px 12px;min-height:145px">{dev_rows}</div>',
                unsafe_allow_html=True,
            )

        st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)
        st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                       color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px">
                       AI Analysis</div>""", unsafe_allow_html=True)
        st.markdown(
            f'<div style="background:#0b1522;border:1px solid #1e2a3a;border-radius:10px;'
            f'padding:14px 16px;margin-bottom:12px">'
            f'<div style="font-family:\'Syne\',sans-serif;color:#60a5fa;font-size:0.82rem;'
            f'margin-bottom:6px">🤖 Analyst Summary</div>'
            f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;'
            f'color:#cbd5e1;line-height:1.6">{plain_english}</div></div>',
            unsafe_allow_html=True,
        )

        st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                       color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px">
                       Risk Factors</div>""", unsafe_allow_html=True)
        if risk_factors:
            badge_html = ""
            for rf in risk_factors:
                txt = str(rf)
                low = txt.lower()
                if any(k in low for k in ("critical", "malicious", "c2", "beacon", "far outside")):
                    bgc, bc, fc = "#2d0a0a", "#7f1d1d", "#f87171"
                elif any(k in low for k in ("high", "certificate", "fingerprint", "suspicious")):
                    bgc, bc, fc = "#2d1200", "#7c2d12", "#fb923c"
                else:
                    bgc, bc, fc = "#2d2000", "#78350f", "#fbbf24"
                badge_html += (
                    f"<span style=\"display:inline-block;margin:0 8px 8px 0;padding:6px 10px;"
                    f"border-radius:999px;border:1px solid {bc};background:{bgc};"
                    f"font-family:'Syne',sans-serif;font-size:0.7rem;font-weight:700;color:{fc};\">{txt}</span>"
                )
            st.markdown(
                f'<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;'
                f'padding:12px 12px">{badge_html}</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;'
                'padding:12px 14px;font-family:\'JetBrains Mono\',monospace;font-size:0.74rem;'
                'color:#64748b">No explicit risk factors available</div>',
                unsafe_allow_html=True,
            )

    
    src_ip = alert.get("src_ip", "")
    if src_ip:
        try:
            related = [a for a in api_client.get_alerts_by_src_ip(src_ip)
                       if a.get("alert_id") != alert_id]
        except Exception:
            related = []
        if related:
            st.markdown('<div style="height:16px"></div>', unsafe_allow_html=True)
            with st.expander(f"Other alerts from {src_ip}  ({len(related)})", expanded=False):
                for a in related[:10]:
                    s = a.get("severity", "")
                    rc1, rc2, rc3, rc4 = st.columns([3, 1, 1, 1])
                    rc1.markdown(f'<div class="mono" style="color:#334155">'
                                 f'{a.get("alert_id","")[:22]}…</div>',
                                 unsafe_allow_html=True)
                    rc2.markdown(f'<span class="badge badge-{s.lower()}">{s}</span>',
                                 unsafe_allow_html=True)
                    rc3.markdown(f'<div class="mono">{float(a.get("composite_score",0)):.3f}</div>',
                                 unsafe_allow_html=True)
                    if rc4.button("View", key=f"rel_{a.get('alert_id','')}"):
                        state.set_selected_alert(a["alert_id"])
                        st.rerun()

    # ── Raw JSON ──
    with st.expander("Raw JSON", expanded=False):
        st.json(alert)
