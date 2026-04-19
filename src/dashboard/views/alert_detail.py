"""
src/dashboard/views/alert_detail.py
Pre-selects the alert injected by Attack Simulator via session key 'ad_jump_alert_id'.
All five risk-factor bars always shown. recommended_action always shown from DB.
"""
from __future__ import annotations
import json, os, sqlite3, threading, time
import streamlit as st

DB_PATH = os.getenv("SPECTRA_DB", "data/spectra.db")

SEVERITY_COLOR = {"CRITICAL":"#f85149","HIGH":"#e3b341","MEDIUM":"#d29922","LOW":"#58a6ff","CLEAN":"#3fb950"}
THREAT_ICONS   = {"C2_BEACON":"📡","DATA_EXFILTRATION":"📤","PORT_SCAN":"🔍","TLS_ANOMALY":"🔐","MALWARE_COMMS":"🦠","LATERAL_MOVEMENT":"↔️","UNKNOWN":"❓"}
RF_COLORS      = {"JA3 Fingerprint":"#a855f7","Certificate Risk":"#f59e0b","Beacon Pattern":"#06b6d4","Graph Proximity":"#10b981","ML Anomaly":"#f85149"}

def _is_capture_running():
    try:
        import requests
        return requests.get("http://localhost:8000/capture/status",timeout=2).json().get("running",False)
    except: return False

def _load_alerts(limit=500, source=None):
    try:
        conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
        cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if not cols: st.error("DB error: no such table: alerts"); return []
        order = "composite_score DESC" if "composite_score" in cols else "rowid DESC"
        where = ""
        if source=="live" and "is_live" in cols: where="WHERE is_live=1"
        elif source=="pcap" and "is_live" in cols: where="WHERE (is_live=0 OR is_live IS NULL)"
        rows = conn.execute(f"SELECT * FROM alerts {where} ORDER BY {order} LIMIT ?",(limit,)).fetchall()
        conn.close(); return [dict(r) for r in rows]
    except Exception as e: st.error(f"DB error: {e}"); return []

def _reload_alert(alert_id):
    try:
        conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row
        row=conn.execute("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)).fetchone()
        conn.close(); return dict(row) if row else None
    except: return None

def _trigger_groq(alert):
    aid=alert.get("alert_id",""); key=f"groq_triggered_{aid}"
    if st.session_state.get(key): return
    st.session_state[key]=True
    def _run():
        try:
            from src.integrations.groq_client import analyse_and_store
            analyse_and_store(alert,DB_PATH)
        except Exception as e:
            import logging; logging.getLogger(__name__).warning("Groq failed: %s",e)
    threading.Thread(target=_run,daemon=True).start()

def _parse_findings(raw):
    if not raw: return []
    if isinstance(raw,list): return raw
    if isinstance(raw,str):
        try:
            p=json.loads(raw); return p if isinstance(p,list) else [str(p)]
        except: return [raw] if raw.strip() else []
    return [str(raw)]

def _score_bar(label, score, color):
    pct=min(int((score or 0)*100),100); op="1" if pct>0 else "0.3"
    return (f'<div style="margin-bottom:12px">'
            f'<div style="display:flex;justify-content:space-between;font-size:12px;color:#8b949e;margin-bottom:4px">'
            f'<span>{label}</span><span style="color:{color};font-weight:600;opacity:{op}">{score:.3f}</span></div>'
            f'<div style="background:#21262d;border-radius:3px;height:5px">'
            f'<div style="background:{color};width:{pct}%;height:5px;border-radius:3px;opacity:{op}"></div>'
            f'</div></div>')

def _findings_panel(alert):
    findings = _parse_findings(alert.get("findings"))
    rec_action = (alert.get("recommended_action") or "").strip()
    col1,col2 = st.columns(2)
    with col1:
        st.markdown('<div style="font-size:10px;color:#8b949e;letter-spacing:1px;margin-bottom:8px">FINDINGS</div>',unsafe_allow_html=True)
        if findings:
            for f in findings:
                st.markdown(f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px 14px;margin-bottom:6px;font-family:monospace;font-size:12px;color:#e6edf3;line-height:1.5">△ {f}</div>',unsafe_allow_html=True)
        else:
            st.markdown('<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px 14px;color:#8b949e;font-size:13px">No specific findings recorded.</div>',unsafe_allow_html=True)
    with col2:
        st.markdown('<div style="font-size:10px;color:#8b949e;letter-spacing:1px;margin-bottom:8px">DEVIATION FROM NORMAL</div>',unsafe_allow_html=True)
        anomaly=float(alert.get("anomaly_score",0) or 0)
        dev=f"Anomaly score {anomaly:.3f} — {int(anomaly*100)}% above baseline" if anomaly>0.3 else "No significant baseline deviations"
        st.markdown(f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:16px;color:#8b949e;font-family:monospace;font-size:13px">{dev}</div>',unsafe_allow_html=True)
    if rec_action:
        sev=alert.get("severity","LOW"); ac=SEVERITY_COLOR.get(sev,"#8b949e"); bg="#1a0a0a" if sev=="CRITICAL" else "#0d1117"
        st.markdown(f'<div style="background:{bg};border:1px solid {ac}44;border-radius:8px;padding:14px 16px;margin-top:12px"><div style="font-size:10px;color:{ac};letter-spacing:1px;margin-bottom:6px">RECOMMENDED ACTION</div><div style="color:#e6edf3;font-size:13px;line-height:1.6">⚡ {rec_action}</div></div>',unsafe_allow_html=True)

def _risk_panel(alert):
    st.divider()
    st.markdown('<div style="font-size:10px;color:#8b949e;letter-spacing:1px;margin-bottom:12px">RISK FACTORS</div>',unsafe_allow_html=True)
    html = (_score_bar("JA3 Fingerprint", float(alert.get("ja3_score",0) or 0),RF_COLORS["JA3 Fingerprint"])
           +_score_bar("Certificate Risk",float(alert.get("cert_score",0) or 0),RF_COLORS["Certificate Risk"])
           +_score_bar("Beacon Pattern",  float(alert.get("beacon_score",0) or 0),RF_COLORS["Beacon Pattern"])
           +_score_bar("Graph Proximity", float(alert.get("graph_score",0) or 0),RF_COLORS["Graph Proximity"])
           +_score_bar("ML Anomaly",      float(alert.get("anomaly_score",0) or 0),RF_COLORS["ML Anomaly"]))
    st.markdown(html, unsafe_allow_html=True)

def _groq_panel(alert):
    st.markdown("---")
    st.markdown('<div style="display:flex;align-items:center;gap:8px;margin-bottom:14px"><span style="font-size:18px">🤖</span><span style="font-size:13px;font-weight:700;color:#e6edf3;letter-spacing:1px">AI ANALYSIS</span></div>',unsafe_allow_html=True)
    sev=alert.get("severity","LOW"); has_groq=bool(alert.get("groq_summary","").strip()); needs_groq=sev in("HIGH","CRITICAL")
    if has_groq:
        threat=alert.get("groq_threat_type","UNKNOWN") or "UNKNOWN"; icon=THREAT_ICONS.get(threat,"❓")
        conf=alert.get("groq_confidence","LOW") or "LOW"; conf_c={"HIGH":"#3fb950","MEDIUM":"#e3b341","LOW":"#f85149"}.get(conf,"#8b949e")
        st.markdown(f'<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap"><span style="background:#161b22;border:1px solid #30363d;border-radius:20px;padding:4px 12px;font-size:12px;color:#e6edf3">{icon} {threat.replace("_"," ")}</span><span style="background:#161b22;border:1px solid {conf_c}55;border-radius:20px;padding:4px 12px;font-size:12px;color:{conf_c}">Confidence: {conf}</span></div>',unsafe_allow_html=True)
        st.markdown(f'<div style="background:linear-gradient(135deg,#0d2137,#0a1628);border:1px solid #1f6feb44;border-radius:8px;padding:14px 16px;margin-bottom:10px"><div style="font-size:10px;color:#58a6ff;letter-spacing:1px;margin-bottom:6px">ANALYST SUMMARY</div><div style="color:#e6edf3;font-size:14px;line-height:1.6">{alert.get("groq_summary","")}</div></div>',unsafe_allow_html=True)
        if alert.get("groq_explanation"):
            st.markdown(f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px 16px;margin-bottom:10px"><div style="font-size:10px;color:#8b949e;letter-spacing:1px;margin-bottom:6px">EXPLANATION</div><div style="color:#c9d1d9;font-size:13px;line-height:1.6">{alert["groq_explanation"]}</div></div>',unsafe_allow_html=True)
        if alert.get("groq_action"):
            st.markdown(f'<div style="background:#0d2014;border:1px solid #3fb95033;border-radius:8px;padding:14px 16px"><div style="font-size:10px;color:#3fb950;letter-spacing:1px;margin-bottom:6px">AI RECOMMENDED ACTION</div><div style="color:#e6edf3;font-size:13px;line-height:1.6">⚡ {alert["groq_action"]}</div></div>',unsafe_allow_html=True)
        if st.button("↻  Refresh AI analysis",key=f"groq_refresh_{alert.get('alert_id','')}"):
            aid=alert.get("alert_id",""); st.session_state.pop(f"groq_triggered_{aid}",None)
            fresh=_reload_alert(aid)
            if fresh: _trigger_groq(fresh)
            st.rerun()
    elif needs_groq:
        aid=alert.get("alert_id",""); _trigger_groq(alert)
        fresh=_reload_alert(aid)
        if fresh and fresh.get("groq_summary","").strip(): st.rerun()
        st.markdown('<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center;color:#8b949e">🔄 AI analysis in progress — results will appear automatically…</div>',unsafe_allow_html=True)
        col_btn,_=st.columns([1,3])
        with col_btn:
            if st.button("↻  Refresh AI Analysis",key=f"groq_manual_{aid}"):
                fresh=_reload_alert(aid)
                if fresh and fresh.get("groq_summary","").strip(): st.success("AI analysis complete!")
                st.rerun()
        time.sleep(3); st.rerun()
    else:
        st.markdown(f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;color:#8b949e;font-size:13px">AI analysis is only triggered for HIGH and CRITICAL alerts (this alert is {sev}).</div>',unsafe_allow_html=True)

def render():
    capture_running=_is_capture_running()
    if capture_running: st.session_state["ad_source"]="live"
    elif "ad_source" not in st.session_state: st.session_state["ad_source"]=None
    if capture_running:
        st.markdown('<div style="background:#0d2137;border:1px solid #1f6feb33;border-radius:6px;padding:6px 12px;font-size:12px;color:#58a6ff;margin-bottom:8px">⊙ Live capture active — showing live-captured alerts only</div>',unsafe_allow_html=True)

    source_param=st.session_state["ad_source"]
    alerts=_load_alerts(limit=500,source=source_param)
    if not alerts:
        st.warning("No live alerts yet — start a capture first." if capture_running else "No alerts in database.")
        return

    # ── Pre-select alert injected by Attack Simulator ─────────────────────────
    jump_id = st.session_state.pop("ad_jump_alert_id", None)
    default_idx = 0

    if jump_id:
        # Search loaded batch
        for i, a in enumerate(alerts):
            if a.get("alert_id") == jump_id:
                default_idx = i
                break
        else:
            # Not in batch — load it directly and prepend
            jumped = _reload_alert(jump_id)
            if jumped:
                alerts = [jumped] + [a for a in alerts if a.get("alert_id") != jump_id]
                default_idx = 0
        st.markdown('<div style="background:#0d2014;border:1px solid #3fb95033;border-radius:6px;padding:8px 14px;font-size:12px;color:#3fb950;margin-bottom:8px">🎯 Showing injected simulated attack alert</div>',unsafe_allow_html=True)

    options=[
        f"{a.get('severity','?')} | {a.get('src_ip','?')}:{a.get('src_port','')} → "
        f"{a.get('dst_domain') or a.get('dst_ip','?')}:{a.get('dst_port','')} | "
        f"score {float(a.get('composite_score',0)):.3f}"
        +(" ⚡" if a.get("is_live") else "")
        for a in alerts
    ]

    idx=st.selectbox("Select alert",range(len(options)),index=default_idx,format_func=lambda i:options[i],label_visibility="collapsed")
    alert=alerts[idx]
    fresh=_reload_alert(alert.get("alert_id",""))
    if fresh: alert=fresh

    sev=alert.get("severity","LOW"); color=SEVERITY_COLOR.get(sev,"#8b949e"); is_live=bool(alert.get("is_live"))
    live_badge=(' <span style="font-size:13px;color:#3fb950;background:#0d2014;padding:2px 8px;border-radius:4px">⚡ LIVE</span>') if is_live else ""
    dst_domain=alert.get("dst_domain") or alert.get("dst_ip") or "unknown"; src_ip=alert.get("src_ip") or "unknown"

    st.markdown(f'<h2 style="color:{color};border-left:3px solid {color};padding-left:16px;margin-bottom:4px">⚡ {sev} — {src_ip} → {dst_domain}{live_badge}</h2>',unsafe_allow_html=True)
    st.caption(f"Alert ID: `{alert.get('alert_id','N/A')}`")
    st.divider()

    _findings_panel(alert)
    _groq_panel(alert)
    _risk_panel(alert)

    aid=alert.get("alert_id","")
    same_src=[a for a in alerts if a.get("src_ip")==src_ip and a.get("alert_id")!=aid]
    with st.expander(f"OTHER ALERTS FROM {src_ip} ({len(same_src)})"):
        for a in same_src[:10]:
            sc=SEVERITY_COLOR.get(a.get("severity","LOW"),"#8b949e")
            st.markdown(f'<div style="font-family:monospace;font-size:12px;padding:5px 0;border-bottom:1px solid #21262d"><span style="color:{sc};min-width:70px;display:inline-block">{a.get("severity","LOW")}</span><span style="color:#e6edf3">{a.get("dst_ip","")}:{a.get("dst_port","")}</span><span style="color:#8b949e;margin-left:10px">{float(a.get("composite_score",0) or 0):.3f}</span></div>',unsafe_allow_html=True)
    with st.expander("RAW JSON"):
        st.json({k:v for k,v in alert.items() if not k.startswith("groq_")})