"""
src/dashboard/views/attack_simulator_view.py
=============================================
Simulated Attack Control Panel — Spectra dashboard view.

Bugs fixed vs v1:
  - parents[4] → parents[3]: view lives 3 levels deep, not 4
  - f-string conditional inside HTML caused Streamlit to render raw tags as
    escaped text. Fixed by pre-computing all sub-strings before the template.
  - Findings loop variable `f` shadowed the built-in; renamed to `finding`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_SEV_COLOR  = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
               "LOW": "#3b82f6", "CLEAN": "#22c55e"}
_SEV_BG     = {"CRITICAL": "#1a0505", "HIGH": "#1a0a00", "MEDIUM": "#1a1400",
               "LOW": "#030f1f", "CLEAN": "#021208"}
_SEV_BORDER = {"CRITICAL": "#7f1d1d", "HIGH": "#7c2d12", "MEDIUM": "#78350f",
               "LOW": "#1e3a5f", "CLEAN": "#14532d"}

_SCENARIO_META = {
    "ja3": {
        "icon": "🔑",
        "title": "Malicious JA3 Fingerprint",
        "desc": "Injects a TLS ClientHello whose JA3 hash matches a known malware family (Emotet, TrickBot, CobaltStrike…) from the threat-intel database.",
        "color": "#8b5cf6",
        "expected": "HIGH / CRITICAL",
    },
    "cert": {
        "icon": "📜",
        "title": "Malicious Certificate",
        "desc": "Self-signed cert issued &lt;7 days ago, known-bad SHA-256 fingerprint, short validity window, and 4+ SANs — all certificate risk flags triggered.",
        "color": "#f59e0b",
        "expected": "MEDIUM / HIGH",
    },
    "combo": {
        "icon": "💀",
        "title": "Combined JA3 + Certificate",
        "desc": "Worst-case: malicious JA3 + self-signed cert + bad fingerprint + beacon. Designed to hit CRITICAL (composite ≥ 0.90).",
        "color": "#ef4444",
        "expected": "CRITICAL",
    },
    "beacon": {
        "icon": "📡",
        "title": "C2 Beacon Pattern",
        "desc": "Periodic C2 beacon — low jitter, regular intervals, malicious JA3, Free-CA cert for a newly-registered domain.",
        "color": "#06b6d4",
        "expected": "HIGH / CRITICAL",
    },
    "all": {
        "icon": "🌐",
        "title": "Full Attack Suite",
        "desc": "Injects one of each scenario simultaneously — JA3, Certificate, Combo, and Beacon — to exercise every detection module.",
        "color": "#10b981",
        "expected": "ALL SEVERITIES",
    },
}


def _score_bar(label: str, score: float, color: str) -> str:
    pct = min(int(score * 100), 100)
    return (
        '<div style="margin-bottom:8px">'
        '<div style="display:flex;justify-content:space-between;font-size:11px;color:#64748b;margin-bottom:3px">'
        '<span style="font-family:\'Syne\',sans-serif;font-weight:600">' + label + '</span>'
        '<span style="font-family:\'JetBrains Mono\',monospace;color:' + color + ';font-weight:700">' + f'{score:.3f}' + '</span>'
        '</div>'
        '<div style="background:#131c2b;border-radius:3px;height:5px">'
        '<div style="width:' + str(pct) + '%;background:' + color + ';height:5px;border-radius:3px;box-shadow:0 0 6px ' + color + '66"></div>'
        '</div></div>'
    )


def _build_findings_block(findings: list) -> str:
    if not findings:
        return '<div style="color:#334155;font-size:11px;font-family:\'Syne\',sans-serif;padding:4px 0">No findings recorded.</div>'
    html = ""
    for finding in findings[:6]:
        safe = str(finding).replace("<", "&lt;").replace(">", "&gt;")
        html += (
            '<div style="font-family:\'JetBrains Mono\',monospace;font-size:11px;'
            'color:#94a3b8;padding:5px 0;border-bottom:1px solid #131c2b;line-height:1.4">'
            '△ ' + safe + '</div>'
        )
    return html


def _build_alert_card(alert: dict) -> str:
    sev    = alert.get("severity", "LOW")
    score  = float(alert.get("composite_score", 0))
    color  = _SEV_COLOR.get(sev, "#64748b")
    bg     = _SEV_BG.get(sev, "#080c14")
    border = _SEV_BORDER.get(sev, "#1e2a3a")
    src    = str(alert.get("src_ip", "?"))
    sport  = str(alert.get("src_port", ""))
    dst    = str(alert.get("dst_domain") or alert.get("dst_ip", "?"))
    dport  = str(alert.get("dst_port", ""))
    aid    = str(alert.get("alert_id", ""))[:8]
    action = str(alert.get("recommended_action", "—")).replace("<", "&lt;").replace(">", "&gt;")
    score_str = f"{score:.4f}"
    src_label = src + ":" + sport
    dst_label = dst + ":" + dport

    raw_findings = alert.get("findings", [])
    if isinstance(raw_findings, str):
        try:
            raw_findings = json.loads(raw_findings)
        except Exception:
            raw_findings = [raw_findings] if raw_findings else []

    findings_block = _build_findings_block(raw_findings)

    bars_block = (
        _score_bar("JA3 Fingerprint",  float(alert.get("ja3_score",    0) or 0), "#8b5cf6")
        + _score_bar("Certificate Risk", float(alert.get("cert_score",    0) or 0), "#f59e0b")
        + _score_bar("Beacon Pattern",   float(alert.get("beacon_score",  0) or 0), "#06b6d4")
        + _score_bar("Graph Proximity",  float(alert.get("graph_score",   0) or 0), "#10b981")
        + _score_bar("ML Anomaly",       float(alert.get("anomaly_score", 0) or 0), "#ef4444")
    )

    return (
        '<div style="background:linear-gradient(135deg,' + bg + ' 0%,#080c14 100%);'
        'border:1px solid ' + border + ';border-radius:14px;'
        'padding:20px 24px;margin-bottom:20px;box-shadow:0 0 28px ' + color + '22">'

        '<div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:18px">'
        '<div>'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.62rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;letter-spacing:0.14em;margin-bottom:5px">'
        '⚡ Simulated Attack Detected</div>'
        '<div style="font-family:\'Syne\',sans-serif;font-size:1.6rem;font-weight:800;'
        'color:' + color + ';letter-spacing:-0.02em">' + sev + '</div>'
        '</div>'
        '<div style="text-align:right">'
        '<div style="font-family:\'JetBrains Mono\',monospace;font-size:2.2rem;'
        'font-weight:700;color:' + color + ';line-height:1">' + score_str + '</div>'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.6rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;letter-spacing:0.1em">Composite Score</div>'
        '</div>'
        '</div>'

        '<div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">'
        '<div style="flex:1;min-width:130px;background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:10px 14px">'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.58rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;margin-bottom:4px">Source</div>'
        '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.82rem;color:#e2e8f0">' + src_label + '</div>'
        '</div>'
        '<div style="flex:2;min-width:180px;background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:10px 14px;overflow:hidden">'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.58rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;margin-bottom:4px">Destination</div>'
        '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.82rem;color:#e2e8f0;'
        'white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + dst_label + '</div>'
        '</div>'
        '<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:10px 14px">'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.58rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;margin-bottom:4px">Alert ID</div>'
        '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;color:#64748b">' + aid + '…</div>'
        '</div>'
        '</div>'

        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">'
        '<div>'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.58rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px">Findings</div>'
        '<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:10px 14px;min-height:90px">'
        + findings_block +
        '</div>'
        '</div>'
        '<div>'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.58rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px">Risk Factors</div>'
        '<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:10px 14px">'
        + bars_block +
        '</div>'
        '</div>'
        '</div>'

        '<div style="background:#0a1628;border:1px solid #1e3a5f;border-radius:8px;padding:10px 16px">'
        '<span style="font-family:\'Syne\',sans-serif;font-size:0.58rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;letter-spacing:0.1em">Recommended Action &nbsp;</span>'
        '<span style="font-family:\'Syne\',sans-serif;font-size:0.82rem;color:#94a3b8">⚡ ' + action + '</span>'
        '</div>'

        '</div>'
    )


def render() -> None:
    st.markdown(
        '<div style="margin-bottom:28px">'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.65rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;letter-spacing:0.14em;margin-bottom:6px">'
        'Attack Simulation Lab</div>'
        '<div style="font-family:\'Syne\',sans-serif;font-size:1.7rem;font-weight:800;'
        'color:#e2e8f0;letter-spacing:-0.02em">Simulated Attack Injector</div>'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.84rem;color:#475569;margin-top:6px">'
        'Inject synthetic malicious JA3 fingerprints and certificates through the live detection '
        'pipeline. Results appear immediately in Overview and Alert Detail.</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.65rem;font-weight:700;'
        'color:#334155;text-transform:uppercase;letter-spacing:0.12em;margin-bottom:12px">'
        'Choose Attack Scenario</div>',
        unsafe_allow_html=True,
    )

    if "sim_scenario" not in st.session_state:
        st.session_state["sim_scenario"] = "combo"

    scenario_keys = list(_SCENARIO_META.keys())
    cols = st.columns(len(scenario_keys))

    for col, key in zip(cols, scenario_keys):
        meta = _SCENARIO_META[key]
        is_sel = (key == st.session_state["sim_scenario"])
        bc   = meta["color"] if is_sel else "#1e2a3a"
        bg   = "#0d1117" if is_sel else "#080c14"
        glow = "box-shadow:0 0 18px " + meta["color"] + "44;" if is_sel else ""
        tc   = meta["color"] if is_sel else "#475569"
        with col:
            st.markdown(
                '<div style="background:' + bg + ';border:1px solid ' + bc + ';'
                'border-radius:12px;padding:14px 10px;text-align:center;' + glow + '">'
                '<div style="font-size:1.5rem;margin-bottom:6px">' + meta["icon"] + '</div>'
                '<div style="font-family:\'Syne\',sans-serif;font-size:0.65rem;font-weight:700;'
                'color:' + tc + ';text-transform:uppercase;letter-spacing:0.06em">' + key.upper() + '</div>'
                '</div>',
                unsafe_allow_html=True,
            )
            label = "✓ Selected" if is_sel else "Select"
            if st.button(label, key="sim_sel_" + key, use_container_width=True):
                st.session_state["sim_scenario"] = key
                st.rerun()

    sel  = st.session_state["sim_scenario"]
    meta = _SCENARIO_META[sel]

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    st.markdown(
        '<div style="background:#0d1117;border:1px solid ' + meta["color"] + '33;'
        'border-radius:12px;padding:16px 20px;margin-bottom:20px">'
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">'
        '<span style="font-size:1.3rem">' + meta["icon"] + '</span>'
        '<span style="font-family:\'Syne\',sans-serif;font-size:0.9rem;font-weight:700;'
        'color:' + meta["color"] + '">' + meta["title"] + '</span>'
        '<span style="margin-left:auto;font-family:\'JetBrains Mono\',monospace;'
        'font-size:0.68rem;background:' + meta["color"] + '18;color:' + meta["color"] + ';'
        'padding:3px 10px;border-radius:20px;border:1px solid ' + meta["color"] + '33">'
        'Expected: ' + meta["expected"] + '</span>'
        '</div>'
        '<div style="font-family:\'Syne\',sans-serif;font-size:0.82rem;color:#64748b;line-height:1.6">'
        + meta["desc"] + '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns([3, 1])
    with c1:
        count = st.slider("Number of attacks to inject", min_value=1, max_value=10,
                          value=1, step=1, key="sim_count")
    with c2:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
        fire = st.button(
            "⚡  Inject " + str(count) + " Attack" + ("s" if count > 1 else ""),
            type="primary", use_container_width=True, key="sim_fire",
        )

    if fire:
        with st.spinner("Running attacks through detection pipeline…"):
            try:
                from simulate_attack import AttackSimulator
                db_path = os.getenv("SPECTRA_DB", "data/spectra.db")
                sim = AttackSimulator(db_path=db_path)
                alerts = sim.run(scenario_filter=sel, count=count, verbose=False)
                st.session_state["sim_last_alerts"] = alerts
                sev_counts: dict[str, int] = {}
                for a in alerts:
                    sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1
                summary = "  |  ".join(s + ": " + str(n) for s, n in sev_counts.items())
                st.success("✅  " + str(len(alerts)) + " alert(s) injected → " + summary +
                           " — visible in Overview and Alert Detail now.")
            except Exception as exc:
                st.error("Injection failed: " + str(exc))
                import traceback
                st.code(traceback.format_exc(), language="python")
                return

    last_alerts = st.session_state.get("sim_last_alerts", [])
    if last_alerts:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        st.markdown(
            '<div style="font-family:\'Syne\',sans-serif;font-size:0.65rem;font-weight:700;'
            'color:#334155;text-transform:uppercase;letter-spacing:0.12em;margin-bottom:14px">'
            'Last Injection — ' + str(len(last_alerts)) + ' Alert' + ('s' if len(last_alerts) > 1 else '') + '</div>',
            unsafe_allow_html=True,
        )
        for alert in last_alerts:
            st.markdown(_build_alert_card(alert), unsafe_allow_html=True)

        if st.button("Clear results", key="sim_clear"):
            st.session_state.pop("sim_last_alerts", None)
            st.rerun()

    with st.expander("How the simulation works — pipeline details"):
        st.markdown("""
**Every injected attack uses the real detection pipeline — no mocking:**

1. A `TLSSessionRecord` is built with the attack's JA3 hash and/or certificate parameters.
2. `JA3Analyzer.score()` looks up the hash in `data/threat_intel/ja3_malicious.json`.
3. `CertificateAnalyzer.score()` checks cert age, self-signed flag, SAN count, issuer type, and SHA-256 fingerprint.
4. `ScoringEngine.compute()` combines with weights `ja3=0.35 · beacon=0.25 · cert=0.20 · graph=0.20` + anomaly uplift.
5. `AlertBuilder.build()` assembles the full `AlertRecord` with findings and severity.
6. Written to `data/spectra.db` → visible in dashboard instantly.

| Scenario | JA3 | Cert Flags | Beacon | Expected |
|---|---|---|---|---|
| `ja3` | Real malicious hash | Clean | None | HIGH |
| `cert` | None | Self-signed + new + bad fp + SAN | None | MEDIUM/HIGH |
| `combo` | Malicious | All cert flags | High | **CRITICAL** |
| `beacon` | Malicious | Free CA + new domain | High | HIGH/CRITICAL |
        """)