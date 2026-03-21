

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from src.dashboard import api_client, state

_NODE_TYPE_SHAPE = {"ip":"dot","domain":"diamond","certificate":"triangle","asn":"square","device":"star"}
_NODE_TYPE_ICON  = {"ip":"🌐","domain":"🔗","certificate":"🔒","asn":"🏢","device":"💻"}
_EDGE_TYPE_DASH  = {"contacted":False,"resolves_to":True,"uses":False,"covers":True}


def _risk_color(risk: float, malicious: bool) -> str:
    if malicious:      return "#ef4444"
    if risk >= 0.75:   return "#f97316"
    if risk >= 0.50:   return "#eab308"
    if risk >= 0.30:   return "#3b82f6"
    return "#22c55e"


def _risk_size(risk: float) -> int:
    return max(10, min(35, int(10 + risk * 25)))


def _build_graph(nodes: list[dict], edges: list[dict]) -> Network:
    net = Network(height="580px", width="100%", directed=True,
                  bgcolor="#080c14", font_color="#94a3b8",
                  notebook=False, select_menu=False, filter_menu=False)
    net.set_options(json.dumps({
        "physics": {
            "enabled": True,
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {
                "gravitationalConstant": -50, "centralGravity": 0.01,
                "springLength": 130, "springConstant": 0.08, "damping": 0.4,
            },
            "stabilization": {"iterations": 150},
        },
        "edges": {
            "smooth": {"type": "continuous"},
            "color": {"inherit": False},
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.5}},
            "width": 1,
        },
        "interaction": {"hover": True, "tooltipDelay": 100,
                        "navigationButtons": True, "keyboard": True},
    }))

    for node in nodes:
        risk   = float(node.get("risk_score", 0))
        is_mal = bool(node.get("is_malicious", False))
        ntype  = node.get("node_type", "ip")
        val    = node.get("value", node.get("id", ""))
        label  = val if len(val) <= 22 else val[:19] + "…"
        tip    = (f"<b style='color:#e2e8f0'>{val}</b><br>"
                  f"<span style='color:#64748b'>type: {ntype}</span><br>"
                  f"<span style='color:#64748b'>risk: {risk:.4f}</span><br>"
                  f"<span style='color:{'#ef4444' if is_mal else '#22c55e'}'>"
                  f"{'⚠ MALICIOUS' if is_mal else 'clean'}</span>")
        net.add_node(node["id"], label=label, title=tip,
                     color=_risk_color(risk, is_mal),
                     size=_risk_size(risk),
                     shape=_NODE_TYPE_SHAPE.get(ntype, "dot"),
                     font={"size": 10, "color": "#94a3b8"},
                     borderWidth=3 if is_mal else 1,
                     borderWidthSelected=5)

    for edge in edges:
        etype  = edge.get("edge_type", "contacted")
        weight = float(edge.get("weight", 1.0))
        net.add_edge(edge["source"], edge["target"], title=etype,
                     color={"color": "#1e2a3a", "highlight": "#38bdf8"},
                     dashes=_EDGE_TYPE_DASH.get(etype, False),
                     width=max(0.5, min(3.5, weight)))
    return net


def _render_graph(net: Network) -> None:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        net.save_graph(f.name)
        path = f.name
    try:
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        components.html(html, height=600, scrolling=False)
    finally:
        try: os.unlink(path)
        except OSError: pass


def render() -> None:
    st.markdown("""
    <div class="page-header">
        <div class="page-header-icon" style="background:#0d1a1a;">◎</div>
        <div>
            <div class="page-header-title">Infrastructure Graph</div>
            <div class="page-header-sub">Entity network · risk topology</div>
        </div>
    </div>""", unsafe_allow_html=True)

    c1, c2, c3 = st.columns([2, 2, 2])
    with c1:
        threshold = st.slider("Risk threshold", 0.0, 1.0,
                              state.get_risk_threshold(), 0.05,
                              format="%.2f", key="gv_thresh")
        state.set_risk_threshold(threshold)
    with c2:
        glimit = st.slider("Max flows", 100, 2000, 500, 100, key="gv_limit")
    with c3:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("↻  Refresh graph", key="gv_ref", use_container_width=True):
            st.rerun()

    with st.spinner("Building graph…"):
        try:
            gdata     = api_client.get_graph(limit=glimit)
            high_risk = api_client.get_high_risk_nodes(threshold=threshold, limit=glimit)
        except ConnectionError as exc:
            st.error(f"API Unavailable — {exc}"); return
        except Exception as exc:
            st.error(f"Fetch failed: {exc}"); return

    nodes = gdata.get("nodes", [])
    edges = gdata.get("edges", [])
    nc, ec = gdata.get("node_count", len(nodes)), gdata.get("edge_count", len(edges))
    malicious_n = sum(1 for n in nodes if n.get("is_malicious"))

    
    chips = (f'<div style="background:#2d0a0a;border:1px solid #7f1d1d;border-radius:10px;'
             f'padding:14px 16px;flex:1;text-align:center">'
             f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:1.5rem;'
             f'font-weight:600;color:#ef4444;line-height:1">{malicious_n}</div>'
             f'<div style="font-family:\'Syne\',sans-serif;font-size:0.68rem;font-weight:700;'
             f'color:#7f1d1d;text-transform:uppercase;letter-spacing:0.08em;margin-top:5px">'
             f'Malicious</div></div>')
    for label, val in [("Total nodes", nc), ("Total edges", ec),
                        (f"Above {threshold:.2f}", len(high_risk))]:
        chips += (f'<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;'
                  f'padding:14px 16px;flex:1;text-align:center">'
                  f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:1.5rem;'
                  f'font-weight:600;color:#e2e8f0;line-height:1">{val}</div>'
                  f'<div style="font-family:\'Syne\',sans-serif;font-size:0.68rem;font-weight:700;'
                  f'color:#334155;text-transform:uppercase;letter-spacing:0.08em;margin-top:5px">'
                  f'{label}</div></div>')
    st.markdown(f'<div style="display:flex;gap:10px;margin:16px 0">{chips}</div>',
                unsafe_allow_html=True)

    if not nodes:
        st.markdown("""<div style="background:#0d1117;border:1px solid #1e2a3a;
                       border-radius:10px;padding:32px;text-align:center;">
            <div style="font-family:'Syne',sans-serif;color:#334155;font-weight:600">
                No graph data. Run the pipeline to ingest PCAP traffic first.</div>
        </div>""", unsafe_allow_html=True)
        return

    
    st.markdown("""
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;
                font-family:'Syne',sans-serif;font-size:0.72rem;font-weight:600">
        <span style="color:#334155">Node colour:</span>
        <span><span style="color:#ef4444">●</span> Malicious</span>
        <span><span style="color:#f97316">●</span> High ≥0.75</span>
        <span><span style="color:#eab308">●</span> Medium ≥0.50</span>
        <span><span style="color:#3b82f6">●</span> Low ≥0.30</span>
        <span><span style="color:#22c55e">●</span> Clean</span>
        <span style="color:#334155;margin-left:8px">Shape:</span>
        <span style="color:#64748b">● IP &nbsp; ◆ Domain &nbsp; ▲ Cert &nbsp; ■ ASN &nbsp; ★ Device</span>
    </div>""", unsafe_allow_html=True)

    graph_col, table_col = st.columns([3, 2])

    with graph_col:
        net = _build_graph(nodes, edges)
        _render_graph(net)

    with table_col:
        st.markdown(f'<div style="font-family:\'Syne\',sans-serif;font-size:0.68rem;'
                    f'font-weight:700;color:#334155;text-transform:uppercase;'
                    f'letter-spacing:0.1em;margin-bottom:8px">'
                    f'High-risk nodes ≥ {threshold:.2f}</div>',
                    unsafe_allow_html=True)
        if not high_risk:
            st.markdown('<div style="font-family:\'Syne\',sans-serif;color:#1e2a3a;'
                        'font-size:0.82rem">No nodes above threshold.</div>',
                        unsafe_allow_html=True)
        else:
            rows = []
            for n in high_risk:
                ntype = n.get("node_type","")
                rows.append({
                    "Type":  f"{_NODE_TYPE_ICON.get(ntype,'❓')} {ntype}",
                    "Value": n.get("value", n.get("id","")),
                    "Risk":  round(float(n.get("risk_score",0)),4),
                    "Flag":  "⚠ YES" if n.get("is_malicious") else "—",
                })
            df = pd.DataFrame(rows).sort_values("Risk", ascending=False)
            st.dataframe(df, use_container_width=True, hide_index=True,
                         column_config={
                             "Risk": st.column_config.ProgressColumn(
                                 "Risk", min_value=0.0, max_value=1.0, format="%.4f")
                         })

    with st.expander("Raw graph JSON (first 20 nodes)", expanded=False):
        st.json({"node_count": nc, "edge_count": ec,
                 "nodes": nodes[:20], "edges": edges[:20]})
