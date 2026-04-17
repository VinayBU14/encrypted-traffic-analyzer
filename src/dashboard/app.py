from __future__ import annotations
import streamlit as st
from src.dashboard import state
from src.dashboard.views import (
    alert_detail,
    graph_view,
    live_capture_view,
    live_monitor,
    overview,
    pcap_upload_view,
    session_timeline,
)

st.set_page_config(
    page_title="Spectra — Encrypted Traffic Analyzer",
    page_icon="🛡️", layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Syne:wght@400;600;700;800&display=swap');

*, *::before, *::after { box-sizing: border-box; }
html, body, [class*="css"] { font-family: 'Syne', sans-serif; }
.stApp { background: #060a10; }
.block-container { padding: 2rem 2.4rem 2rem !important; max-width: 100% !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #080c14 !important;
    border-right: 1px solid #111827 !important;
    min-width: 220px !important;
}
section[data-testid="stSidebar"] > div { padding: 1.6rem 1.2rem; }

/* ── Nav pills ── */
section[data-testid="stSidebar"] .stRadio > div { gap: 3px !important; }
section[data-testid="stSidebar"] .stRadio label {
    font-family: 'Syne', sans-serif !important;
    font-size: 0.82rem !important; font-weight: 700 !important;
    letter-spacing: 0.06em !important; color: #334155 !important;
    padding: 10px 14px !important; border-radius: 8px !important;
    border: 1px solid transparent !important;
    transition: all 0.15s ease !important; width: 100% !important;
    text-transform: uppercase !important;
}
section[data-testid="stSidebar"] .stRadio label:hover {
    color: #64748b !important; background: #0d1117 !important;
    border-color: #1e2a3a !important;
}
section[data-testid="stSidebar"] .stRadio [data-testid="stMarkdownContainer"] p {
    font-family: 'Syne', sans-serif !important; font-size: 0.82rem !important;
}

/* ── Typography ── */
h1,h2,h3,h4 { font-family: 'Syne', sans-serif !important; }
h1 { font-weight:800 !important; font-size:1.8rem !important;
     color:#e2e8f0 !important; letter-spacing:-0.02em; }
h2 { font-weight:700 !important; color:#cbd5e1 !important; }
h3,h4 { font-weight:600 !important; color:#64748b !important; }

/* ── Metrics ── */
[data-testid="stMetric"] {
    background:#0d1117; border:1px solid #1e2a3a;
    border-radius:10px; padding:14px 18px !important;
}
[data-testid="stMetricLabel"] {
    font-family:'Syne',sans-serif !important; font-size:0.68rem !important;
    font-weight:700 !important; text-transform:uppercase !important;
    letter-spacing:0.1em !important; color:#334155 !important;
}
[data-testid="stMetricValue"] {
    font-family:'JetBrains Mono',monospace !important;
    font-size:1.4rem !important; color:#e2e8f0 !important;
}

/* ── Buttons ── */
.stButton > button {
    font-family:'Syne',sans-serif !important; font-weight:700 !important;
    font-size:0.75rem !important; letter-spacing:0.06em !important;
    text-transform:uppercase !important; background:#0d1117 !important;
    color:#475569 !important; border:1px solid #1e2a3a !important;
    border-radius:8px !important; padding:7px 16px !important;
    transition:all 0.15s ease !important;
}
.stButton > button:hover {
    background:#0d1f35 !important; color:#38bdf8 !important;
    border-color:#38bdf8 !important;
}

/* ── Inputs ── */
.stSelectbox label, .stSlider label, .stTextInput label, .stCheckbox label {
    font-family:'Syne',sans-serif !important; font-size:0.68rem !important;
    font-weight:700 !important; text-transform:uppercase !important;
    letter-spacing:0.1em !important; color:#334155 !important;
}
[data-baseweb="select"] > div {
    background:#0d1117 !important; border:1px solid #1e2a3a !important;
    border-radius:8px !important; color:#64748b !important;
    font-family:'Syne',sans-serif !important; font-size:0.85rem !important;
}
.stTextInput input {
    background:#0d1117 !important; border:1px solid #1e2a3a !important;
    border-radius:8px !important; color:#94a3b8 !important;
    font-family:'JetBrains Mono',monospace !important; font-size:0.85rem !important;
}
.stTextInput input:focus { border-color:#38bdf8 !important; box-shadow:0 0 0 2px rgba(56,189,248,0.1) !important; }

/* ── Divider ── */
hr { border-color:#111827 !important; margin:1rem 0 !important; }

/* ── Expander ── */
details { background:#0d1117 !important; border:1px solid #1e2a3a !important; border-radius:10px !important; }
summary { font-family:'Syne',sans-serif !important; font-size:0.75rem !important;
          font-weight:700 !important; color:#334155 !important;
          text-transform:uppercase !important; letter-spacing:0.08em !important; padding:10px 14px !important; }

/* ── Alerts ── */
.stAlert { border-radius:10px !important; font-family:'Syne',sans-serif !important; font-size:0.88rem !important; }

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    background:#0d1117 !important; border:1px solid #1e2a3a !important;
    border-radius:10px !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width:4px; height:4px; }
::-webkit-scrollbar-track { background:#060a10; }
::-webkit-scrollbar-thumb { background:#1e2a3a; border-radius:2px; }
::-webkit-scrollbar-thumb:hover { background:#2d3f56; }

/* ── Reusable classes ── */
.mono { font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:#475569; }
.badge { display:inline-block; padding:2px 9px; border-radius:5px;
         font-family:'Syne',sans-serif; font-size:0.68rem; font-weight:700;
         letter-spacing:0.08em; text-transform:uppercase; }
.badge-critical { background:#1a0505; color:#f87171; border:1px solid #7f1d1d; }
.badge-high     { background:#1a0a00; color:#fb923c; border:1px solid #7c2d12; }
.badge-medium   { background:#1a1400; color:#fbbf24; border:1px solid #78350f; }
.badge-low      { background:#030f1f; color:#60a5fa; border:1px solid #1e3a5f; }
.badge-clean    { background:#021208; color:#4ade80; border:1px solid #14532d; }

.score-track { background:#131c2b; border-radius:3px; height:4px; width:100%; margin-top:4px; }
.score-fill  { height:4px; border-radius:3px; }

.page-header { display:flex; align-items:center; gap:14px;
               padding-bottom:20px; margin-bottom:4px;
               border-bottom:1px solid #111827; }
.page-header-icon { width:42px; height:42px; border-radius:10px;
                    display:flex; align-items:center; justify-content:center;
                    font-size:1.1rem; flex-shrink:0; }
.page-header-title { font-family:'Syne',sans-serif; font-weight:800;
                     font-size:1.6rem; color:#e2e8f0; letter-spacing:-0.02em; margin:0; }
.page-header-sub { font-family:'Syne',sans-serif; font-size:0.68rem; font-weight:700;
                   color:#334155; text-transform:uppercase; letter-spacing:0.1em; margin:0; }
</style>
""", unsafe_allow_html=True)

state.init()

# UPDATED: Added "PCAP Upload" page
PAGES = [
    "Overview",
    "PCAP Upload",
    "Live Monitor",
    "Live Capture",
    "Alert Detail",
    "Graph View",
    "Session Timeline",
]
PAGE_ICONS = {
    "Overview": "◉",
    "PCAP Upload": "⬆",
    "Live Monitor": "⬤",
    "Live Capture": "◎",
    "Alert Detail": "◈",
    "Graph View": "◎",
    "Session Timeline": "◷",
}

with st.sidebar:
    st.markdown("""
    <div style="padding:4px 2px 24px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
            <div style="width:38px;height:38px;
                        background:linear-gradient(135deg,#0ea5e9 0%,#6366f1 100%);
                        border-radius:10px;display:flex;align-items:center;
                        justify-content:center;font-size:1.1rem;flex-shrink:0">🛡️</div>
            <div>
                <div style="font-family:'Syne',sans-serif;font-weight:800;font-size:1.1rem;
                            color:#e2e8f0;letter-spacing:0.02em">SPECTRA</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.62rem;font-weight:700;
                            color:#1e2a3a;text-transform:uppercase;letter-spacing:0.12em">
                    Encrypted Traffic Analyzer</div>
            </div>
        </div>
    </div>
    <div style="font-family:'Syne',sans-serif;font-size:0.62rem;font-weight:700;
                color:#1e2a3a;text-transform:uppercase;letter-spacing:0.12em;
                padding:0 2px;margin-bottom:6px">Navigation</div>
    """, unsafe_allow_html=True)

    active = state.get_active_page()
    if active not in PAGES:
        active = PAGES[0]
    page = st.radio("Nav", PAGES, index=PAGES.index(active), label_visibility="collapsed")
    state.set_active_page(page)

    st.markdown("""
    <div style="margin-top:24px;background:#060a10;border:1px solid #111827;
                border-radius:10px;padding:14px 16px">
        <div style="font-family:'Syne',sans-serif;font-size:0.62rem;font-weight:700;
                    color:#1e2a3a;text-transform:uppercase;letter-spacing:0.12em;
                    margin-bottom:12px">Severity Scale</div>
        <div style="display:flex;flex-direction:column;gap:8px">
            <div style="display:flex;align-items:center;justify-content:space-between">
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="width:7px;height:7px;border-radius:50%;background:#ef4444"></div>
                    <span style="font-family:'Syne',sans-serif;font-size:0.72rem;
                                 color:#475569;font-weight:700">CRITICAL</span>
                </div>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                             color:#334155">≥ 0.90</span>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between">
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="width:7px;height:7px;border-radius:50%;background:#f97316"></div>
                    <span style="font-family:'Syne',sans-serif;font-size:0.72rem;
                                 color:#475569;font-weight:700">HIGH</span>
                </div>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                             color:#334155">≥ 0.75</span>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between">
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="width:7px;height:7px;border-radius:50%;background:#eab308"></div>
                    <span style="font-family:'Syne',sans-serif;font-size:0.72rem;
                                 color:#475569;font-weight:700">MEDIUM</span>
                </div>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                             color:#334155">≥ 0.60</span>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between">
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="width:7px;height:7px;border-radius:50%;background:#3b82f6"></div>
                    <span style="font-family:'Syne',sans-serif;font-size:0.72rem;
                                 color:#475569;font-weight:700">LOW</span>
                </div>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                             color:#334155">≥ 0.30</span>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between">
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="width:7px;height:7px;border-radius:50%;background:#22c55e"></div>
                    <span style="font-family:'Syne',sans-serif;font-size:0.72rem;
                                 color:#475569;font-weight:700">CLEAN</span>
                </div>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                             color:#334155">&lt; 0.30</span>
            </div>
        </div>
    </div>
    <div style="margin-top:16px;font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:#111827;text-align:center;padding:0 2px">
        spectra v1.0.0 · AI traffic analysis</div>
    """, unsafe_allow_html=True)

# ── Route ──────────────────────────────────────────────────────────────────────
if page == "Overview":            overview.render()
elif page == "PCAP Upload":       pcap_upload_view.render()
elif page == "Live Monitor":      live_monitor.render()
elif page == "Live Capture":      live_capture_view.render()
elif page == "Alert Detail":      alert_detail.render()
elif page == "Graph View":        graph_view.render()
elif page == "Session Timeline":  session_timeline.render()