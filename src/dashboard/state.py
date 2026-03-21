
from __future__ import annotations
import streamlit as st

_SELECTED_ALERT_ID = "selected_alert_id"
_SELECTED_FLOW_ID  = "selected_flow_id"
_ACTIVE_PAGE       = "active_page"
_REFRESH_COUNTER   = "refresh_counter"
_SEVERITY_FILTER   = "severity_filter"
_FLOW_LIMIT        = "flow_limit"
_ALERT_LIMIT       = "alert_limit"
_RISK_THRESHOLD    = "risk_threshold"

def init() -> None:
    defaults: dict[str, object] = {
        _SELECTED_ALERT_ID: None,
        _SELECTED_FLOW_ID:  None,
        _ACTIVE_PAGE:       "Overview",
        _REFRESH_COUNTER:   0,
        _SEVERITY_FILTER:   "ALL",
        _FLOW_LIMIT:        100,
        _ALERT_LIMIT:       100,
        _RISK_THRESHOLD:    0.30,
    }
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)

def set_selected_alert(alert_id: str) -> None:
    st.session_state[_SELECTED_ALERT_ID] = alert_id
    st.session_state[_ACTIVE_PAGE] = "Alert Detail"

def get_selected_alert() -> str | None:
    return st.session_state.get(_SELECTED_ALERT_ID)

def clear_selected_alert() -> None:
    st.session_state[_SELECTED_ALERT_ID] = None
    st.session_state[_ACTIVE_PAGE] = "Live Monitor"

def set_selected_flow(flow_id: str) -> None:
    st.session_state[_SELECTED_FLOW_ID] = flow_id

def get_selected_flow() -> str | None:
    return st.session_state.get(_SELECTED_FLOW_ID)

def get_active_page() -> str:
    return st.session_state.get(_ACTIVE_PAGE, "Overview")

def set_active_page(page: str) -> None:
    st.session_state[_ACTIVE_PAGE] = page

def bump_refresh() -> None:
    st.session_state[_REFRESH_COUNTER] = st.session_state.get(_REFRESH_COUNTER, 0) + 1

def get_risk_threshold() -> float:
    return float(st.session_state.get(_RISK_THRESHOLD, 0.30))

def set_risk_threshold(value: float) -> None:
    st.session_state[_RISK_THRESHOLD] = value
