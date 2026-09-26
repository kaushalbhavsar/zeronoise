"""ZeroNoise SOC console — three workspaces over one offline snapshot."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from console.state import PAGE_INTEL, PAGE_OVERVIEW, PAGE_QUEUE, init_session, load_result
from console.theme import inject_theme

st.set_page_config(
    page_title="ZeroNoise · SOC",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_theme()
init_session(load_result())

page = st.navigation(
    [
        st.Page(PAGE_OVERVIEW, title="Security overview", icon=":material/space_dashboard:", default=True),
        st.Page(PAGE_QUEUE, title="Incident queue", icon=":material/assignment:"),
        st.Page(PAGE_INTEL, title="Detection intelligence", icon=":material/query_stats:"),
    ],
    position="top",
)
page.run()
