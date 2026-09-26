"""Shared session, case records, and cached pipeline load."""

from __future__ import annotations

from datetime import datetime, timedelta

import streamlit as st

from config import ALERTS_PATH, CMDB_PATH, IAM_PATH
from engine.pipeline import run_pipeline
from engine.schemas import PipelineResult, ScoredIncident

STATUSES = (
    "New",
    "Acknowledged",
    "Investigating",
    "Escalated",
    "Closed — false positive",
    "Closed — true positive",
)
ASSIGNEES = ("Unassigned", "You", "Analyst-2", "Shift lead")
OPEN_STATUSES = frozenset({"New", "Acknowledged", "Investigating", "Escalated"})
PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
ENVIRONMENTS = ("prod", "staging", "dev", "sandbox", "unknown")
PAGE_OVERVIEW = "console/pages/overview.py"
PAGE_QUEUE = "console/pages/queue.py"
PAGE_INTEL = "console/pages/intelligence.py"
SEVERITY_TOKEN = {
    "Critical": "p0",
    "High": "p1",
    "Medium": "p2",
    "Low": "p3",
}


@st.cache_data(show_spinner="Loading incident snapshot…")
def load_result(cache_version: int = 7) -> PipelineResult:
    if not ALERTS_PATH.exists():
        from data.generate_synthetic_data import write_dataset

        write_dataset()
    return run_pipeline(alerts_path=ALERTS_PATH, cmdb_path=CMDB_PATH, iam_path=IAM_PATH)


def snapshot_now(result: PipelineResult) -> datetime:
    return max(item.incident.last_seen for item in result.risk_ranked) + timedelta(minutes=12)


def snapshot_window(result: PipelineResult) -> tuple[datetime, datetime]:
    first = min(item.incident.first_seen for item in result.risk_ranked)
    last = max(item.incident.last_seen for item in result.risk_ranked)
    return first, last


def init_session(result: PipelineResult) -> None:
    if "cases" not in st.session_state:
        st.session_state.cases = {
            item.incident.incident_id: {
                "status": "New",
                "assignee": "Unassigned",
                "notes": "",
                "done": [],
                "close_reason": "",
            }
            for item in result.risk_ranked
        }
    if "active_case_id" not in st.session_state:
        st.session_state.active_case_id = None
    if "selected" not in st.session_state:
        st.session_state.selected = None


def case(incident_id: str) -> dict:
    return st.session_state.cases[incident_id]


def set_status(incident_id: str, status: str) -> None:
    record = case(incident_id)
    record["status"] = status
    if status == "Investigating" and record["assignee"] == "Unassigned":
        record["assignee"] = "You"


def open_case(incident_id: str) -> None:
    st.session_state.active_case_id = incident_id
    st.session_state.selected = incident_id


def back_to_queue() -> None:
    st.session_state.active_case_id = None
    st.session_state.ignore_queue_pick = True
    st.session_state.show_fp_confirm = False


def open_case_view(incident_id: str, *, switch: bool = False) -> None:
    open_case(incident_id)
    if switch:
        st.switch_page(PAGE_QUEUE)
    else:
        st.rerun()


def reset_case_state() -> None:
    if "cases" in st.session_state:
        del st.session_state.cases
    st.session_state.active_case_id = None


def primary_next_action(item: ScoredIncident) -> str:
    status = case(item.incident.incident_id)["status"]
    if status == "New":
        return "Investigate"
    if status == "Acknowledged":
        return "Investigate"
    if status == "Investigating":
        return "Escalate"
    if status == "Escalated":
        return "Record response"
    return "Reopen if needed"
