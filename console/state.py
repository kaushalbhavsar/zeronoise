"""Shared session, case records, and cached pipeline load."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
SESSION_ACTOR = "You"


@st.cache_data(show_spinner="Loading incident snapshot…")
def load_result(cache_version: int = 9) -> PipelineResult:
    if not ALERTS_PATH.exists():
        from data.generate_synthetic_data import write_dataset

        write_dataset()
    return run_pipeline(alerts_path=ALERTS_PATH, cmdb_path=CMDB_PATH, iam_path=IAM_PATH)


def load_result_or_error() -> tuple[PipelineResult | None, str | None]:
    try:
        return load_result(), None
    except Exception as exc:
        return None, str(exc)


def snapshot_now(result: PipelineResult) -> datetime:
    return max(item.incident.last_seen for item in result.risk_ranked) + timedelta(minutes=12)


def snapshot_window(result: PipelineResult) -> tuple[datetime, datetime]:
    first = min(item.incident.first_seen for item in result.risk_ranked)
    last = max(item.incident.last_seen for item in result.risk_ranked)
    return first, last


def _empty_case() -> dict:
    return {
        "status": "New",
        "assignee": "Unassigned",
        "notes": "",
        "done": [],
        "close_reason": "",
        "history": [],
    }


def init_session(result: PipelineResult) -> None:
    if "cases" not in st.session_state:
        st.session_state.cases = {
            item.incident.incident_id: _empty_case() for item in result.risk_ranked
        }
    else:
        for item in result.risk_ranked:
            record = st.session_state.cases.setdefault(item.incident.incident_id, _empty_case())
            record.setdefault("history", [])
    if "active_case_id" not in st.session_state:
        st.session_state.active_case_id = None
    if "selected" not in st.session_state:
        st.session_state.selected = None
    if "snapshot_loaded_at" not in st.session_state:
        st.session_state.snapshot_loaded_at = datetime.now(timezone.utc)
    if "presentation_mode" not in st.session_state:
        st.session_state.presentation_mode = False
    apply_deep_link({item.incident.incident_id for item in result.risk_ranked})


def presenting() -> bool:
    return bool(st.session_state.get("presentation_mode"))


def case(incident_id: str) -> dict:
    return st.session_state.cases[incident_id]


def record_event(incident_id: str, field: str, old: str, new: str) -> None:
    if old == new:
        return
    case(incident_id).setdefault("history", []).append(
        {
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
            "actor": SESSION_ACTOR,
            "field": field,
            "old": old,
            "new": new,
        }
    )


def persist_status(incident_id: str, status: str) -> None:
    record = case(incident_id)
    old = record["status"]
    record["status"] = status
    record_event(incident_id, "status", old, status)
    st.toast(f"Status saved: {status}")


def persist_owner(incident_id: str, owner: str) -> None:
    record = case(incident_id)
    old = record["assignee"]
    if old == owner:
        return
    record["assignee"] = owner
    record_event(incident_id, "owner", old, owner)
    st.toast(f"Owner saved: {owner}")


def persist_notes(incident_id: str, notes: str) -> None:
    record = case(incident_id)
    old = record["notes"]
    record["notes"] = notes
    record_event(incident_id, "notes", "(updated)" if old else "(empty)", "(saved)")
    st.toast("Notes saved")


def persist_task(incident_id: str, action: str, done: bool) -> None:
    record = case(incident_id)
    items = record["done"]
    if done and action not in items:
        items.append(action)
        record_event(incident_id, "task", "open", action)
        st.toast("Task recorded in this case file")
    elif not done and action in items:
        items.remove(action)
        record_event(incident_id, "task", action, "open")
        st.toast("Task unmarked")


def set_status(incident_id: str, status: str) -> None:
    persist_status(incident_id, status)


def open_case(incident_id: str) -> None:
    st.session_state.active_case_id = incident_id
    st.session_state.selected = incident_id


def back_to_queue() -> None:
    st.session_state.active_case_id = None
    st.session_state.ignore_queue_pick = True
    st.session_state.show_fp_confirm = False


def apply_deep_link(known_ids: set[str]) -> None:
    case_id = st.query_params.get("case")
    if not case_id:
        return
    if case_id in known_ids:
        st.session_state.active_case_id = case_id
        st.session_state.selected = case_id
        return
    st.session_state.deep_link_missing = case_id


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
    st.toast("Session case state cleared")


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
