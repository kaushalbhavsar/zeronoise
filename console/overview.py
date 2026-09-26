"""Security overview — executive exposure in one screen."""

from __future__ import annotations

import streamlit as st

from console.common import (
    defined_metric,
    empty_state,
    heading,
    owner_of,
    page_header,
    priority,
    queue_metrics,
    render_load_error,
    render_priority_card,
    session_chrome,
)
from console.state import (
    OPEN_STATUSES,
    PAGE_QUEUE,
    case,
    init_session,
    load_result_or_error,
    snapshot_now,
)
from engine.presentation import review_reduction_label
from engine.schemas import ScoredIncident


def _affected_rows(items: list[ScoredIncident]) -> list[dict]:
    rows: dict[str, dict] = {}
    for item in items:
        if case(item.incident.incident_id)["status"] not in OPEN_STATUSES:
            continue
        if priority(item.risk.risk_score) not in {"P0", "P1"}:
            continue
        for alert in item.incident.alerts:
            for asset in (alert.asset, alert.dest_asset):
                if not asset:
                    continue
                row = rows.setdefault(
                    asset.host_id,
                    {
                        "Asset": asset.hostname,
                        "Host": asset.host_id,
                        "Environment": asset.environment,
                        "Data": asset.data_sensitivity,
                        "Crit": asset.business_criticality,
                        "Incidents": 0,
                        "_ids": set(),
                        "Highest priority": priority(item.risk.risk_score),
                        "Owner": owner_of(item),
                    },
                )
                if item.incident.incident_id not in row["_ids"]:
                    row["_ids"].add(item.incident.incident_id)
                    row["Incidents"] += 1
                if priority(item.risk.risk_score) < row["Highest priority"]:
                    row["Highest priority"] = priority(item.risk.risk_score)
    cleaned = []
    for row in rows.values():
        row.pop("_ids", None)
        cleaned.append(row)
    return sorted(cleaned, key=lambda row: (row["Highest priority"], -row["Crit"]))


def _progress_rows(result) -> list[dict]:
    counts = {status: 0 for status in (
        "New",
        "Acknowledged",
        "Investigating",
        "Escalated",
        "Closed — false positive",
        "Closed — true positive",
    )}
    for item in result.risk_ranked:
        counts[case(item.incident.incident_id)["status"]] += 1
    return [{"Status": status, "Cases": n} for status, n in counts.items() if n]


def render() -> None:
    result, error = load_result_or_error()
    if result is None:
        render_load_error(error or "Unknown load failure")
        return
    if st.query_params.get("case"):
        st.switch_page(PAGE_QUEUE)
    init_session(result)
    now = snapshot_now(result)
    page_header(
        "Security overview",
        result,
        lede="Current exposure from the offline incident snapshot.",
    )
    metrics = queue_metrics(result)
    raw_n = result.metrics.raw_alert_count
    inc_n = result.metrics.incident_count

    with st.sidebar:
        st.caption("Same snapshot as the queue and detection workspaces.")
        session_chrome()

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        defined_metric("open", "Open incidents", metrics["open"])
    with c2:
        defined_metric("p0_p1", "P0–P1 open", metrics["p0_p1"])
    with c3:
        defined_metric("prod", "Open in production", metrics["prod"])
    with c4:
        defined_metric("unacked", "Unacknowledged", metrics["unacked"])
    st.caption(f"{review_reduction_label(raw_n, inc_n)} ({raw_n} → {inc_n}). Organization-wide.")

    heading("Highest-priority incidents")
    urgent = [
        item
        for item in result.risk_ranked
        if case(item.incident.incident_id)["status"] in OPEN_STATUSES
        and priority(item.risk.risk_score) in {"P0", "P1"}
    ][:2]
    if not urgent:
        empty_state("no_p0", action="Open the incident queue to review remaining cases.")
    else:
        cols = st.columns(len(urgent), gap="medium")
        for col, item in zip(cols, urgent):
            with col:
                render_priority_card(item, now, key_prefix="ov", switch=True)

    left, right = st.columns([1.15, 0.85], gap="large")
    with left:
        heading("Affected services and assets")
        rows = _affected_rows(result.risk_ranked)
        if rows:
            st.dataframe(rows, width="stretch", hide_index=True, key="ov-assets")
        else:
            empty_state("no_assets", action="Open the queue to inspect lower-priority cases.")
    with right:
        heading("Response progress")
        st.dataframe(_progress_rows(result), width="stretch", hide_index=True, key="ov-progress")

    st.page_link(PAGE_QUEUE, label="Open the incident queue")
