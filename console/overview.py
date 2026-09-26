"""Security overview — executive exposure in one screen."""

from __future__ import annotations

import streamlit as st

from console.common import (
    classify,
    defined_metric,
    display,
    empty_state,
    env_of,
    fmt_age,
    owner_of,
    page_header,
    primary_asset,
    priority,
    queue_metrics,
    render_load_error,
    render_priority_card,
    section,
    session_chrome,
    status_of,
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
    st.caption(
        f"{review_reduction_label(raw_n, inc_n)}: {raw_n} raw alerts collapsed to {inc_n} incidents. "
        "That is a volume count, not measured time saved. "
        "These four metrics are organization-wide, not queue-filtered."
    )
    with st.expander("Metric definitions"):
        st.write("Each metric help text states scope, time window, and calculation. Hover a metric label for the same definition.")

    section("Highest-priority incidents", "Action")
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
        section("Affected services and assets", "Observed")
        rows = _affected_rows(result.risk_ranked)
        if rows:
            st.dataframe(rows, width="stretch", hide_index=True, key="ov-assets")
        else:
            empty_state("no_assets", action="Open the queue to inspect lower-priority cases.")
        st.caption("Rows are observed CMDB assets on open high-priority incidents. No inferred dollar impact.")
    with right:
        section("Response progress", "Session")
        st.dataframe(_progress_rows(result), width="stretch", hide_index=True, key="ov-progress")
        st.caption("Counts reflect local case state for this session. Closing a case here does not change the source snapshot.")

    section("Open queue, risk order", "Observed")
    preview = [
        item
        for item in result.risk_ranked
        if case(item.incident.incident_id)["status"] in OPEN_STATUSES
    ][:8]
    if preview:
        st.dataframe(
            [
                {
                    "Priority": priority(item.risk.risk_score),
                    "Incident": display(item.title, item),
                    "Affected service/asset": display(primary_asset(item), item),
                    "Status": status_of(item),
                    "Owner": owner_of(item),
                    "Age": fmt_age(item.incident.first_seen, now),
                    "Risk": round(item.risk.risk_score, 1),
                    "Class": classify(item),
                    "Env": env_of(item),
                }
                for item in preview
            ],
            width="stretch",
            hide_index=True,
            key="ov-queue-preview",
        )
    st.page_link(PAGE_QUEUE, label="Open the incident queue")
