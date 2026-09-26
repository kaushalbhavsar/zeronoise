"""Security overview — executive exposure in one screen."""

from __future__ import annotations

import streamlit as st

from console.common import (
    classify,
    demo_admin_controls,
    env_of,
    fmt_age,
    owner_of,
    page_header,
    primary_asset,
    priority,
    queue_metrics,
    render_badges,
    status_of,
)
from console.state import (
    OPEN_STATUSES,
    PAGE_QUEUE,
    case,
    init_session,
    load_result,
    open_case_view,
    snapshot_now,
)
from engine.presentation import review_reduction_label, urgency_sentence
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
    result = load_result()
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
        demo_admin_controls()

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(
        f"<div class='zn-metric'><div class='n'>{metrics['open']}</div>"
        f"<div class='l'>Open incidents</div>"
        f"<div class='h'>Of {inc_n} correlated cases</div></div>",
        unsafe_allow_html=True,
    )
    c2.markdown(
        f"<div class='zn-metric'><div class='n'>{metrics['p0_p1']}</div>"
        f"<div class='l'>P0–P1 open</div>"
        f"<div class='h'>Priority from risk score, not vendor severity</div></div>",
        unsafe_allow_html=True,
    )
    c3.markdown(
        f"<div class='zn-metric'><div class='n'>{metrics['prod']}</div>"
        f"<div class='l'>Open in production</div>"
        f"<div class='h'>Production is scope, not a healthy state</div></div>",
        unsafe_allow_html=True,
    )
    c4.markdown(
        f"<div class='zn-metric'><div class='n'>{metrics['unacked']}</div>"
        f"<div class='l'>Unacknowledged</div>"
        f"<div class='h'>{metrics['assigned']} assigned of {metrics['open']} open</div></div>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"{review_reduction_label(raw_n, inc_n)}: {raw_n} raw alerts collapsed to {inc_n} incidents. "
        "That is a volume count, not measured time saved."
    )

    st.subheader("Highest-priority incidents")
    urgent = [
        item
        for item in result.risk_ranked
        if case(item.incident.incident_id)["status"] in OPEN_STATUSES
        and priority(item.risk.risk_score) in {"P0", "P1"}
    ][:2]
    if not urgent:
        st.info("No open P0 or P1 incidents in this snapshot.")
    else:
        cols = st.columns(len(urgent), gap="medium")
        for col, item in zip(cols, urgent):
            with col:
                pri = priority(item.risk.risk_score)
                st.markdown(
                    f"<div class='icard pri-{pri.lower()}'>"
                    f"<div class='title'>{item.title}</div>"
                    f"<div class='meta'><span class='pri {pri.lower()}'>{pri}</span> "
                    f"Risk {item.risk.risk_score:.0f} · {primary_asset(item)} · {owner_of(item)}</div>"
                    f"<div class='urgency'>{urgency_sentence(item)}</div>"
                    f"<div class='id'>{item.incident.incident_id}</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
                render_badges(item, limit=3)
                if st.button("Open case", key=f"ov-{item.incident.incident_id}", use_container_width=True):
                    open_case_view(item.incident.incident_id, switch=True)

    left, right = st.columns([1.15, 0.85], gap="large")
    with left:
        st.subheader("Affected services and assets")
        rows = _affected_rows(result.risk_ranked)
        if rows:
            st.dataframe(rows, width="stretch", hide_index=True, key="ov-assets")
        else:
            st.info("No production-sensitive assets are attached to open P0/P1 cases.")
        st.caption("Rows are observed CMDB assets on open high-priority incidents. No inferred dollar impact.")
    with right:
        st.subheader("Response progress")
        st.dataframe(_progress_rows(result), width="stretch", hide_index=True, key="ov-progress")
        st.caption("Counts reflect local case state for this session. Closing a case here does not change the source snapshot.")

    st.subheader("Open queue, risk order")
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
                    "Incident": item.title,
                    "Affected service/asset": primary_asset(item),
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
