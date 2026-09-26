"""Incident queue — operational workspace for analysts."""

from __future__ import annotations

from datetime import datetime

import streamlit as st

from console.case import render_case_workspace
from console.common import (
    classify,
    copyable_id,
    demo_admin_controls,
    filter_summary,
    fmt_age,
    owner_of,
    page_header,
    primary_asset,
    priority,
    queue_filters,
    queue_metrics,
    render_badges,
    status_of,
    visible_incidents,
)
from console.state import (
    init_session,
    load_result,
    open_case_view,
    snapshot_now,
)
from engine.presentation import rank_delta, rank_delta_label, urgency_sentence
from engine.schemas import PipelineResult, ScoredIncident


def _featured(items: list[ScoredIncident]) -> list[ScoredIncident]:
    urgent = [item for item in items if priority(item.risk.risk_score) in {"P0", "P1"}]
    picked = (urgent or items)[:2]
    return picked


def render_featured_cards(items: list[ScoredIncident], now: datetime) -> None:
    top = _featured(items)
    if not top:
        return
    st.subheader("Take next")
    cols = st.columns(len(top), gap="medium")
    last = st.session_state.get("selected")
    for col, item in zip(cols, top):
        with col:
            pri = priority(item.risk.risk_score)
            active = "active" if item.incident.incident_id == last else ""
            st.markdown(
                f"<div class='icard pri-{pri.lower()} {active}'>"
                f"<div class='title'>{item.title}</div>"
                f"<div class='meta'>"
                f"<span class='pri {pri.lower()}'>{pri}</span> "
                f"Risk {item.risk.risk_score:.0f} · {primary_asset(item)} · {owner_of(item)} · "
                f"{status_of(item)} · {fmt_age(item.incident.first_seen, now)}"
                f"</div>"
                f"<div class='urgency'>{urgency_sentence(item)}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
            copyable_id(item.incident.incident_id, key=f"feat-id-{item.incident.incident_id}")
            render_badges(item, limit=3)
            extra = context_rest(item)
            if extra:
                with st.expander("More context"):
                    st.write(", ".join(extra))
            if st.button(
                "Open case",
                key=f"feat-{st.session_state.get('queue_mode', 'ai')}-{item.incident.incident_id}",
                use_container_width=True,
            ):
                open_case_view(item.incident.incident_id)


def context_rest(item: ScoredIncident) -> list[str]:
    from engine.presentation import context_badges

    names = context_badges(item)
    return names[3:]


def queue_rows(items: list[ScoredIncident], now: datetime, *, show_ranks: bool) -> list[dict]:
    rows = []
    for item in items:
        delta = rank_delta(item.risk_rank, item.naive_siem_rank)
        row = {
            "_id": item.incident.incident_id,
            "Priority": priority(item.risk.risk_score),
            "Incident": item.title,
            "Affected service/asset": primary_asset(item),
            "Status": status_of(item),
            "Owner": owner_of(item),
            "Age": fmt_age(item.incident.first_seen, now),
            "Risk": round(item.risk.risk_score, 1),
        }
        if show_ranks:
            row["AI rank"] = item.risk_rank or "—"
            row["Legacy rank"] = item.naive_siem_rank or "—"
            row["Rank delta"] = rank_delta_label(delta)
        rows.append(row)
    return rows


def render_queue_table(items: list[ScoredIncident], now: datetime, *, show_ranks: bool) -> None:
    if not items:
        st.info("No incidents match the current filters.")
        return
    frame = queue_rows(items, now, show_ranks=show_ranks)
    order = [
        "Priority",
        "Incident",
        "Affected service/asset",
        "Status",
        "Owner",
        "Age",
        "Risk",
    ]
    if show_ranks:
        order.extend(["AI rank", "Legacy rank", "Rank delta"])
    event = st.dataframe(
        frame,
        width="stretch",
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key=f"queue_table_{st.session_state.get('queue_mode', 'ai')}",
        height=min(640, 52 + 36 * min(len(frame), 16)),
        column_order=order,
        column_config={
            "Priority": st.column_config.TextColumn(
                "Priority",
                help="P0 ≥ 85 · P1 ≥ 70 · P2 ≥ 50 · P3 ≥ 30 · P4 below. Not vendor severity.",
            ),
            "Incident": st.column_config.TextColumn("Incident", width="large"),
            "Age": st.column_config.TextColumn(
                "Age",
                help="Time since first_seen. No SLA deadline is recorded in this snapshot.",
            ),
            "_id": st.column_config.TextColumn("_id", width="small"),
        },
    )
    selected_rows = event.selection.rows if event and event.selection else []
    if not selected_rows:
        return
    incident_id = str(frame[selected_rows[0]]["_id"])
    if st.session_state.pop("ignore_queue_pick", False):
        st.session_state.queue_table_pick = incident_id
        return
    if st.session_state.get("queue_table_pick") == incident_id:
        return
    st.session_state.queue_table_pick = incident_id
    open_case_view(incident_id)


def render_incident_queue(result: PipelineResult, visible: list[ScoredIncident], now: datetime, filters: dict) -> None:
    page_header(
        "Incident queue",
        result,
        lede="Working queue for the current snapshot.",
    )
    metrics = queue_metrics(result)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Open incidents", metrics["open"])
    m2.metric("P0–P1 open", metrics["p0_p1"])
    m3.metric("Unacknowledged", metrics["unacked"])
    m4.metric("Assigned", f"{metrics['assigned']} of {metrics['open']}")
    st.caption(
        filter_summary(
            len(visible),
            result.metrics.incident_count,
            filters["pri_filter"],
            filters["status_filter"],
            filters["env_filter"],
            str(filters["preset"]),
        )
        + " · Age is time since first seen. This snapshot has no SLA deadlines."
    )
    render_featured_cards(visible, now)
    st.subheader("Working queue")
    render_queue_table(visible, now, show_ranks=bool(filters["show_ranks"]))
    if not filters["show_ranks"]:
        st.caption("AI rank, legacy rank, and rank delta live under Detection intelligence, or enable them in More filters.")


def render() -> None:
    result = load_result()
    init_session(result)
    now = snapshot_now(result)
    cards = {card.incident_id: card for card in result.cards}
    by_id = {item.incident.incident_id: item for item in result.risk_ranked}

    with st.sidebar:
        filters = queue_filters()
        demo_admin_controls()

    visible = visible_incidents(
        result,
        str(filters["order"]),
        str(filters["q"] or ""),
        list(filters["pri_filter"]),
        list(filters["status_filter"]),
        list(filters["env_filter"]),
        bool(filters["mine"]),
        bool(filters["hide_closed"]),
        unassigned_critical=bool(filters["unassigned_critical"]),
        production_only=bool(filters["production_only"]),
    )

    if st.session_state.active_case_id:
        render_case_workspace(st.session_state.active_case_id, by_id, cards, now)
    else:
        render_incident_queue(result, visible, now, filters)
