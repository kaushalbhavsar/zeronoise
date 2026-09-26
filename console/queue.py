"""Incident queue — operational workspace for analysts."""

from __future__ import annotations

from datetime import datetime

import streamlit as st

from console.case import render_case_workspace
from console.common import (
    defined_metric,
    display,
    empty_state,
    filter_summary,
    fmt_age,
    heading,
    human_title,
    owner_of,
    page_header,
    primary_asset,
    priority,
    queue_filters,
    queue_metrics,
    render_load_error,
    render_priority_card,
    session_chrome,
    status_of,
    visible_incidents,
)
from console.state import (
    init_session,
    load_result_or_error,
    open_case_view,
    snapshot_now,
)
from engine.presentation import rank_delta, rank_delta_label
from engine.schemas import PipelineResult, ScoredIncident


def _featured(items: list[ScoredIncident]) -> list[ScoredIncident]:
    urgent = [item for item in items if priority(item.risk.risk_score) in {"P0", "P1"}]
    picked = (urgent or items)[:2]
    return picked


def _frozen_featured(items: list[ScoredIncident], signature: tuple) -> list[ScoredIncident]:
    by_id = {item.incident.incident_id: item for item in items}
    if st.session_state.get("featured_sig") != signature:
        st.session_state.featured_ids = [item.incident.incident_id for item in _featured(items)]
        st.session_state.featured_sig = signature
    frozen = [by_id[item_id] for item_id in st.session_state.get("featured_ids", []) if item_id in by_id]
    return frozen or _featured(items)


def render_featured_cards(items: list[ScoredIncident], now: datetime, signature: tuple) -> list[ScoredIncident]:
    top = _frozen_featured(items, signature)
    if not top:
        return []
    heading("Take next")
    cols = st.columns(len(top), gap="medium")
    mode = st.session_state.get("queue_mode", "ai")
    for col, item in zip(cols, top):
        with col:
            render_priority_card(item, now, key_prefix=f"feat-{mode}")
    return top


def queue_rows(items: list[ScoredIncident], now: datetime, *, show_ranks: bool) -> list[dict]:
    rows = []
    for item in items:
        delta = rank_delta(item.risk_rank, item.naive_siem_rank)
        row = {
            "_id": item.incident.incident_id,
            "Priority": priority(item.risk.risk_score),
            "Incident": display(human_title(item), item),
            "Affected service/asset": display(primary_asset(item), item),
            "Status": status_of(item),
            "Owner": owner_of(item),
            "Age / Risk": f"{fmt_age(item.incident.first_seen, now)} · {item.risk.risk_score:.0f}",
        }
        if show_ranks:
            row["AI rank"] = item.risk_rank or "—"
            row["Legacy rank"] = item.naive_siem_rank or "—"
            row["Rank delta"] = rank_delta_label(delta)
        rows.append(row)
    return rows


def render_queue_table(
    items: list[ScoredIncident],
    now: datetime,
    *,
    show_ranks: bool,
    has_featured: bool = False,
) -> None:
    if not items:
        if has_featured:
            st.caption("Matching high-priority cases are on the cards above.")
        else:
            empty_state("no_matches", action="Clear search or choose All open to see the organization-wide queue.")
        return
    frame = queue_rows(items, now, show_ranks=show_ranks)
    order = [
        "Priority",
        "Incident",
        "Affected service/asset",
        "Status",
        "Owner",
        "Age / Risk",
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
            "Age / Risk": st.column_config.TextColumn(
                "Age / Risk",
                help="Age is time since first_seen. Risk is 0–100, not vendor severity or confidence. No SLA is recorded.",
            ),
            "_id": None,
        },
    )
    selected_rows = event.selection.rows if event and event.selection else []
    incident_id = str(frame[selected_rows[0]]["_id"]) if selected_rows else None
    if st.session_state.pop("ignore_queue_pick", False):
        incident_id = None
    if incident_id:
        st.session_state.queue_table_pick = incident_id
        st.session_state.selected = incident_id
    open_col, hint = st.columns([1, 2.4])
    with open_col:
        if st.button("Open selected case", disabled=not incident_id, key="open-selected-case"):
            open_case_view(incident_id)
    with hint:
        if incident_id:
            st.caption(f"Selected {display(incident_id)}")
        else:
            st.caption("Select a row, then open it. Featured cases stay on the cards above.")


def render_incident_queue(result: PipelineResult, visible: list[ScoredIncident], now: datetime, filters: dict) -> None:
    page_header(
        "Incident queue",
        result,
        lede="Working queue for the current snapshot.",
    )
    metrics = queue_metrics(result)
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        defined_metric("open", "Open incidents", metrics["open"])
    with m2:
        defined_metric("p0_p1", "P0–P1 open", metrics["p0_p1"])
    with m3:
        defined_metric("unacked", "Unacknowledged", metrics["unacked"])
    with m4:
        defined_metric("assigned", "Assigned", f"{metrics['assigned']} of {metrics['open']}")
    with m5:
        defined_metric("matching", "Matching filters", len(visible))
    st.caption(
        filter_summary(
            len(visible),
            result.metrics.incident_count,
            filters["pri_filter"],
            filters["status_filter"],
            filters["env_filter"],
            str(filters["preset"]),
        )
    )
    signature = (
        str(filters["preset"]),
        str(filters["order"]),
        str(filters["q"] or ""),
        tuple(filters["pri_filter"]),
        tuple(filters["status_filter"]),
        tuple(filters["env_filter"]),
        bool(filters["mine"]),
        bool(filters["unassigned_critical"]),
        bool(filters["production_only"]),
    )
    featured = render_featured_cards(visible, now, signature)
    featured_ids = {item.incident.incident_id for item in featured}
    table_items = [item for item in visible if item.incident.incident_id not in featured_ids]
    heading("Working queue")
    render_queue_table(
        table_items,
        now,
        show_ranks=bool(filters["show_ranks"]),
        has_featured=bool(featured),
    )


def render() -> None:
    result, error = load_result_or_error()
    if result is None:
        render_load_error(error or "Unknown load failure")
        return
    init_session(result)
    now = snapshot_now(result)
    cards = {card.incident_id: card for card in result.cards}
    by_id = {item.incident.incident_id: item for item in result.risk_ranked}

    with st.sidebar:
        filters = queue_filters()
        session_chrome()
        st.caption("Order is fixed to the selected ranking. Status changes do not reshuffle ranks.")

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

    missing = st.session_state.pop("deep_link_missing", None)
    if missing and not st.session_state.active_case_id:
        empty_state("missing_case", action="Remove the case query parameter or open a case from the queue.")
        st.caption(f"Requested id: {missing}")

    if not result.risk_ranked:
        empty_state("no_incidents", action="Regenerate the demo dataset.")
        return

    if st.session_state.active_case_id:
        render_case_workspace(st.session_state.active_case_id, by_id, cards, now)
    else:
        render_incident_queue(result, visible, now, filters)
