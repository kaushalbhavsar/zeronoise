"""Incident queue — dense operational board for SOC analysts."""

from __future__ import annotations

import html
from datetime import datetime

import streamlit as st

from console.case import render_case_workspace
from console.common import (
    display,
    empty_state,
    filter_summary,
    owner_of,
    page_header,
    queue_filters,
    queue_metrics,
    render_load_error,
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
from engine.queue_view import (
    RankingMode,
    SortKey,
    build_queue_row,
    compression_label,
    compression_tooltip,
    default_sort_key,
    display_asset,
    display_owner,
    format_rank_cell,
    rank_tooltip,
    row_aria_label,
    sort_queue_rows,
)
from engine.schemas import IncidentCard, PipelineResult, ScoredIncident


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _ranking_mode(order: str) -> RankingMode:
    return "legacy" if "Legacy" in order or order.startswith("Legacy") else "zeronoise"


def _risk_band_label(score: float) -> str:
    if score >= 85:
        return "Critical risk"
    if score >= 70:
        return "High risk"
    if score >= 50:
        return "Elevated"
    if score >= 30:
        return "Moderate"
    return "Low"


def _delta_html(delta: int | None) -> str:
    if delta is None or delta == 0:
        return '<span class="flat">—</span>'
    if delta > 0:
        return f'<span class="up">↑{delta}</span>'
    return f'<span class="down">↓{abs(delta)}</span>'


def _status_display(status: str) -> str:
    mapping = {
        "Closed — false positive": "Suppressed",
        "Closed — true positive": "Resolved",
    }
    return mapping.get(status, status)


def build_board_rows(
    items: list[ScoredIncident],
    now: datetime,
    cards: dict[str, IncidentCard],
) -> list:
    rows = []
    for item in items:
        rows.append(
            build_queue_row(
                item,
                now,
                status=status_of(item),
                owner=owner_of(item),
                card=cards.get(item.incident.incident_id),
            )
        )
    return rows


def render_summary_bar(result: PipelineResult, metrics: dict) -> None:
    st.markdown(
        "<div class='zn-summary-bar'>"
        f"<span><strong>{metrics['open']}</strong> Active Incidents</span>"
        f"<span><strong>{metrics['p0_p1']}</strong> High Priority</span>"
        f"<span><strong>{result.metrics.raw_alert_count}</strong> Raw Alerts</span>"
        f"<span><strong>{result.metrics.deduplicated_alert_count}</strong> Correlated Signals</span>"
        f"<span><strong>{result.metrics.fatigue_reduction_pct:.0f}%</strong> Noise Reduction</span>"
        "</div>",
        unsafe_allow_html=True,
    )


def render_board_toolbar(mode: RankingMode) -> SortKey:
    mode_label = "ZERO NOISE" if mode == "zeronoise" else "LEGACY SIEM"
    mode_class = "mode" if mode == "zeronoise" else "mode legacy"
    left, right = st.columns([2.2, 1.4])
    with left:
        st.markdown(
            "<div class='zn-board-chrome'>"
            "<div class='title'>Incident queue</div>"
            f"<div class='{mode_class}'>{mode_label}</div>"
            "</div>",
            unsafe_allow_html=True,
        )
    with right:
        sort_labels = {
            "zeronoise_rank": "ZeroNoise Rank",
            "legacy_rank": "Legacy Rank",
            "rank_delta": "Rank Delta",
            "risk_score": "Risk Score",
            "age": "Age",
            "priority": "Priority",
            "status": "Status",
            "owner": "Owner",
        }
        default = default_sort_key(mode)
        options = list(sort_labels.keys())
        # Prefer default for the active ranking mode when session has no choice yet.
        if "queue_sort_key" not in st.session_state:
            st.session_state.queue_sort_key = default
        # When mode flips, snap sort to that mode's default if still on the other rank key.
        prev_mode = st.session_state.get("queue_sort_mode")
        if prev_mode != mode:
            current = st.session_state.get("queue_sort_key", default)
            if current in {"zeronoise_rank", "legacy_rank"}:
                st.session_state.queue_sort_key = default
            st.session_state.queue_sort_mode = mode
        chosen = st.selectbox(
            "Sort",
            options,
            format_func=lambda key: sort_labels[key],
            key="queue_sort_key",
            label_visibility="collapsed",
            help="Default is ZeroNoise Rank ascending. Not vendor severity.",
        )
    return chosen  # type: ignore[return-value]


def _strip_html(row, *, mode: RankingMode, selected: bool, expanded: bool) -> str:
    pri = row.priority.lower()
    risk = f"{row.risk_score:.0f}"
    risk_sub = _risk_band_label(row.risk_score)
    if mode == "zeronoise":
        rank_core = f"#{row.zeronoise_rank}" if row.zeronoise_rank else "—"
        rank_move = _delta_html(row.rank_delta)
        rank_html = f'{_esc(rank_core)} {rank_move}'
    else:
        rank_html = _esc(format_rank_cell(
            mode=mode,
            zeronoise_rank=row.zeronoise_rank,
            legacy_rank=row.legacy_rank,
            delta=row.rank_delta,
        ))
    title = display(row.title)
    engine = display(row.engine_title)
    asset = display(display_asset(row.primary_asset))
    asset_full = display(row.primary_asset_full or display_asset(row.primary_asset))
    owner = display(display_owner(row.owner))
    status = _status_display(row.status)
    owner_class = "zn-owner unassigned" if display_owner(row.owner) == "Unassigned" else "zn-owner"
    status_class = "zn-status"
    sensors = "".join(f"<span class='zn-sensor'>{_esc(s)}</span>" for s in row.sensors) or "—"
    stage = row.latest_attack_stage or "—"
    stage_class = f"zn-stage {(row.latest_attack_stage or '').lower()}"
    stage_title = row.latest_attack_stage_full or "No observed stage"
    tag = f"<div class='zn-asset-tag'>{_esc(row.asset_tag)}</div>" if row.asset_tag else ""
    active = "active" if selected else ""
    aria = _esc(row_aria_label(row, mode=mode))
    tip_rank = _esc(rank_tooltip(row.zeronoise_rank, row.legacy_rank))
    tip_comp = _esc(compression_tooltip(row.raw_alert_count, row.deduplicated_event_count))
    tip_risk = _esc("Risk score 0–100 from fidelity × progression × blast. Not vendor severity or confidence %.")
    tip_asset = _esc(asset_full)
    comp = _esc(compression_label(row.raw_alert_count, row.deduplicated_event_count))
    preview = ""
    if expanded:
        preview = (
            "<div class='zn-preview'>"
            f"<div class='path'>{_esc(row.attack_path)}</div>"
            f"<div><strong>Why #{row.zeronoise_rank or '—'}:</strong> {_esc(row.why_high)}</div>"
            f"<div><strong>Next:</strong> {_esc(row.next_action)}</div>"
            f"<div><strong>Identity:</strong> {_esc(row.top_identity or '—')}</div>"
            "</div>"
        )
    # Mobile two-line helpers live inside the same grid cells; CSS reflows under 960px.
    mobile_line1 = (
        f"<div class='zn-mobile-primary'>"
        f"<span class='pri-rail {pri}'>{_esc(row.priority)}</span> "
        f"<span class='zn-risk'>{_esc(risk)}</span> "
        f"<span class='zn-rank'>{rank_html}</span> "
        f"<span class='zn-inc-title'>{_esc(title)}</span>"
        f"</div>"
    )
    mobile_line2 = (
        f"<div class='zn-mobile-secondary'>"
        f"{_esc(asset)} · {_esc(stage)} · {_esc(status)} · {_esc(row.age)}"
        f"</div>"
    )
    return (
        f"<a class='zn-strip pri-{pri} {active}' href='?case={_esc(row.incident_id)}' "
        f"role='row' aria-label='{aria}' title='Open {_esc(title)}'>"
        f"{mobile_line1}{mobile_line2}"
        f"<div class='pri-rail {pri} zn-desk'>{_esc(row.priority)}</div>"
        f"<div class='zn-desk' title='{tip_risk}'><div class='zn-risk'>{_esc(risk)}</div>"
        f"<div class='zn-risk-sub'>{_esc(risk_sub)}</div></div>"
        f"<div class='zn-rank zn-desk' title='{tip_rank}'>{rank_html}</div>"
        f"<div class='zn-desk'><div class='zn-inc-title' title='{_esc(engine)}'>{_esc(title)}</div>"
        f"<div class='zn-inc-sub'>{_esc(engine)}</div></div>"
        f"<div class='zn-desk' title='{tip_asset}'><div class='zn-asset'>{_esc(asset)}</div>{tag}</div>"
        f"<div class='{stage_class} zn-desk' title='{_esc(stage_title)}'>{_esc(stage)}</div>"
        f"<div class='zn-age col-age zn-desk'>{_esc(row.age)}</div>"
        f"<div class='zn-sensors col-sensors zn-desk'>{sensors}</div>"
        f"<div class='zn-comp col-comp zn-desk' title='{tip_comp}'>{comp}</div>"
        f"<div class='zn-desk'><span class='{status_class}'>{_esc(status)}</span></div>"
        f"<div class='{owner_class} col-owner zn-desk'>{_esc(owner)}</div>"
        f"<div class='zn-open-affordance col-open zn-desk' aria-hidden='true'>›</div>"
        f"{preview}"
        f"</a>"
    )


def render_board_header() -> str:
    cols = [
        ("PRI", ""),
        ("RISK", "Risk score 0–100. Not vendor severity or confidence."),
        ("RANK", "ZeroNoise rank and movement vs legacy SIEM."),
        ("INCIDENT", ""),
        ("ASSET", "Primary affected asset"),
        ("STAGE", "Most consequential observed ATT&CK stage"),
        ("AGE", "Time since first_seen"),
        ("SENSORS", "Distinct contributing sensors"),
        ("ALERTS", "Raw alerts → deduplicated/correlated events"),
        ("STATUS", ""),
        ("OWNER", ""),
        ("", ""),
    ]
    cells = []
    class_for = {
        "AGE": "col-age",
        "SENSORS": "col-sensors",
        "ALERTS": "col-comp",
        "OWNER": "col-owner",
    }
    for label, tip in cols:
        cls = class_for.get(label, "")
        title = f" title='{_esc(tip)}'" if tip else ""
        cells.append(f"<div class='{cls}'{title}>{_esc(label)}</div>")
    return f"<div class='zn-board-head' role='row'>{''.join(cells)}</div>"


def render_incident_board(
    items: list[ScoredIncident],
    now: datetime,
    *,
    mode: RankingMode,
    sort_key: SortKey,
    cards: dict[str, IncidentCard],
) -> None:
    if not items:
        empty_state("no_matches", action="Clear search or choose All open to see the organization-wide queue.")
        return

    rows = build_board_rows(items, now, cards)
    ascending = sort_key not in {"risk_score"}  # risk: default high→low feels natural for SOC
    if sort_key == "risk_score":
        ascending = False
    elif sort_key == "rank_delta":
        ascending = False  # largest promotion first
    ordered = sort_queue_rows(rows, sort_key, ascending=ascending)

    selected = st.session_state.get("selected")
    expanded_id = st.session_state.get("queue_expanded_id")

    strips = [
        _strip_html(
            row,
            mode=mode,
            selected=row.incident_id == selected,
            expanded=row.incident_id == expanded_id,
        )
        for row in ordered
    ]
    board = (
        "<div class='zn-board' role='table' aria-label='ZeroNoise incident queue'>"
        "<div class='zn-board-scroll'>"
        f"{render_board_header()}"
        f"{''.join(strips)}"
        "</div></div>"
    )
    st.markdown(board, unsafe_allow_html=True)

    # Keyboard / non-link fallback: compact open control for accessibility tooling
    # that does not follow markdown anchors inside Streamlit.
    labels = {
        row.incident_id: f"{row.priority} · {row.title} · {display_asset(row.primary_asset)}"
        for row in ordered
    }
    ids = [row.incident_id for row in ordered]
    if st.session_state.get("queue_focus_id") not in ids:
        st.session_state.queue_focus_id = ids[0]
    pick_col, open_col, expand_col = st.columns([3.2, 1, 1])
    with pick_col:
        choice = st.selectbox(
            "Focus incident",
            ids,
            format_func=lambda i: labels[i],
            key="queue_focus_id",
            label_visibility="collapsed",
        )
    with open_col:
        if st.button("Open", type="primary", use_container_width=True, key="queue-open-focus"):
            open_case_view(choice)
    with expand_col:
        if st.button("Preview", use_container_width=True, key="queue-expand-focus"):
            if st.session_state.get("queue_expanded_id") == choice:
                st.session_state.queue_expanded_id = None
            else:
                st.session_state.queue_expanded_id = choice
            st.rerun()
    st.caption("Select a strip or use Open. Entire row opens the investigation workspace.")


def render_incident_queue(
    result: PipelineResult,
    visible: list[ScoredIncident],
    now: datetime,
    filters: dict,
    cards: dict[str, IncidentCard],
) -> None:
    page_header(
        "Incident queue",
        result,
        lede="Working queue for the current snapshot.",
    )
    metrics = queue_metrics(result)
    render_summary_bar(result, metrics)
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
    mode = _ranking_mode(str(filters["order"]))
    sort_key = render_board_toolbar(mode)
    render_incident_board(
        visible,
        now,
        mode=mode,
        sort_key=sort_key,
        cards=cards,
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
        st.caption("Order follows the selected ranking mode. Status changes do not reshuffle ranks.")

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
        stage_filter=list(filters.get("stage_filter") or []),
        sensor_filter=list(filters.get("sensor_filter") or []),
        owner_filter=list(filters.get("owner_filter") or []),
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
        render_incident_queue(result, visible, now, filters, cards)
