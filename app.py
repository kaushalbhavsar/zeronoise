"""Operational SOC incident queue and investigation workbench."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import plotly.graph_objects as go
import streamlit as st

from config import ALERTS_PATH, CMDB_PATH, IAM_PATH, KILL_CHAIN
from engine.pipeline import run_pipeline
from engine.presentation import (
    context_badges,
    correlation_evidence,
    driver_label,
    driver_rows,
    rank_delta,
    rank_delta_label,
    raw_alert_ids,
)
from engine.schemas import IncidentCard, PipelineResult, ScoredIncident

st.set_page_config(
    page_title="SOC · Incident Queue",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

STATUSES = (
    "New",
    "Acknowledged",
    "Investigating",
    "Escalated",
    "Closed — false positive",
    "Closed — true positive",
)
ASSIGNEES = ("Unassigned", "You", "Analyst-2", "Shift lead")
OPEN_STATUSES = {"New", "Acknowledged", "Investigating", "Escalated"}
PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
SEVERITY_TOKEN = {
    "Critical": "p0",
    "High": "p1",
    "Medium": "p2",
    "Low": "p3",
}

st.markdown(
    """
    <style>
    .stApp { background: #070b12; color: #d7e0ea; }
    .block-container { padding: 0.7rem 1.4rem 1.6rem 1.4rem; max-width: 1800px; }
    h1, h2, h3 { color: #f2f6fb !important; letter-spacing: 0; }
    [data-testid="stMetricLabel"] { color: #8fa2b8 !important; font-size: 0.74rem !important; text-transform: uppercase; }
    [data-testid="stMetricValue"] { color: #f2f6fb !important; font-variant-numeric: tabular-nums; }
    [data-testid="stSidebar"] { background: #0b111a; }
    [data-testid="stHeader"] { background: rgba(7,11,18,0.9); }
    footer { visibility: hidden; }
    .topbar {
        display: flex; justify-content: space-between; align-items: baseline;
        border-bottom: 1px solid #1c2736; padding: 0.15rem 0 0.55rem 0; margin-bottom: 0.7rem;
    }
    .brand { font-size: 0.92rem; font-weight: 650; color: #f2f6fb; }
    .brand span { color: #7d93ab; font-weight: 500; margin-left: 0.55rem; }
    .pri {
        display: inline-block; min-width: 1.85rem; text-align: center;
        font-size: 0.72rem; font-weight: 700; padding: 0.08rem 0.4rem; border-radius: 3px;
        border: 1px solid transparent; letter-spacing: 0.02em;
    }
    .p0 { background: #2a1848; color: #d6c7ff; border-color: #7c3aed; }
    .p1 { background: #4a1515; color: #ff8a8a; border-color: #c43c3c; }
    .p2 { background: #e3b341; color: #1a1406; border-color: #c4921f; }
    .p3 { background: #15202c; color: #c5d2e0; border-color: #2a3b50; }
    .p4 { background: #10161e; color: #8fa2b8; border-color: #1c2736; }
    .chip {
        display: inline-block; font-size: 0.72rem; padding: 0.08rem 0.4rem;
        border: 1px solid #2a3b50; border-radius: 3px; color: #c5d2e0; margin: 0 0.2rem 0.2rem 0;
    }
    .badge {
        display: inline-block; font-size: 0.70rem; padding: 0.10rem 0.42rem;
        border-radius: 3px; margin: 0 0.22rem 0.22rem 0; border: 1px solid #2a3b50;
        color: #d7e0ea;
    }
    .badge.hot { border-color: #8a3a3a; color: #ffb4b4; background: #2a1212; }
    .badge.warn { border-color: #7a5a20; color: #ffd089; background: #2a2010; }
    .badge.ok { border-color: #2a4a3a; color: #b6e0c8; background: #102018; }
    .delta.up { color: #8ee0a8; }
    .delta.down { color: #ff9a9a; }
    .scorebox {
        border: 1px solid #1c2736; border-radius: 6px; padding: 0.55rem 0.7rem;
        background: #0c121b;
    }
    .scorebox .n { font-size: 1.35rem; font-weight: 700; color: #f2f6fb; }
    .scorebox .l { font-size: 0.7rem; color: #8fa2b8; text-transform: uppercase; }
    .funnel {
        display: flex; align-items: stretch; gap: 0.35rem; margin: 0.2rem 0 0.75rem 0;
    }
    .funnel-step {
        flex: 1; border: 1px solid #1c2736; border-radius: 6px; padding: 0.55rem 0.7rem;
        background: #0c121b;
    }
    .funnel-step .n { font-size: 1.45rem; font-weight: 700; color: #f2f6fb; font-variant-numeric: tabular-nums; }
    .funnel-step .l { font-size: 0.7rem; color: #8fa2b8; text-transform: uppercase; letter-spacing: 0.03em; }
    .funnel-arrow { color: #4d6178; display: flex; align-items: center; font-size: 1.1rem; }
    .icard {
        border: 1px solid #1c2736; border-left-width: 4px; border-radius: 6px;
        padding: 0.55rem 0.65rem; background: #0c121b; height: 100%;
    }
    .icard.pri-p0 { border-left-color: #7c3aed; }
    .icard.pri-p1 { border-left-color: #c43c3c; }
    .icard.pri-p2 { border-left-color: #e3b341; }
    .icard.pri-p3, .icard.pri-p4 { border-left-color: #2a3b50; }
    .icard.active { background: #101820; box-shadow: inset 0 0 0 1px #3d6d99; }
    .icard .meta { color: #8fa2b8; font-size: 0.74rem; margin-top: 0.2rem; }
    .icard .ranks { font-variant-numeric: tabular-nums; font-size: 0.78rem; color: #d7e0ea; margin-top: 0.28rem; }
    .case-header {
        position: sticky; top: 3.35rem; z-index: 30;
        border: 1px solid #1c2736; border-left-width: 4px; border-radius: 8px;
        padding: 0.75rem 0.9rem 0.8rem 0.9rem; background: #0b111a;
        margin: 0.35rem 0 0.85rem 0;
    }
    .case-header.pri-p0 { border-left-color: #7c3aed; }
    .case-header.pri-p1 { border-left-color: #c43c3c; }
    .case-header.pri-p2 { border-left-color: #e3b341; }
    .case-header.pri-p3, .case-header.pri-p4 { border-left-color: #2a3b50; }
    .case-title { font-size: 1.05rem; font-weight: 650; color: #f2f6fb; margin: 0.25rem 0 0.2rem 0; }
    .case-meta { color: #8fa2b8; font-size: 0.78rem; }
    .tl-line {
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 0.92rem; padding: 0.28rem 0.55rem; margin: 0.18rem 0;
        border-left: 3px solid #2a3b50; background: #0c121b; border-radius: 0 4px 4px 0;
    }
    .tl-line.p0 { border-left-color: #7c3aed; }
    .tl-line.p1 { border-left-color: #c43c3c; }
    .tl-line.p2 { border-left-color: #e3b341; color: #f2e6c4; }
    .tl-line.p3, .tl-line.p4 { border-left-color: #2a3b50; }
    .tl-late { color: #ffb4b4; }
    .tl-time { color: #8fa2b8; }
    .tl-id { color: #c5d2e0; }
    .tl-tactic { color: #ffd089; }
    .kc { display: flex; gap: 0.28rem; flex-wrap: wrap; margin: 0.45rem 0 0.7rem 0; }
    .kc-step {
        flex: 1 1 6.5rem; text-align: center; font-size: 0.68rem; padding: 0.28rem 0.2rem;
        border: 1px solid #1c2736; border-radius: 4px; color: #6d8094; background: #0c121b;
    }
    .kc-step.on { border-color: #6b2a2a; color: #ffd0d0; background: #2a1212; }
    .sev {
        display: inline-block; font-size: 0.7rem; font-weight: 700;
        padding: 0.04rem 0.35rem; border-radius: 3px; border: 1px solid transparent;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner="Loading incident queue…")
def load_result(cache_version: int = 6) -> PipelineResult:
    if not ALERTS_PATH.exists():
        from data.generate_synthetic_data import write_dataset

        write_dataset()
    return run_pipeline(alerts_path=ALERTS_PATH, cmdb_path=CMDB_PATH, iam_path=IAM_PATH)


def priority(score: float) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    if score >= 30:
        return "P3"
    return "P4"


def pri_class(score: float) -> str:
    return priority(score).lower()


def severity_token(severity: str) -> str:
    return SEVERITY_TOKEN.get(severity, "p4")


def classify(item: ScoredIncident) -> str:
    tactics = set(item.incident.unique_tactics)
    assets = [alert.asset for alert in item.incident.alerts if alert.asset]
    dests = [alert.dest_asset for alert in item.incident.alerts if alert.dest_asset]
    jewel = any(
        asset.data_sensitivity == "crown_jewel_pii_pci" for asset in assets + dests
    )
    if "Exfiltration" in tactics:
        return "Data exfiltration" if jewel else "Outbound transfer"
    if "Impact" in tactics:
        return "Destructive activity"
    if "Lateral Movement" in tactics and "Credential Access" in tactics:
        return "Credential + lateral"
    if item.incident.total_event_count >= 40 and tactics <= {"Initial Access", "Discovery"}:
        return "External scanning"
    if "Credential Access" in tactics:
        return "Credential access"
    if "Initial Access" in tactics:
        return "Initial access"
    if tactics:
        return next(iter(tactics))
    return "Unclassified"


def fmt_age(ts: datetime, now: datetime) -> str:
    minutes = max(0, int((now - ts).total_seconds() // 60))
    if minutes < 60:
        return f"{minutes}m"
    hours, rem = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {rem:02d}m"
    return f"{hours // 24}d"


def fmt_ts(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%H:%M:%SZ")


def env_of(item: ScoredIncident) -> str:
    envs = {
        alert.asset.environment
        for alert in item.incident.alerts
        if alert.asset
    }
    envs |= {
        alert.dest_asset.environment
        for alert in item.incident.alerts
        if alert.dest_asset
    }
    if "prod" in envs:
        return "prod"
    if envs:
        return sorted(envs)[0]
    return "unknown"


def primary_asset(item: ScoredIncident) -> str:
    hosts = item.incident.unique_hosts
    return hosts[0] if hosts else "—"


def primary_user(item: ScoredIncident) -> str:
    users = item.incident.unique_users
    return users[0] if users else "—"


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


def open_case(incident_id: str) -> None:
    st.session_state.active_case_id = incident_id
    st.session_state.selected = incident_id


def back_to_queue() -> None:
    st.session_state.active_case_id = None
    st.session_state.ignore_queue_pick = True
    st.session_state.show_fp_confirm = False


def case(incident_id: str) -> dict:
    return st.session_state.cases[incident_id]


def set_status(incident_id: str, status: str) -> None:
    record = case(incident_id)
    record["status"] = status
    if status == "Investigating" and record["assignee"] == "Unassigned":
        record["assignee"] = "You"


def kill_chain_html(tactics: list[str]) -> str:
    present = set(tactics)
    cells = "".join(
        f"<div class='kc-step {'on' if name in present else ''}'>{name}</div>"
        for name in KILL_CHAIN
    )
    return f"<div class='kc'>{cells}</div>"


def kill_chain_figure(tactics: list[str], *, chart_id: str) -> go.Figure:
    present = set(tactics)
    colors = ["#6b2a2a" if name in present else "#1a2430" for name in KILL_CHAIN]
    fig = go.Figure(
        go.Bar(
            x=list(KILL_CHAIN),
            y=[1] * len(KILL_CHAIN),
            marker_color=colors,
            text=["●" if name in present else "○" for name in KILL_CHAIN],
            textposition="inside",
            hovertext=list(KILL_CHAIN),
            hoverinfo="text",
        )
    )
    fig.update_layout(
        height=110,
        margin=dict(l=0, r=0, t=8, b=32),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c5d2e0", size=11),
        yaxis=dict(visible=False),
        xaxis=dict(tickangle=-28),
        bargap=0.12,
        showlegend=False,
        meta={"chart_id": chart_id},
    )
    return fig


def badge_class(name: str) -> str:
    if name in {"Crown Jewel", "Tier-0 Admin", "Exfiltration", "Impact"}:
        return "hot"
    if name in {"High FP Rule", "Sandbox"}:
        return "warn"
    return "ok"


def render_badges(item: ScoredIncident) -> None:
    chips = "".join(
        f"<span class='badge {badge_class(name)}'>{name}</span>"
        for name in context_badges(item)
    )
    if chips:
        st.markdown(chips, unsafe_allow_html=True)


def driver_chart(card: IncidentCard) -> go.Figure:
    drivers = driver_rows(card)
    fig = go.Figure(
        go.Bar(
            x=[d.contribution_pct for d in drivers],
            y=[driver_label(d.factor) for d in drivers],
            orientation="h",
            marker_color="#3d6d99",
            text=[f"{d.contribution_pct}%" for d in drivers],
            textposition="outside",
        )
    )
    fig.update_layout(
        height=320,
        margin=dict(l=8, r=48, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#d7e0ea", size=13),
        xaxis=dict(
            title="Ablation contribution %",
            range=[0, max(42, max(d.contribution_pct for d in drivers) + 8)],
        ),
        yaxis=dict(autorange="reversed"),
        meta={"chart_id": f"drivers-{card.incident_id}"},
    )
    return fig


def queue_rows(items: list[ScoredIncident], now: datetime) -> list[dict]:
    rows = []
    for item in items:
        record = case(item.incident.incident_id)
        delta = rank_delta(item.risk_rank, item.naive_siem_rank)
        rows.append(
            {
                "Pri": priority(item.risk.risk_score),
                "Incident": item.incident.incident_id,
                "Risk": round(item.risk.risk_score, 1),
                "AI#": item.risk_rank or "—",
                "Legacy#": item.naive_siem_rank or "—",
                "Δ": rank_delta_label(delta),
                "Status": record["status"],
                "Age": fmt_age(item.incident.first_seen, now),
                "Identity": primary_user(item),
                "Asset": primary_asset(item),
                "Class": classify(item),
            }
        )
    return rows


def _format_timeline_line(line: str) -> str:
    head, sep, tail = line.partition(" — ")
    if not sep:
        return line
    if "]" not in head:
        return line
    prefix, tactic = head.rsplit("]", 1)
    prefix = prefix + "]"
    time_part = prefix.split("[")[0].strip()
    id_part = prefix.split("[", 1)[1]
    return (
        f"<span class='tl-time'>{time_part}</span> "
        f"<span class='tl-id'>[{id_part}</span> "
        f"<span class='tl-tactic'>{tactic.strip()}</span> — {tail}"
    )


def render_featured_cards(items: list[ScoredIncident]) -> None:
    top = items[:5]
    if not top:
        return
    cols = st.columns(len(top), gap="small")
    last = st.session_state.get("selected")
    for col, item in zip(cols, top):
        with col:
            delta = rank_delta(item.risk_rank, item.naive_siem_rank)
            chips = "".join(
                f"<span class='badge {badge_class(name)}'>{name}</span>"
                for name in context_badges(item)[:3]
            )
            pri = priority(item.risk.risk_score)
            active = "active" if item.incident.incident_id == last else ""
            st.markdown(
                f"<div class='icard pri-{pri.lower()} {active}'>"
                f"<span class='pri {pri.lower()}'>{pri}</span> "
                f"<strong>{item.incident.incident_id}</strong>"
                f"<div class='meta'>{classify(item)} · risk {item.risk.risk_score:.0f}</div>"
                f"<div class='ranks'>AI #{item.risk_rank or '—'} · Legacy #{item.naive_siem_rank or '—'} · "
                f"<span class='delta {'up' if (delta or 0) > 0 else 'down' if (delta or 0) < 0 else ''}'>"
                f"{rank_delta_label(delta)}</span></div>"
                f"<div class='meta'>{item.incident.total_event_count} raw · "
                f"{len(item.incident.alerts)} deduplicated</div>"
                f"<div style='margin-top:0.28rem'>{chips}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
            if st.button(
                "Open case",
                key=f"feat-{st.session_state.get('queue_mode', 'ai')}-{item.incident.incident_id}",
                use_container_width=True,
            ):
                open_case(item.incident.incident_id)
                st.rerun()


def render_queue_table(items: list[ScoredIncident], now: datetime) -> None:
    if not items:
        st.info("No incidents match the current filters.")
        return
    frame = queue_rows(items, now)
    event = st.dataframe(
        frame,
        width="stretch",
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key=f"queue_table_{st.session_state.get('queue_mode', 'ai')}",
        height=min(640, 52 + 36 * min(len(frame), 16)),
        column_config={
            "Pri": st.column_config.TextColumn("Pri", help="P0 purple · P1 red · P2 amber · P3/P4 neutral"),
        },
    )
    selected_rows = event.selection.rows if event and event.selection else []
    if not selected_rows:
        return
    incident_id = str(frame[selected_rows[0]]["Incident"])
    if st.session_state.pop("ignore_queue_pick", False):
        st.session_state.queue_table_pick = incident_id
        return
    if st.session_state.get("queue_table_pick") == incident_id:
        return
    st.session_state.queue_table_pick = incident_id
    open_case(incident_id)
    st.rerun()


def render_incident_queue(
    result: PipelineResult,
    visible: list[ScoredIncident],
    now: datetime,
    order: str,
) -> None:
    raw_n = result.metrics.raw_alert_count
    dedup_n = result.metrics.deduplicated_alert_count
    inc_n = result.metrics.incident_count
    high_n = result.metrics.high_priority_count
    open_items = [
        item
        for item in result.risk_ranked
        if case(item.incident.incident_id)["status"] in OPEN_STATUSES
    ]
    urgent = sum(
        1 for item in open_items if priority(item.risk.risk_score) in {"P0", "P1"}
    )
    unacked = sum(
        1
        for item in open_items
        if case(item.incident.incident_id)["status"] == "New"
    )
    st.markdown(
        f"<div class='topbar'><div class='brand'>SOC"
        f"<span>Incident queue · {now.strftime('%d %b %H:%M UTC')}</span></div>"
        f"<div class='brand'><span>{len(visible)} shown · {order}</span></div></div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"<div class='funnel'>"
        f"<div class='funnel-step'><div class='n'>{raw_n}</div><div class='l'>Raw alerts</div></div>"
        f"<div class='funnel-arrow'>→</div>"
        f"<div class='funnel-step'><div class='n'>{dedup_n}</div><div class='l'>Deduplicated events</div></div>"
        f"<div class='funnel-arrow'>→</div>"
        f"<div class='funnel-step'><div class='n'>{inc_n}</div><div class='l'>Correlated incidents</div></div>"
        f"<div class='funnel-arrow'>→</div>"
        f"<div class='funnel-step'><div class='n'>{high_n}</div><div class='l'>High-priority incidents</div></div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    f1, f2, f3 = st.columns(3)
    f1.metric("Alert fatigue reduction", f"{result.metrics.fatigue_reduction_pct:.0f}%")
    f1.caption(f"{raw_n} raw alerts → {inc_n} analyst-reviewable incidents")
    f2.metric("Dedup compression", f"{result.metrics.volume_compression_pct:.0f}%")
    f2.caption(f"{raw_n} raw → {dedup_n} after burst collapse")
    f3.metric("Open / P0–P1 / unacked", f"{len(open_items)} / {urgent} / {unacked}")

    st.caption(f"Top of {order}. Cards reorder when the queue mode changes.")
    render_featured_cards(visible)
    st.caption("Full queue — select a row or click Open case.")
    render_queue_table(visible, now)


def render_case_header(item: ScoredIncident, card: IncidentCard, now: datetime) -> None:
    record = case(item.incident.incident_id)
    pri = priority(item.risk.risk_score)
    if st.button("← Back to queue", key="back-to-queue"):
        back_to_queue()
        st.rerun()
    st.markdown(
        f"<div class='case-header pri-{pri.lower()}'>"
        f"<span class='pri {pri.lower()}'>{pri}</span> "
        f"<strong>{item.incident.incident_id}</strong>"
        f"<span class='case-meta'> · {record['status']}</span>"
        f"<div class='case-title'>{item.title}</div>"
        f"<div class='case-meta'>risk {item.risk.risk_score:.0f} · "
        f"age {fmt_age(item.incident.first_seen, now)} · "
        f"{fmt_ts(item.incident.first_seen)} → {fmt_ts(item.incident.last_seen)} · "
        f"{item.incident.total_event_count} raw / {len(item.incident.alerts)} deduplicated</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    render_badges(item)
    actions, owner, destroy = st.columns([1.5, 0.7, 0.9])
    with actions:
        b1, b2, b3 = st.columns([1.15, 1, 1])
        if b1.button("Investigate", type="primary", use_container_width=True):
            set_status(item.incident.incident_id, "Investigating")
            st.rerun()
        if b2.button("Acknowledge", use_container_width=True):
            set_status(item.incident.incident_id, "Acknowledged")
            st.rerun()
        if b3.button("Escalate", use_container_width=True):
            set_status(item.incident.incident_id, "Escalated")
            st.rerun()
    with owner:
        record["assignee"] = st.selectbox(
            "Owner",
            ASSIGNEES,
            index=ASSIGNEES.index(record["assignee"]) if record["assignee"] in ASSIGNEES else 0,
            key=f"owner-{item.incident.incident_id}",
        )
        st.caption(f"Status: {record['status']}")
    with destroy:
        st.caption("Destructive")
        with st.popover("Close as false positive"):
            st.write("This closes the case as a false positive. A reason is required.")
            reason = st.text_area(
                "Reason",
                value=record.get("close_reason") or "",
                key=f"fp-reason-{item.incident.incident_id}",
                height=90,
            )
            if st.button("Confirm close as false positive", key=f"fp-confirm-{item.incident.incident_id}"):
                if not str(reason).strip():
                    st.warning("Enter a reason before closing.")
                else:
                    record["close_reason"] = str(reason).strip()
                    set_status(item.incident.incident_id, "Closed — false positive")
                    st.rerun()
    ai_rank = item.risk_rank or card.priority_rank or card.risk_rank
    legacy_rank = item.naive_siem_rank or card.naive_siem_rank
    delta = rank_delta(ai_rank, legacy_rank)
    delta_cls = "up" if (delta or 0) > 0 else "down" if (delta or 0) < 0 else ""
    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(
        f"<div class='scorebox'><div class='l'>Risk score</div><div class='n'>{item.risk.risk_score:.0f}</div></div>",
        unsafe_allow_html=True,
    )
    m2.markdown(
        f"<div class='scorebox'><div class='l'>AI rank</div><div class='n'>#{ai_rank or '—'}</div></div>",
        unsafe_allow_html=True,
    )
    m3.markdown(
        f"<div class='scorebox'><div class='l'>Legacy rank</div><div class='n'>#{legacy_rank or '—'}</div></div>",
        unsafe_allow_html=True,
    )
    m4.markdown(
        f"<div class='scorebox'><div class='l'>Rank delta</div>"
        f"<div class='n delta {delta_cls}'>{rank_delta_label(delta)}</div></div>",
        unsafe_allow_html=True,
    )


def render_overview_tab(item: ScoredIncident, card: IncidentCard) -> None:
    st.markdown("**Executive summary**")
    st.write(card.executive_summary)
    if card.contrastive_explanation or card.contrastive:
        st.markdown("**Why the legacy SIEM got this wrong**")
        st.write(card.contrastive_explanation or card.contrastive)
    if card.why_not_false_positive:
        st.markdown("**Why this may be real rather than noise**")
        st.write(card.why_not_false_positive)
    left, right = st.columns(2)
    with left:
        st.markdown("**Affected identities**")
        if card.identities:
            st.dataframe(
                [
                    {
                        "User": ident.user_id,
                        "Department": ident.department,
                        "Privilege": ident.privilege_tier,
                    }
                    for ident in card.identities
                ],
                width="stretch",
                hide_index=True,
                key=f"idents-{item.incident.incident_id}",
            )
        else:
            st.write(primary_user(item))
    with right:
        st.markdown("**Affected assets**")
        if card.assets:
            st.dataframe(
                [
                    {
                        "Host": asset.host_id,
                        "Hostname": asset.hostname,
                        "Env": asset.environment,
                        "Data": asset.data_sensitivity,
                        "Crit": asset.business_criticality,
                        "IP": asset.ip_address,
                    }
                    for asset in card.assets
                ],
                width="stretch",
                hide_index=True,
                key=f"assets-{item.incident.incident_id}",
            )
        else:
            st.write(primary_asset(item))
    st.caption(f"Sensors: {', '.join(card.products) or '—'}  ·  Class: {classify(item)}")


def render_timeline_tab(item: ScoredIncident, card: IncidentCard) -> None:
    late = {"Exfiltration", "Impact", "Lateral Movement", "Credential Access"}
    alerts_by_id = {alert.alert_id: alert for alert in item.incident.alerts}
    for line in card.attack_timeline:
        alert = next(
            (alerts_by_id[alert_id] for alert_id in alerts_by_id if f"[{alert_id}]" in line),
            None,
        )
        token = severity_token(alert.severity_raw) if alert else "p4"
        late_cls = "tl-late" if any(tactic in line for tactic in late) else ""
        sev = alert.severity_raw if alert else ""
        st.markdown(
            f"<div class='tl-line {token} {late_cls}'>"
            f"<span class='sev {token}'>{sev}</span> "
            f"{_format_timeline_line(line)}</div>",
            unsafe_allow_html=True,
        )
    st.dataframe(
        [
            {
                "Alert": alert.alert_id,
                "Start": fmt_ts(alert.first_seen or alert.timestamp),
                "End": fmt_ts(alert.last_seen or alert.timestamp),
                "Sensor": alert.source_product,
                "Sev": alert.severity_raw,
                "Tactic": alert.mitre_tactic,
                "Rule": alert.rule_name,
                "Events": alert.event_count,
                "User": alert.entities.user_id or "—",
                "Host": alert.entities.host_id or "—",
            }
            for alert in item.incident.alerts
        ],
        width="stretch",
        hide_index=True,
        key=f"timeline-alerts-{item.incident.incident_id}",
    )


def render_attack_tab(item: ScoredIncident, card: IncidentCard) -> None:
    st.markdown(kill_chain_html(card.tactics), unsafe_allow_html=True)
    st.write(" → ".join(card.tactics) if card.tactics else "No mapped tactics.")
    st.plotly_chart(
        kill_chain_figure(card.tactics, chart_id=f"attack-{item.incident.incident_id}"),
        width="stretch",
        key=f"kill-chain-attack-{item.incident.incident_id}",
    )
    st.markdown("**MITRE techniques**")
    techniques = item.incident.unique_techniques or card.techniques
    if techniques:
        for technique in techniques:
            st.write(f"- {technique}")
    else:
        st.write("No mapped techniques.")


def render_risk_tab(item: ScoredIncident, card: IncidentCard) -> None:
    left, right = st.columns([1.15, 0.85])
    with left:
        st.plotly_chart(
            driver_chart(card),
            width="stretch",
            key=f"risk-drivers-{item.incident.incident_id}",
        )
    with right:
        for driver in driver_rows(card):
            st.write(f"**{driver_label(driver.factor)}** · {driver.contribution_pct}%")
            if driver.evidence:
                st.caption(driver.evidence)
    st.caption(
        f"SIEM rank #{item.naive_siem_rank} uses raw severity×volume only. "
        "It is not used for this queue's default order."
    )


def render_response_tab(item: ScoredIncident, card: IncidentCard) -> None:
    record = case(item.incident.incident_id)
    recommended = card.recommended_actions or card.containment
    if not recommended:
        st.write("No entity-specific actions were generated.")
    for action in recommended:
        checked = action in record["done"]
        if st.checkbox(
            action,
            value=checked,
            key=f"act-{item.incident.incident_id}-{hash(action)}",
        ):
            if action not in record["done"]:
                record["done"].append(action)
        elif action in record["done"]:
            record["done"].remove(action)
    if record.get("close_reason"):
        st.caption(f"FP close reason: {record['close_reason']}")
    record["notes"] = st.text_area(
        "Case notes",
        value=record["notes"],
        height=160,
        key=f"notes-{item.incident.incident_id}",
    )


def render_evidence_tab(item: ScoredIncident, card: IncidentCard) -> None:
    reasons = correlation_evidence(item)
    if reasons:
        st.markdown("**Why were these alerts grouped?**")
        for row in reasons:
            st.write(f"`{row['from']}` → `{row['to']}`")
            st.caption(row["reason"])
    else:
        st.write("Single-alert incident — no inter-alert edges.")
    if card.edges:
        st.dataframe(
            [
                {
                    "From": edge.source_alert_id,
                    "To": edge.target_alert_id,
                    "Link": edge.relationship_type,
                    "Δ min": edge.time_delta_minutes,
                    "Strength": edge.correlation_strength,
                }
                for edge in card.edges
            ],
            width="stretch",
            hide_index=True,
            key=f"evidence-edges-{item.incident.incident_id}",
        )
    originals = raw_alert_ids(item)
    st.markdown("**Raw alert references**")
    st.caption(
        f"{len(originals)} raw alert IDs collapsed into "
        f"{len(item.incident.alerts)} deduplicated events"
    )
    ev1, ev2 = st.columns(2)
    with ev1:
        st.markdown("**Source events**")
        st.code("\n".join(originals[:80]) + ("\n…" if len(originals) > 80 else "") or "—")
    with ev2:
        st.markdown("**Deduplicated survivors**")
        st.code("\n".join(card.alert_ids) or "—")


def render_case_workspace(
    incident_id: str,
    by_id: dict[str, ScoredIncident],
    cards: dict[str, IncidentCard],
    now: datetime,
) -> None:
    item = by_id.get(incident_id)
    card = cards.get(incident_id)
    if item is None or card is None:
        st.error("That incident is no longer in the current queue.")
        if st.button("← Back to queue", key="back-missing"):
            back_to_queue()
            st.rerun()
        return
    render_case_header(item, card, now)
    case_tabs = st.tabs(
        ["Overview", "Timeline", "ATT&CK", "Risk", "Response", "Evidence"]
    )
    tab_renderers = (
        render_overview_tab,
        render_timeline_tab,
        render_attack_tab,
        render_risk_tab,
        render_response_tab,
        render_evidence_tab,
    )
    for tab, renderer in zip(case_tabs, tab_renderers):
        with tab:
            renderer(item, card)


def visible_incidents(
    result: PipelineResult,
    order: str,
    q: str,
    pri_filter: list[str],
    status_filter: list[str],
    env_filter: list[str],
    mine: bool,
    hide_closed: bool,
) -> list[ScoredIncident]:
    ordered = result.risk_ranked if order.startswith("AI") else result.legacy_ranked
    visible: list[ScoredIncident] = []
    for item in ordered:
        record = case(item.incident.incident_id)
        pri = priority(item.risk.risk_score)
        if pri not in pri_filter:
            continue
        if record["status"] not in status_filter:
            continue
        if hide_closed and record["status"] not in OPEN_STATUSES:
            continue
        if env_filter and env_of(item) not in env_filter:
            continue
        if mine and record["assignee"] != "You":
            continue
        blob = " ".join(
            [
                item.incident.incident_id,
                item.title,
                classify(item),
                primary_user(item),
                primary_asset(item),
                " ".join(item.incident.unique_tactics),
            ]
        ).lower()
        if q and q.lower() not in blob:
            continue
        visible.append(item)
    return visible


def main() -> None:
    result = load_result()
    init_session(result)
    cards = {card.incident_id: card for card in result.cards}
    by_id = {item.incident.incident_id: item for item in result.risk_ranked}
    now = max(item.incident.last_seen for item in result.risk_ranked) + timedelta(minutes=12)

    with st.sidebar:
        st.markdown("**Shift console**")
        st.caption(now.strftime("%Y-%m-%d %H:%M UTC"))
        order = st.radio(
            "Queue order",
            ("AI Risk-Based Triage", "Legacy SIEM Triage"),
            horizontal=False,
            key="queue_order",
        )
        st.session_state.queue_mode = "ai" if order.startswith("AI") else "legacy"
        q = st.text_input("Search", placeholder="INC, user, host, class", key="queue_search")
        pri_filter = st.multiselect(
            "Priority",
            list(PRIORITIES),
            default=list(PRIORITIES),
            key="queue_priority",
        )
        status_filter = st.multiselect(
            "Status",
            list(STATUSES),
            default=list(OPEN_STATUSES),
            key="queue_status",
        )
        env_filter = st.multiselect(
            "Environment",
            ["prod", "staging", "dev", "sandbox", "unknown"],
            key="queue_env",
        )
        mine = st.checkbox("Assigned to me", value=False, key="queue_mine")
        hide_closed = st.checkbox("Hide closed", value=True, key="queue_hide_closed")
        if st.button("Reset case state"):
            del st.session_state.cases
            st.rerun()

    visible = visible_incidents(
        result, order, q, pri_filter, status_filter, env_filter, mine, hide_closed
    )

    if st.session_state.active_case_id:
        render_case_workspace(st.session_state.active_case_id, by_id, cards, now)
    else:
        render_incident_queue(result, visible, now, order)


if __name__ == "__main__":
    main()
