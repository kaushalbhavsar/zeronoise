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

st.markdown(
    """
    <style>
    .stApp { background: #070b12; color: #d7e0ea; }
    .block-container { padding: 0.7rem 1.2rem 1.4rem 1.2rem; max-width: 1600px; }
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
        display: inline-block; min-width: 1.7rem; text-align: center;
        font-size: 0.72rem; font-weight: 700; padding: 0.08rem 0.35rem; border-radius: 3px;
    }
    .p1 { background: #4a1515; color: #ff8a8a; }
    .p2 { background: #3d2a10; color: #ffc46b; }
    .p3 { background: #2b2a12; color: #e6de7a; }
    .p4 { background: #15202c; color: #8fa2b8; }
    .chip {
        display: inline-block; font-size: 0.72rem; padding: 0.08rem 0.4rem;
        border: 1px solid #2a3b50; border-radius: 3px; color: #c5d2e0; margin: 0 0.2rem 0.2rem 0;
    }
    .chip.on { border-color: #c45c5c; color: #ffd0d0; background: #2a1414; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner="Loading incident queue…")
def load_result() -> PipelineResult:
    if not ALERTS_PATH.exists():
        from data.generate_synthetic_data import write_dataset

        write_dataset()
    return run_pipeline(alerts_path=ALERTS_PATH, cmdb_path=CMDB_PATH, iam_path=IAM_PATH)


def priority(score: float) -> str:
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    if score >= 30:
        return "P3"
    return "P4"


def pri_class(score: float) -> str:
    return priority(score).lower()


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


def init_cases(result: PipelineResult) -> None:
    if "cases" not in st.session_state:
        st.session_state.cases = {
            item.incident.incident_id: {
                "status": "New",
                "assignee": "Unassigned",
                "notes": "",
                "done": [],
            }
            for item in result.risk_ranked
        }
    if "selected" not in st.session_state:
        st.session_state.selected = result.risk_ranked[0].incident.incident_id


def case(incident_id: str) -> dict:
    return st.session_state.cases[incident_id]


def set_status(incident_id: str, status: str) -> None:
    record = case(incident_id)
    record["status"] = status
    if status == "Investigating" and record["assignee"] == "Unassigned":
        record["assignee"] = "You"


def kill_chain_figure(tactics: list[str]) -> go.Figure:
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
        height=90,
        margin=dict(l=0, r=0, t=4, b=28),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c5d2e0", size=10),
        yaxis=dict(visible=False),
        xaxis=dict(tickangle=-28),
        bargap=0.12,
        showlegend=False,
    )
    return fig


def driver_chart(card: IncidentCard) -> go.Figure:
    drivers = [d for d in card.risk.drivers if d.name != "noise_discount"]
    fig = go.Figure(
        go.Bar(
            x=[d.contribution_pct for d in drivers],
            y=[d.name.replace("_", " ") for d in drivers],
            orientation="h",
            marker_color="#3d6d99",
            text=[f"{d.contribution_pct:.1f}%" for d in drivers],
            textposition="outside",
        )
    )
    fig.update_layout(
        height=280,
        margin=dict(l=8, r=36, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#d7e0ea", size=12),
        xaxis=dict(
            title="Contribution %",
            range=[0, max(42, max(d.contribution_pct for d in drivers) + 8)],
        ),
        yaxis=dict(autorange="reversed"),
    )
    return fig


def queue_rows(
    items: list[ScoredIncident],
    now: datetime,
) -> list[dict]:
    rows = []
    for item in items:
        record = case(item.incident.incident_id)
        rows.append(
            {
                "Pri": priority(item.risk.risk_score),
                "Incident": item.incident.incident_id,
                "Risk": round(item.risk.risk_score, 1),
                "SIEM#": item.naive_siem_rank or "—",
                "Status": record["status"],
                "Age": fmt_age(item.incident.first_seen, now),
                "Last": fmt_ts(item.incident.last_seen),
                "Identity": primary_user(item),
                "Asset": primary_asset(item),
                "Env": env_of(item),
                "Class": classify(item),
                "Owner": record["assignee"],
            }
        )
    return rows


def render_queue(items: list[ScoredIncident], now: datetime) -> str | None:
    if not items:
        st.info("No incidents match the current filters.")
        return None
    frame = queue_rows(items, now)
    event = st.dataframe(
        frame,
        width="stretch",
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="queue_table",
        height=min(560, 46 + 36 * len(frame)),
    )
    selected_rows = event.selection.rows if event and event.selection else []
    if selected_rows:
        return frame[selected_rows[0]]["Incident"]
    if st.session_state.selected in {row["Incident"] for row in frame}:
        return st.session_state.selected
    return frame[0]["Incident"]


def render_workbench(item: ScoredIncident, card: IncidentCard, now: datetime) -> None:
    record = case(item.incident.incident_id)
    pri = priority(item.risk.risk_score)
    head_l, head_r = st.columns([1.35, 0.65])
    with head_l:
        st.markdown(
            f"<span class='pri {pri_class(item.risk.risk_score)}'>{pri}</span> "
            f"<strong>{item.incident.incident_id}</strong> · risk {item.risk.risk_score:.1f} · "
            f"SIEM #{item.naive_siem_rank} · {record['status']}",
            unsafe_allow_html=True,
        )
        st.markdown(f"**{item.title}**")
        st.caption(
            f"{fmt_ts(item.incident.first_seen)} → {fmt_ts(item.incident.last_seen)}  ·  "
            f"age {fmt_age(item.incident.first_seen, now)}  ·  "
            f"{item.incident.total_event_count} raw events  ·  "
            f"{len(item.incident.alerts)} correlated alerts  ·  "
            f"{env_of(item)}"
        )
    with head_r:
        a1, a2, a3, a4 = st.columns(4)
        if a1.button("Ack", use_container_width=True):
            set_status(item.incident.incident_id, "Acknowledged")
        if a2.button("Investigate", use_container_width=True):
            set_status(item.incident.incident_id, "Investigating")
        if a3.button("Escalate", use_container_width=True):
            set_status(item.incident.incident_id, "Escalated")
        if a4.button("Close FP", use_container_width=True):
            set_status(item.incident.incident_id, "Closed — false positive")
        record["assignee"] = st.selectbox(
            "Owner",
            ASSIGNEES,
            index=ASSIGNEES.index(record["assignee"]) if record["assignee"] in ASSIGNEES else 0,
            key=f"owner-{item.incident.incident_id}",
        )
        record["status"] = st.selectbox(
            "Status",
            STATUSES,
            index=STATUSES.index(record["status"]),
            key=f"status-{item.incident.incident_id}",
        )

    overview, timeline, attack, risk, response, evidence = st.tabs(
        ["Overview", "Timeline", "ATT&CK", "Risk", "Response", "Evidence"]
    )

    with overview:
        st.write(card.executive_summary)
        e1, e2, e3 = st.columns(3)
        with e1:
            st.markdown("**Identities**")
            if card.identities:
                for ident in card.identities:
                    st.write(
                        f"{ident.user_id} · {ident.department} · {ident.privilege_tier}"
                    )
            else:
                st.write(primary_user(item))
        with e2:
            st.markdown("**Assets**")
            if card.assets:
                for asset in card.assets:
                    st.write(
                        f"{asset.hostname} · {asset.environment} · "
                        f"{asset.data_sensitivity} · crit {asset.business_criticality}"
                    )
            else:
                st.write(primary_asset(item))
        with e3:
            st.markdown("**Sensors**")
            st.write(", ".join(card.products) or "—")
            st.markdown("**Class**")
            st.write(classify(item))
        if card.contrastive and item.naive_siem_rank and item.naive_siem_rank <= 3:
            st.caption(
                "SIEM would surface this on volume/severity. Confirm business impact before paging."
            )
        elif card.contrastive and (card.risk_rank or 99) <= 2:
            st.caption(card.contrastive)

    with timeline:
        rows = [
            {
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
        ]
        st.dataframe(rows, width="stretch", hide_index=True)

    with attack:
        st.plotly_chart(kill_chain_figure(card.tactics), width="stretch")
        st.write(" → ".join(card.tactics) if card.tactics else "No mapped tactics.")
        st.markdown("**Techniques**")
        for technique in item.incident.unique_techniques:
            st.write(f"- {technique}")

    with risk:
        left, right = st.columns([1.1, 0.9])
        with left:
            st.plotly_chart(driver_chart(card), width="stretch")
        with right:
            st.markdown("**Why this priority**")
            for driver in card.risk.drivers:
                if driver.name == "noise_discount" and driver.score < 0.05:
                    continue
                st.write(
                    f"**{driver.name.replace('_', ' ')}** · {driver.contribution_pct:.1f}%"
                )
                for line in driver.evidence[:2]:
                    st.caption(line)
        st.caption(
            f"SIEM rank #{item.naive_siem_rank} uses raw severity×volume only. "
            "It is not used for this queue's default order."
        )

    with response:
        st.markdown("**Recommended containment**")
        for action in card.containment:
            checked = action in record["done"]
            if st.checkbox(action, value=checked, key=f"act-{item.incident.incident_id}-{hash(action)}"):
                if action not in record["done"]:
                    record["done"].append(action)
            elif action in record["done"]:
                record["done"].remove(action)
        record["notes"] = st.text_area(
            "Case notes",
            value=record["notes"],
            height=140,
            key=f"notes-{item.incident.incident_id}",
        )

    with evidence:
        ev1, ev2 = st.columns(2)
        with ev1:
            st.markdown("**Correlated alerts**")
            st.code("\n".join(card.alert_ids) or "—")
        with ev2:
            st.markdown("**Source events**")
            originals = []
            for alert in item.incident.alerts:
                originals.extend(alert.original_alert_ids or alert.member_alert_ids or [alert.alert_id])
            st.caption(f"{len(originals)} raw alert IDs after burst collapse")
            st.code("\n".join(originals[:40]) + ("\n…" if len(originals) > 40 else ""))
        if card.edges:
            st.markdown("**Correlation graph**")
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
            )


def main() -> None:
    result = load_result()
    init_cases(result)
    cards = {card.incident_id: card for card in result.cards}
    by_id = {item.incident.incident_id: item for item in result.risk_ranked}
    now = max(item.incident.last_seen for item in result.risk_ranked) + timedelta(minutes=12)

    with st.sidebar:
        st.markdown("**Shift console**")
        st.caption(now.strftime("%Y-%m-%d %H:%M UTC"))
        order = st.radio("Queue order", ("Risk", "SIEM volume"), horizontal=True)
        q = st.text_input("Search", placeholder="INC, user, host, class")
        pri_filter = st.multiselect("Priority", ["P1", "P2", "P3", "P4"], default=["P1", "P2", "P3", "P4"])
        status_filter = st.multiselect("Status", list(STATUSES), default=list(OPEN_STATUSES))
        env_filter = st.multiselect("Environment", ["prod", "staging", "dev", "sandbox", "unknown"])
        mine = st.checkbox("Assigned to me", value=False)
        hide_closed = st.checkbox("Hide closed", value=True)
        if st.button("Reset case state"):
            del st.session_state.cases
            st.rerun()

    ordered = (
        result.risk_ranked
        if order == "Risk"
        else result.legacy_ranked
    )
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

    open_items = [
        item
        for item in result.risk_ranked
        if case(item.incident.incident_id)["status"] in OPEN_STATUSES
    ]
    p1 = sum(1 for item in open_items if priority(item.risk.risk_score) == "P1")
    p2 = sum(1 for item in open_items if priority(item.risk.risk_score) == "P2")
    unacked = sum(
        1
        for item in open_items
        if case(item.incident.incident_id)["status"] == "New"
    )

    st.markdown(
        f"<div class='topbar'><div class='brand'>SOC"
        f"<span>Incident queue · {now.strftime('%d %b %H:%M UTC')}</span></div>"
        f"<div class='brand'><span>{len(visible)} shown · "
        f"order {order.lower()}</span></div></div>",
        unsafe_allow_html=True,
    )
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Open", f"{len(open_items)}")
    k2.metric("P1", f"{p1}")
    k3.metric("P2", f"{p2}")
    k4.metric("Unacked", f"{unacked}")
    k5.metric("Alerts 24h", f"{result.metrics.raw_alert_count}")
    k6.metric("Correlated", f"{result.metrics.incident_count}")

    queue_col, case_col = st.columns([0.92, 1.28], gap="large")
    with queue_col:
        st.caption("Select a row to open the case.")
        chosen = render_queue(visible, now)
        if chosen:
            st.session_state.selected = chosen
    with case_col:
        selected_id = st.session_state.selected
        if selected_id not in by_id:
            selected_id = visible[0].incident.incident_id if visible else result.risk_ranked[0].incident.incident_id
            st.session_state.selected = selected_id
        render_workbench(by_id[selected_id], cards[selected_id], now)


if __name__ == "__main__":
    main()
