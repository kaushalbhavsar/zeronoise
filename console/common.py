"""Shared presentation helpers used by every workspace. No pipeline recompute."""

from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from console.state import (
    ENVIRONMENTS,
    OPEN_STATUSES,
    PAGE_INTEL,
    PAGE_OVERVIEW,
    PAGE_QUEUE,
    PRIORITIES,
    SEVERITY_TOKEN,
    STATUSES,
    case,
    presenting,
    reset_case_state,
    snapshot_now,
    snapshot_window,
)
from engine.presentation import (
    METRIC_DEFINITIONS,
    badge_tone,
    context_badges,
    incident_roles,
    mask_identifier,
    mask_text,
    role_tokens,
)
from engine.schemas import PipelineResult, ScoredIncident


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


def fmt_day(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%d %b %Y %H:%M UTC")


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
    return incident_roles(item)["affected_asset"]


def primary_user(item: ScoredIncident) -> str:
    return incident_roles(item)["title_identity"]


def display(text: str, item: ScoredIncident | None = None) -> str:
    if not presenting():
        return text
    tokens = role_tokens(item) if item is not None else []
    return mask_text(text, tokens, True) if tokens else mask_identifier(text)


def owner_of(item: ScoredIncident) -> str:
    return case(item.incident.incident_id)["assignee"]


def status_of(item: ScoredIncident) -> str:
    return case(item.incident.incident_id)["status"]


def page_header(title: str, result: PipelineResult, *, lede: str) -> None:
    now = snapshot_now(result)
    first, last = snapshot_window(result)
    loaded = st.session_state.get("snapshot_loaded_at")
    loaded_label = fmt_day(loaded) if loaded else fmt_day(now)
    kicker = "ZeroNoise · presentation" if presenting() else "ZeroNoise · demo snapshot"
    st.markdown(f"<div class='zn-kicker'>{kicker}</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='zn-title'>{title}</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div class='zn-sub'>{lede} Reporting period {fmt_day(first)} → {fmt_day(last)}. "
        f"Scope: offline JSONL + CMDB/IAM. Last observed event {fmt_day(last)}. "
        f"Snapshot refreshed {loaded_label}. "
        f"Freshness clock {fmt_day(now)} (12 minutes after last observed event). "
        f"Historical / demo snapshot — not a live SIEM feed.</div>",
        unsafe_allow_html=True,
    )
    if presenting():
        st.info(
            "Presentation mode is on. Identifiers are masked for screen sharing. "
            "This is display-only and is not access control."
        )
    st.caption("Filters and case navigation use the cached snapshot; they do not rescore incidents.")


def render_badges(item: ScoredIncident, *, limit: int | None = 3) -> None:
    names = context_badges(item)
    shown = names if limit is None else names[:limit]
    chips = "".join(f"<span class='badge {badge_tone(name)}'>{name}</span>" for name in shown)
    extra = len(names) - len(shown)
    if extra > 0:
        chips += f"<span class='badge ctx'>+{extra}</span>"
    if chips:
        st.markdown(chips, unsafe_allow_html=True)


def copyable_id(incident_id: str, *, key: str) -> None:
    st.code(incident_id, language=None)


def visible_incidents(
    result: PipelineResult,
    order: str,
    q: str,
    pri_filter: list[str],
    status_filter: list[str],
    env_filter: list[str],
    mine: bool,
    hide_closed: bool,
    unassigned_critical: bool = False,
    production_only: bool = False,
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
        env = env_of(item)
        if env_filter and env not in env_filter:
            continue
        if production_only and env != "prod":
            continue
        if mine and record["assignee"] != "You":
            continue
        if unassigned_critical:
            if record["assignee"] != "Unassigned" or pri not in {"P0", "P1"}:
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


def apply_preset(preset: str) -> dict[str, object]:
    flags = {
        "mine": False,
        "unassigned_critical": False,
        "production_only": False,
        "hide_closed": True,
    }
    if preset == "My cases":
        flags["mine"] = True
    elif preset == "Unassigned critical":
        flags["unassigned_critical"] = True
    elif preset == "Production":
        flags["production_only"] = True
    return flags


def filter_summary(
    visible_n: int,
    total_n: int,
    pri_filter: list[str],
    status_filter: list[str],
    env_filter: list[str],
    preset: str,
) -> str:
    pri = "all priorities" if set(pri_filter) == set(PRIORITIES) else ", ".join(pri_filter)
    if set(status_filter) == set(OPEN_STATUSES):
        status = "open"
    elif set(status_filter) == set(STATUSES):
        status = "any status"
    else:
        status = f"{len(status_filter)} statuses"
    env = "all environments" if not env_filter else ", ".join(env_filter)
    extra = f" · {preset}" if preset and preset != "All open" else ""
    return f"Showing {visible_n} of {total_n} · {pri} · {status} · {env}{extra}"


def queue_filters() -> dict[str, object]:
    st.markdown("**Queue filters**")
    preset = st.pills(
        "Presets",
        ["All open", "My cases", "Unassigned critical", "Production"],
        default="All open",
        key="queue_preset",
    )
    flags = apply_preset(preset or "All open")
    q = st.text_input("Search", placeholder="Title, INC, user, host", key="queue_search")
    with st.expander("More filters", expanded=False):
        order = st.radio(
            "Queue order",
            ("AI Risk-Based Triage", "Legacy SIEM Triage"),
            key="queue_order",
        )
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
            list(ENVIRONMENTS),
            key="queue_env",
        )
        hide_closed = st.checkbox("Hide closed", value=True, key="queue_hide_closed")
        show_ranks = st.checkbox("Show AI / legacy rank columns", value=False, key="queue_show_ranks")
    if "queue_order" not in st.session_state:
        order = "AI Risk-Based Triage"
        pri_filter = list(PRIORITIES)
        status_filter = list(OPEN_STATUSES)
        env_filter = []
        hide_closed = True
        show_ranks = False
    else:
        order = st.session_state.queue_order
        pri_filter = st.session_state.queue_priority
        status_filter = st.session_state.queue_status
        env_filter = st.session_state.queue_env
        hide_closed = st.session_state.queue_hide_closed
        show_ranks = st.session_state.get("queue_show_ranks", False)
    st.session_state.queue_mode = "ai" if str(order).startswith("AI") else "legacy"
    flags.update(
        {
            "preset": preset or "All open",
            "q": q,
            "order": order,
            "pri_filter": pri_filter,
            "status_filter": status_filter,
            "env_filter": env_filter,
            "hide_closed": hide_closed and flags["hide_closed"],
            "show_ranks": show_ranks,
        }
    )
    return flags


def workspace_links() -> None:
    a, b, c = st.columns(3)
    a.page_link(PAGE_OVERVIEW, label="Security overview")
    b.page_link(PAGE_QUEUE, label="Incident queue")
    c.page_link(PAGE_INTEL, label="Detection intelligence")


def session_chrome() -> None:
    st.toggle(
        "Presentation mode",
        key="presentation_mode",
        help="Masks identifiers and collapses technical controls for screen sharing. Not access control.",
    )
    loaded = st.session_state.get("snapshot_loaded_at")
    if loaded:
        st.caption(f"Snapshot refreshed {fmt_day(loaded)}")
    if not presenting():
        demo_admin_controls()


def demo_admin_controls() -> None:
    with st.expander("Demo / admin", expanded=False):
        st.caption("These controls reset local session state. They do not change scores or source data.")
        if st.button("Reset case state", key="reset-case-state"):
            reset_case_state()
            st.rerun()


def defined_metric(key: str, label: str, value) -> None:
    st.metric(label, value, help=METRIC_DEFINITIONS[key])


def empty_state(kind: str, *, action: str | None = None) -> None:
    messages = {
        "no_incidents": "This snapshot contains no correlated incidents.",
        "no_matches": "No incidents match the current filters. The organization-wide snapshot is unchanged.",
        "missing_case": "That incident is not in the current snapshot, so the deep link cannot be opened.",
        "load_error": "The incident snapshot failed to load. Source files may be missing or unreadable.",
        "no_p0": "There are no open P0 or P1 incidents in this snapshot.",
        "no_assets": "No CMDB assets are attached to open P0/P1 cases.",
        "no_edges": "Single-alert incident — no inter-alert edges were recorded.",
    }
    st.info(messages.get(kind, "Nothing to show."))
    if action:
        st.caption(action)


def render_load_error(message: str) -> None:
    empty_state("load_error", action="Regenerate the demo dataset or check data/sample_alerts.jsonl.")
    with st.expander("Error details"):
        st.code(message)


def queue_metrics(result: PipelineResult) -> dict[str, int]:
    open_items = [
        item
        for item in result.risk_ranked
        if case(item.incident.incident_id)["status"] in OPEN_STATUSES
    ]
    urgent = sum(1 for item in open_items if priority(item.risk.risk_score) in {"P0", "P1"})
    unacked = sum(1 for item in open_items if case(item.incident.incident_id)["status"] == "New")
    assigned = sum(1 for item in open_items if case(item.incident.incident_id)["assignee"] != "Unassigned")
    prod = sum(1 for item in open_items if env_of(item) == "prod")
    return {
        "open": len(open_items),
        "p0_p1": urgent,
        "unacked": unacked,
        "assigned": assigned,
        "prod": prod,
    }


