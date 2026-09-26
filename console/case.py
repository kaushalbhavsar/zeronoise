"""Full-width case workspace: decision brief and investigation sections."""

from __future__ import annotations

from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from config import KILL_CHAIN
from console.common import (
    copyable_id,
    fmt_age,
    fmt_ts,
    primary_asset,
    primary_user,
    priority,
    render_badges,
    severity_token,
)
from console.state import ASSIGNEES, back_to_queue, case, primary_next_action, set_status
from engine.presentation import (
    ACTION_GROUPS,
    driver_label,
    driver_rows,
    evidence_summary,
    exposed_assets,
    exposed_identities,
    grouped_correlation_evidence,
    group_recommended_actions,
    next_recommended_action,
    parse_timeline_line,
    raw_alert_ids,
    why_this_matters,
)
from engine.schemas import IncidentCard, ScoredIncident


def driver_chart(card: IncidentCard) -> go.Figure:
    drivers = driver_rows(card)
    fig = go.Figure(
        go.Bar(
            x=[d.contribution_pct for d in drivers],
            y=[driver_label(d.factor) for d in drivers],
            orientation="h",
            marker_color="#3b82f6",
            text=[f"{d.contribution_pct}%" for d in drivers],
            textposition="outside",
        )
    )
    fig.update_layout(
        height=320,
        margin=dict(l=8, r=48, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e8eef7", size=13),
        xaxis=dict(
            title="Ablation contribution %",
            range=[0, max(42, max((d.contribution_pct for d in drivers), default=0) + 8)],
        ),
        yaxis=dict(autorange="reversed"),
        meta={"chart_id": f"drivers-{card.incident_id}"},
    )
    return fig


def render_case_header(item: ScoredIncident, card: IncidentCard, now: datetime) -> None:
    record = case(item.incident.incident_id)
    pri = priority(item.risk.risk_score)
    next_action = primary_next_action(item)
    if st.button("← Back to queue", key="back-to-queue"):
        back_to_queue()
        st.rerun()
    st.markdown(
        f"<div class='case-header pri-{pri.lower()}'>"
        f"<div class='case-title'>{item.title}</div>"
        f"<div class='case-meta'>"
        f"<span class='pri {pri.lower()}'>{pri}</span> · {record['status']} · "
        f"{record['assignee']} · risk {item.risk.risk_score:.0f} · "
        f"age {fmt_age(item.incident.first_seen, now)} · "
        f"{fmt_ts(item.incident.first_seen)} → {fmt_ts(item.incident.last_seen)}"
        f"</div></div>",
        unsafe_allow_html=True,
    )
    id_col, badge_col = st.columns([0.45, 1.55])
    with id_col:
        copyable_id(item.incident.incident_id, key=f"case-id-{item.incident.incident_id}")
    with badge_col:
        render_badges(item, limit=4)

    actions, owner, resolve = st.columns([1.5, 0.7, 0.9])
    with actions:
        b1, b2, b3 = st.columns([1.15, 1, 1])
        if b1.button(
            "Investigate",
            type="primary" if next_action == "Investigate" else "secondary",
            use_container_width=True,
        ):
            set_status(item.incident.incident_id, "Investigating")
            st.rerun()
        if b2.button("Acknowledge", use_container_width=True):
            set_status(item.incident.incident_id, "Acknowledged")
            st.rerun()
        if b3.button(
            "Escalate",
            type="primary" if next_action == "Escalate" else "secondary",
            use_container_width=True,
        ):
            set_status(item.incident.incident_id, "Escalated")
            st.rerun()
        st.caption(f"Primary next action: {next_action}.")
    with owner:
        record["assignee"] = st.selectbox(
            "Owner",
            ASSIGNEES,
            index=ASSIGNEES.index(record["assignee"]) if record["assignee"] in ASSIGNEES else 0,
            key=f"owner-{item.incident.incident_id}",
        )
        st.caption(f"Status: {record['status']}")
    with resolve:
        with st.popover("Resolve"):
            st.write("Closing a case requires a recorded outcome. This does not delete source alerts.")
            reason = st.text_area(
                "Reason",
                value=record.get("close_reason") or "",
                key=f"fp-reason-{item.incident.incident_id}",
                height=90,
            )
            c1, c2 = st.columns(2)
            if c1.button("Close as false positive", key=f"fp-confirm-{item.incident.incident_id}"):
                if not str(reason).strip():
                    st.warning("Enter a reason before closing as a false positive.")
                else:
                    record["close_reason"] = str(reason).strip()
                    set_status(item.incident.incident_id, "Closed — false positive")
                    st.rerun()
            if c2.button("Close as true positive", key=f"tp-confirm-{item.incident.incident_id}"):
                record["close_reason"] = str(reason).strip()
                set_status(item.incident.incident_id, "Closed — true positive")
                st.rerun()


def render_decision_brief(item: ScoredIncident, card: IncidentCard) -> None:
    st.subheader("Decision brief")
    blocks = [
        ("What happened?", "Observed", card.executive_summary),
        (
            "What is exposed?",
            "Observed",
            "\n".join(exposed_assets(item) or ["No resolved asset"])
            + "\n"
            + "\n".join(exposed_identities(item) or ["No resolved identity"]),
        ),
        ("Why does this matter?", "Assessment", why_this_matters(item)),
        ("What evidence supports the assessment?", "Observed", evidence_summary(item)),
        ("What should happen next?", "Recommended", next_recommended_action(card)),
    ]
    for title, kind, body in blocks:
        st.markdown(f"**{title}**")
        st.caption(kind)
        st.write(body)
    if card.why_not_false_positive:
        st.caption(f"Uncertainty: {card.why_not_false_positive}")


def render_overview_tab(item: ScoredIncident, card: IncidentCard) -> None:
    render_decision_brief(item, card)
    if card.contrastive_explanation or card.contrastive:
        st.markdown("**Why this incident ranks higher**")
        st.write(card.contrastive_explanation or card.contrastive)
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
    st.caption(f"Sensors: {', '.join(card.products) or '—'}  ·  Class is derived from observed tactics, not scenario_id.")


def render_timeline_tab(item: ScoredIncident, card: IncidentCard) -> None:
    alerts_by_id = {alert.alert_id: alert for alert in item.incident.alerts}
    st.markdown("<div class='tl'>", unsafe_allow_html=True)
    for line in card.attack_timeline:
        parsed = parse_timeline_line(line)
        alert = alerts_by_id.get(parsed["alert_id"])
        token = severity_token(alert.severity_raw) if alert else "p4"
        sensor = alert.source_product if alert else "—"
        identity = (alert.entities.user_id if alert else None) or "—"
        asset = (alert.entities.host_id if alert else None) or "—"
        st.markdown(
            f"<div class='tl-item {token}'>"
            f"<div class='tl-time'>{parsed['clock'] or '—'}</div>"
            f"<div><strong>{parsed['tactic'] or 'Unmapped'}</strong> — {parsed['detail']}</div>"
            f"<div class='case-meta'>Sensor {sensor} · Identity {identity} · Asset {asset} · "
            f"<span class='tl-id'>[{parsed['alert_id']}]</span></div>"
            f"</div>",
            unsafe_allow_html=True,
        )
        if alert:
            with st.expander(f"Evidence {alert.alert_id}"):
                st.write(
                    {
                        "rule": alert.rule_name,
                        "severity": alert.severity_raw,
                        "confidence": alert.confidence,
                        "false_positive_rate": alert.false_positive_rate,
                        "technique": alert.mitre_technique,
                        "src_ip": alert.entities.src_ip,
                        "dest_ip": alert.entities.dest_ip,
                        "events": alert.event_count,
                        "first_seen": fmt_ts(alert.first_seen or alert.timestamp),
                        "last_seen": fmt_ts(alert.last_seen or alert.timestamp),
                    }
                )
    st.markdown("</div>", unsafe_allow_html=True)


def render_attack_tab(item: ScoredIncident, card: IncidentCard) -> None:
    present = set(card.tactics)
    observed = [name for name in KILL_CHAIN if name in present]
    if observed:
        st.caption("Observed path: " + " → ".join(observed))
    else:
        st.caption("No mapped ATT&CK stages on this incident.")
    st.caption("Full stage names are listed below. Highlighted rows were observed; muted rows were not.")

    for index, stage in enumerate(KILL_CHAIN, start=1):
        supporting = [
            alert
            for alert in item.incident.alerts
            if alert.mitre_tactic == stage
        ]
        if stage in present:
            with st.container(border=True):
                st.markdown(
                    f"**{index:02d}  {stage}** · observed · "
                    f"{len(supporting)} supporting event{'s' if len(supporting) != 1 else ''}"
                )
                for alert in supporting:
                    st.write(
                        f"`{alert.alert_id}` · {alert.source_product} · {alert.rule_name} · "
                        f"{alert.entities.user_id or '—'} / {alert.entities.host_id or '—'}"
                    )
        else:
            st.caption(f"{index:02d}  {stage} · not observed")

    techniques = item.incident.unique_techniques or card.techniques
    st.markdown("**MITRE techniques**")
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
                "This percentage is the share of score movement when that factor is ablated. "
                "It is not a confidence probability."
            )
    with st.expander("Scoring details"):
        st.write(item.risk.formula)
        st.write(
            {
                "fidelity_b": item.risk.fidelity_b,
                "progression_k": item.risk.progression_k,
                "blast_c": item.risk.blast_c,
                "asset_risk": item.risk.asset_risk,
                "identity_risk": item.risk.identity_risk,
                "risk_score": item.risk.risk_score,
            }
        )
        st.caption(
            f"Legacy SIEM rank #{item.naive_siem_rank} uses raw severity × volume only "
            "and is not used for this queue's default order."
        )


def render_response_tab(item: ScoredIncident, card: IncidentCard) -> None:
    record = case(item.incident.incident_id)
    recommended = card.recommended_actions or card.containment
    st.caption(
        "Checking a box records that the task was completed in this case file. "
        "It does not execute an infrastructure action."
    )
    if not recommended:
        st.write("No entity-specific actions were generated.")
    grouped = group_recommended_actions(recommended)
    for group in ACTION_GROUPS:
        actions = grouped[group]
        if not actions:
            continue
        st.markdown(f"**{group}**")
        for action in actions:
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
        st.caption(f"Close reason: {record['close_reason']}")
    record["notes"] = st.text_area(
        "Case notes",
        value=record["notes"],
        height=160,
        key=f"notes-{item.incident.incident_id}",
    )


def render_evidence_tab(item: ScoredIncident, card: IncidentCard) -> None:
    groups = grouped_correlation_evidence(item)
    if groups:
        st.markdown("**Why were these alerts grouped?**")
        for row in groups:
            reasons = row["reasons"]
            st.write(f"`{row['from']}` → `{row['to']}`")
            st.caption(" · ".join(str(reason) for reason in reasons))
    else:
        st.write("Single-alert incident — no inter-alert edges.")
    if card.edges:
        with st.expander("Raw correlation edges"):
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
