"""Full-width case workspace: decision brief and investigation sections."""

from __future__ import annotations

from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from config import KILL_CHAIN
from console.common import (
    copyable_id,
    display,
    empty_state,
    fmt_age,
    fmt_ts,
    primary_asset,
    primary_user,
    priority,
    render_badges,
    section,
    severity_token,
)
from console.export import case_markdown, case_pdf, export_filenames
from console.state import (
    ASSIGNEES,
    back_to_queue,
    case,
    persist_notes,
    persist_owner,
    persist_status,
    persist_task,
    presenting,
    primary_next_action,
)
from engine.presentation import (
    ACTION_GROUPS,
    driver_label,
    driver_rows,
    evidence_summary,
    exposed_assets,
    exposed_identities,
    group_recommended_actions,
    link_evidence,
    observable_evidence,
    incident_roles,
    next_recommended_action,
    parse_timeline_line,
    raw_alert_ids,
    vendor_severity,
    why_this_matters,
)
from engine.schemas import IncidentCard, ScoredIncident


def render_context_strip(item: ScoredIncident) -> None:
    roles = incident_roles(item)
    st.write(
        f"Initial identity: {display(roles['initial_identity'], item)}  \n"
        f"Privileged identity: {display(roles['privileged_identity'], item)}  \n"
        f"Source host: {display(roles['source_host'], item)}  \n"
        f"Affected destination: {display(roles['destination'], item)}  \n"
        f"Title asset (same as queue): {display(roles['affected_asset'], item)}"
    )


def render_session_activity(record: dict) -> None:
    history = record.get("history") or []
    with st.expander("Session activity", expanded=False):
        if history:
            for event in history:
                st.caption(
                    f"{event['at']} · {event['actor']} · {event['field']}: "
                    f"{event['old']} → {event['new']}"
                )
        else:
            st.caption("No case changes in this session. History is not invented.")


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
            title="Ablation contribution % (not confidence)",
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
    roles = incident_roles(item)
    if st.button("← Back to queue", key="back-to-queue"):
        back_to_queue()
        st.rerun()
    st.markdown(
        f"<div class='case-header pri-{pri.lower()}'>"
        f"<div class='case-title'>{display(item.title, item)}</div>"
        f"<div class='case-meta'>"
        f"<span class='pri {pri.lower()}'>{pri}</span> · {record['status']} · "
        f"{record['assignee']} · risk {item.risk.risk_score:.0f} · "
        f"vendor {vendor_severity(item)} · "
        f"age {fmt_age(item.incident.first_seen, now)} · "
        f"{fmt_ts(item.incident.first_seen)} → {fmt_ts(item.incident.last_seen)}"
        f"</div>"
        f"<div class='case-meta'>Source {display(roles['source_host'], item)} · "
        f"Destination {display(roles['destination'], item)} · "
        f"Initial identity {display(roles['initial_identity'], item)} · "
        f"Privileged identity {display(roles['privileged_identity'], item)}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    id_col, badge_col = st.columns([0.45, 1.55])
    with id_col:
        shown_id = display(item.incident.incident_id, item)
        copyable_id(shown_id, key=f"case-id-{item.incident.incident_id}")
        if not presenting():
            st.caption(f"Deep link: add `?case={item.incident.incident_id}` to the app URL.")
    with badge_col:
        render_badges(item, limit=4)
    st.caption(
        f"Priority {pri} is derived from risk score (P0 ≥ 85, P1 ≥ 70). "
        f"Vendor severity is {vendor_severity(item)} and is not the queue rank. "
        "This snapshot does not produce an incident-level confidence percentage."
    )

    actions, owner, resolve = st.columns([1.5, 0.7, 0.9])
    with actions:
        b1, b2, b3 = st.columns([1.15, 1, 1])
        if b1.button(
            "Investigate",
            type="primary" if next_action == "Investigate" else "secondary",
            use_container_width=True,
        ):
            persist_status(item.incident.incident_id, "Investigating")
            st.rerun()
        if b2.button("Acknowledge", use_container_width=True):
            persist_status(item.incident.incident_id, "Acknowledged")
            st.rerun()
        if b3.button(
            "Escalate",
            type="primary" if next_action == "Escalate" else "secondary",
            use_container_width=True,
        ):
            persist_status(item.incident.incident_id, "Escalated")
            st.rerun()
        st.caption(f"Primary next action: {next_action}.")
    with owner:
        chosen = st.selectbox(
            "Owner",
            ASSIGNEES,
            index=ASSIGNEES.index(record["assignee"]) if record["assignee"] in ASSIGNEES else 0,
            key=f"owner-{item.incident.incident_id}",
        )
        if st.button("Save owner", key=f"save-owner-{item.incident.incident_id}"):
            persist_owner(item.incident.incident_id, chosen)
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
                    persist_status(item.incident.incident_id, "Closed — false positive")
                    st.rerun()
            if c2.button("Close as true positive", key=f"tp-confirm-{item.incident.incident_id}"):
                record["close_reason"] = str(reason).strip()
                persist_status(item.incident.incident_id, "Closed — true positive")
                st.rerun()
        render_case_export(item, card, record, now)
    render_session_activity(record)


def render_case_export(
    item: ScoredIncident,
    card: IncidentCard,
    record: dict,
    now: datetime,
) -> None:
    mask = presenting()
    with st.popover("Export"):
        st.caption(
            "Downloads the open case: decision brief, chronology, ATT&CK, score, "
            "recommended work, detections, and saved session fields. "
            "The file is prepared here; nothing is sent to another system."
        )
        markdown = case_markdown(item, card, record, now, mask=mask)
        pdf = case_pdf(markdown)
        names = export_filenames(item, mask=mask)
        st.download_button(
            "Download Markdown",
            data=markdown,
            file_name=names["md"],
            mime="text/markdown",
            key=f"export-md-{item.incident.incident_id}",
        )
        st.download_button(
            "Download PDF",
            data=pdf,
            file_name=names["pdf"],
            mime="application/pdf",
            key=f"export-pdf-{item.incident.incident_id}",
        )
        if mask:
            st.caption("Presentation mode is on, so identifiers in the file are masked. Masking is not access control.")
        else:
            st.caption("Turn on presentation mode before export if you need identifiers masked for screen sharing.")


def render_decision_brief(item: ScoredIncident, card: IncidentCard) -> None:
    section("Decision brief", "Assessment")
    blocks = [
        ("What happened?", "Observed", display(card.executive_summary, item)),
        ("What is exposed?", "Observed", None),
        ("Why does this matter?", "Assessment", display(why_this_matters(item), item)),
        ("What evidence supports the assessment?", "Observed", display(evidence_summary(item), item)),
        ("What should happen next?", "Recommended", display(next_recommended_action(card), item)),
    ]
    for title, kind, body in blocks:
        section(title, kind)
        if body is None:
            render_context_strip(item)
        else:
            st.write(body)
    if card.why_not_false_positive:
        st.caption(f"Uncertainty: {display(card.why_not_false_positive, item)}")
    if not presenting():
        with st.expander("All resolved identities and assets"):
            st.write("\n".join(exposed_identities(item) or ["No resolved identity"]))
            st.write("\n".join(exposed_assets(item) or ["No resolved asset"]))


def render_overview_tab(item: ScoredIncident, card: IncidentCard) -> None:
    render_decision_brief(item, card)
    if card.contrastive_explanation or card.contrastive:
        with st.expander("Why this incident ranks higher", expanded=not presenting()):
            st.markdown("**Why this incident ranks higher**")
            st.write(display(card.contrastive_explanation or card.contrastive or "", item))
    if presenting():
        return
    left, right = st.columns(2)
    with left:
        section("Affected identities", "Observed")
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
        section("Affected assets", "Observed")
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
    section("Chronology", "Observed")
    st.caption("Each row is a cited detection. Color is not the only cue: tactic and time are labeled.")
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
            f"<div><strong>{parsed['tactic'] or 'Unmapped'}</strong> — {display(parsed['detail'], item)}</div>"
            f"<div class='case-meta'>Sensor {sensor} · Identity {display(identity, item)} · "
            f"Asset {display(asset, item)} · "
            f"<span class='tl-id'>[{display(parsed['alert_id'], item)}]</span></div>"
            f"</div>",
            unsafe_allow_html=True,
        )
        if alert and not presenting():
            with st.expander(f"Evidence {alert.alert_id}"):
                st.caption(
                    "Alert confidence is the source-event field used inside fidelity B. "
                    "It is not an incident-level probability."
                )
                st.write(
                    {
                        "rule": alert.rule_name,
                        "severity": alert.severity_raw,
                        "alert_confidence": alert.confidence,
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
    section("ATT&CK path", "Observed")
    present = set(card.tactics)
    observed = [name for name in KILL_CHAIN if name in present]
    if observed:
        st.caption("Observed path: " + " → ".join(observed))
    else:
        st.caption("No mapped ATT&CK stages on this incident.")
    st.caption("Observed stages are labeled. Unobserved stages are listed on demand and are not implied.")

    unobserved: list[str] = []
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
                        f"`{display(alert.alert_id, item)}` · {alert.source_product} · "
                        f"{display(alert.rule_name, item)} · "
                        f"{display(alert.entities.user_id or '—', item)} / "
                        f"{display(alert.entities.host_id or '—', item)}"
                    )
        else:
            unobserved.append(f"{index:02d}  {stage} · not observed")
    if unobserved:
        with st.expander("Unobserved stages", expanded=not presenting()):
            for line in unobserved:
                st.caption(line)

    techniques = item.incident.unique_techniques or card.techniques
    section("MITRE techniques", "Observed")
    if techniques:
        for technique in techniques:
            st.write(f"- {technique}")
    else:
        st.write("No mapped techniques.")


def render_risk_tab(item: ScoredIncident, card: IncidentCard) -> None:
    section("Why this score", "Assessment")
    st.caption(
        f"Risk {item.risk.risk_score:.0f} is not vendor severity ({vendor_severity(item)}) "
        "and is not a confidence percentage."
    )
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
            "Chart text lists each factor and its ablation share. "
            "These percentages are not confidence probabilities, and color is not the only cue."
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
    section("Recommended work", "Recommended")
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
            now_checked = st.checkbox(
                display(action, item),
                value=checked,
                key=f"act-{item.incident.incident_id}-{hash(action)}",
            )
            if now_checked != checked:
                persist_task(item.incident.incident_id, action, now_checked)
    if record.get("close_reason"):
        st.caption(f"Close reason: {record['close_reason']}")
    notes = st.text_area(
        "Case notes",
        value=record["notes"],
        height=160,
        key=f"notes-{item.incident.incident_id}",
    )
    if st.button("Save notes", key=f"save-notes-{item.incident.incident_id}"):
        persist_notes(item.incident.incident_id, notes)
    st.caption("Session activity is in the case header. It only lists changes saved in this session.")


def render_evidence_tab(item: ScoredIncident, card: IncidentCard) -> None:
    facts = observable_evidence(item)
    section("Incident context", "Observed")
    render_context_strip(item)
    st.caption(
        "Same identities and assets as the queue title and decision brief. "
        "Vendor severity on a detection is not the incident risk score, and there is no incident-level confidence %."
    )

    section("Detections", "Observed")
    st.caption(
        "Evidence is what sensors reported. Alert IDs are citations. "
        "This tab does not invent packet captures, file contents, or business impact."
    )
    if facts["detections"]:
        st.dataframe(
            [
                {
                    "When": row["when"],
                    "Sensor": row["sensor"],
                    "What was observed": display(str(row["what_was_observed"]), item),
                    "Tactic": row["tactic"],
                    "Technique": row["technique"],
                    "Vendor severity": row["vendor_severity"],
                    "Identity": display(str(row["identity"]), item),
                    "Host": display(str(row["host"]), item),
                    "Src IP": display(str(row["src_ip"]), item),
                    "Dest IP": display(str(row["dest_ip"]), item),
                    "Process hash": display(str(row["process_hash"]), item),
                    "Raw events": row["raw_events"],
                }
                for row in facts["detections"]
            ],
            width="stretch",
            hide_index=True,
            key=f"evidence-detections-{item.incident.incident_id}",
        )
    else:
        st.caption("No detections were attached to this incident.")

    with st.expander("Identities, hosts, network, and hashes", expanded=not presenting()):
        left, right = st.columns(2)
        with left:
            st.markdown("**Identities**")
            if facts["identities"]:
                st.dataframe(
                    [
                        {
                            "Identity": display(str(row["identity"]), item),
                            "Privilege": row["privilege"],
                            "Department": row["department"],
                            "Sensors": row["sensors"],
                            "Tactics": row["tactics"],
                        }
                        for row in facts["identities"]
                    ],
                    width="stretch",
                    hide_index=True,
                    key=f"evidence-idents-{item.incident.incident_id}",
                )
            else:
                st.caption("No identity was resolved on these events.")
            st.markdown("**Hosts**")
            if facts["hosts"]:
                st.dataframe(
                    [
                        {
                            "Host": display(str(row["host"]), item),
                            "Hostname": display(str(row["hostname"]), item),
                            "Environment": row["environment"],
                            "Data": row["data"],
                            "Crit": row["criticality"],
                            "Role": row["roles"],
                            "Sensors": row["sensors"],
                        }
                        for row in facts["hosts"]
                    ],
                    width="stretch",
                    hide_index=True,
                    key=f"evidence-hosts-{item.incident.incident_id}",
                )
            else:
                st.caption("No host was resolved on these events.")
        with right:
            st.markdown("**Network**")
            if facts["network"]:
                st.dataframe(
                    [
                        {
                            "Direction": row["direction"],
                            "IP": display(str(row["ip"]), item),
                            "Sensors": row["sensors"],
                            "CMDB": row["gaps"],
                        }
                        for row in facts["network"]
                    ],
                    width="stretch",
                    hide_index=True,
                    key=f"evidence-net-{item.incident.incident_id}",
                )
            else:
                st.caption("No source or destination IP was present on these events.")
            st.markdown("**Process hashes**")
            if facts["hashes"]:
                st.dataframe(
                    [
                        {
                            "Hash": display(str(row["hash"]), item),
                            "Sensors": row["sensors"],
                            "Rules": display(str(row["rules"]), item),
                        }
                        for row in facts["hashes"]
                    ],
                    width="stretch",
                    hide_index=True,
                    key=f"evidence-hash-{item.incident.incident_id}",
                )
            else:
                st.caption("No process hash was present on these events.")

    section("How the events are linked", "Observed")
    links = link_evidence(item)
    if links:
        st.dataframe(
            [
                {
                    "Shared fact": row["fact"],
                    "Value": display(str(row["value"]), item),
                    "Events linked": row["event_count"],
                }
                for row in links
            ],
            width="stretch",
            hide_index=True,
            key=f"evidence-links-{item.incident.incident_id}",
        )
        st.caption("One row per shared artifact. This is not a list of alert-id pairs.")
    else:
        st.caption("Single-alert incident — no shared identity, host, IP, or hash links.")

    if facts["gaps"] and not presenting():
        with st.expander("Context gaps"):
            for gap in facts["gaps"]:
                st.write(f"- {gap}")

    if not presenting():
        with st.expander("Alert citations and raw edges"):
            st.caption("Alert IDs cite the detections above. They are not additional evidence.")
            originals = raw_alert_ids(item)
            st.write(
                f"{len(originals)} raw rows collapsed into {len(item.incident.alerts)} detections."
            )
            st.code("\n".join(originals[:80]) + ("\n…" if len(originals) > 80 else "") or "—")
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
    else:
        st.caption("Raw alert identifiers are hidden in presentation mode.")


def render_case_workspace(
    incident_id: str,
    by_id: dict[str, ScoredIncident],
    cards: dict[str, IncidentCard],
    now: datetime,
) -> None:
    item = by_id.get(incident_id)
    card = cards.get(incident_id)
    if item is None or card is None:
        empty_state(
            "missing_case",
            action="Return to the queue and open a case from the current snapshot.",
        )
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
