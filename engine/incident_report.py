"""Normalized SOC incident report. Markdown is a view of this model."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from config import BLAST_ASSET_WEIGHT, BLAST_IDENTITY_WEIGHT, FIDELITY_CAP, KILL_CHAIN, RISK_SCALE
from engine.presentation import (
    PRIVILEGED_TIERS,
    context_badges,
    driver_label,
    driver_rows,
    group_recommended_actions,
    incident_roles,
    link_evidence,
    mask_identifier,
    mask_text,
    next_recommended_action,
    observable_evidence,
    parse_timeline_line,
    role_tokens,
    vendor_severity,
    why_this_matters,
)
from engine.readability import enforce_readability, is_readable
from engine.schemas import IncidentCard, ScoredIncident

REPORT_ACTION_HEADINGS = (
    ("Contain", "Immediate containment"),
    ("Validate", "Validate"),
    ("Preserve", "Preserve"),
    ("Recover", "Recover"),
)

_PRIVILEGE_LABEL = {
    "tier_0_domain_admin": "Tier-0 admin",
    "tier_1_cloud_admin": "Cloud admin",
    "service_account": "Service account",
    "standard_user": "Standard user",
}

_ARTIFACT_LABELS = {
    "Shared identity": "Identity",
    "Shared host": "Host",
    "Shared source IP": "Source IP",
    "Shared process hash": "Process hash",
}

_DATA_LABELS = {
    "crown_jewel_pii_pci": "Crown-jewel data",
    "confidential": "Confidential data",
    "internal": "Internal data",
    "public": "Public data",
}

_COUNT_WORDS = {
    1: "One",
    2: "Two",
    3: "Three",
    4: "Four",
    5: "Five",
    6: "Six",
    7: "Seven",
    8: "Eight",
    9: "Nine",
    10: "Ten",
}

SECTION_ORDER = (
    "Decision brief",
    "Key entities",
    "Attack timeline",
    "Why ZeroNoise ranked this",
    "Why this may be a real attack",
    "ATT&CK coverage",
    "Recommended work",
    "Evidence linking",
    "Technical appendix",
)


class DecisionBrief(BaseModel):
    what_happened: str
    why_it_matters: str
    immediate_action: str


class EntityRow(BaseModel):
    entity: str
    value: str
    context: str = ""


class TimelineRow(BaseModel):
    time: str
    stage: str
    activity: str
    sensor: str
    evidence: str


class ReportRiskDriver(BaseModel):
    factor: str
    contribution_pct: int
    why: str


class AttackStage(BaseModel):
    stage: str
    observed: bool
    evidence_count: int


class Technique(BaseModel):
    technique_id: str
    name: str = ""


class RecommendationGroups(BaseModel):
    groups: dict[str, list[tuple[str, bool]]] = Field(default_factory=dict)


class SharedArtifact(BaseModel):
    artifact: str
    value: str
    supporting_alerts: int
    alert_ids: list[str] = Field(default_factory=list)


class CaseActivity(BaseModel):
    time: str
    actor: str
    change: str


class DetectionEvidence(BaseModel):
    time: str
    sensor: str
    detection: str
    technique: str
    severity: str
    evidence: str


class CorrelationEdge(BaseModel):
    source: str
    target: str
    link: str
    delta_min: float
    strength: float


class RiskCalculationDetails(BaseModel):
    formula: str
    raw_risk: float
    fidelity_b: float
    progression_k: float
    blast_c: float
    asset_risk: float
    identity_risk: float
    risk_score: float
    scale: float
    noise_note: str
    drivers: list[ReportRiskDriver] = Field(default_factory=list)


class ExportMetadata(BaseModel):
    exported_at: str
    source: str
    live_or_demo: str
    inputs: str
    risk_disclaimer: str
    masking_disclaimer: str
    workspace: str = "Exported from the ZeroNoise case workspace."


class IncidentReportModel(BaseModel):
    title: str
    engine_title: str
    incident_id: str
    priority: str
    status: str
    owner: str
    risk_score: float
    vendor_severity: str
    first_seen: str
    last_seen: str
    duration: str
    zeronoise_rank: int | None
    legacy_rank: int | None
    sensors: list[str]
    context_tags: list[str]
    attack_path: list[str]
    decision_brief: DecisionBrief
    entities: list[EntityRow]
    timeline: list[TimelineRow]
    ranking_explanation: str
    risk_drivers: list[ReportRiskDriver]
    why_real: str
    attack_coverage: list[AttackStage]
    techniques: list[Technique]
    recommendations: RecommendationGroups
    evidence_links: list[SharedArtifact]
    context_gaps: list[str]
    case_activity: list[CaseActivity]
    case_notes: str
    close_reason: str
    risk_calculation: RiskCalculationDetails
    detections: list[DetectionEvidence]
    correlation_edges: list[CorrelationEdge]
    export_metadata: ExportMetadata
    mask: bool = False
    mask_tokens: list[str] = Field(default_factory=list)


def _priority(score: float) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    if score >= 30:
        return "P3"
    return "P4"


def _short_host(name: str) -> str:
    if not name or name == "—":
        return "unknown host"
    return name.split(".")[0]


def display_title(item: ScoredIncident) -> str:
    tactics = set(item.incident.unique_tactics)
    badges = context_badges(item)
    host = _short_host(incident_roles(item)["affected_asset"])
    if "Impact" in tactics:
        label = "Ransomware staging"
    elif "Exfiltration" in tactics and "Crown Jewel" in badges:
        label = "Crown-jewel exfil"
    elif "Exfiltration" in tactics:
        label = "Data exfil"
    elif "High FP Rule" in badges and "Sandbox" in badges:
        label = "Noisy scanner"
    elif "Lateral Movement" in tactics and "Credential Access" in tactics:
        label = "Credential theft"
    elif tactics:
        label = next(iter(tactics))
    else:
        label = "Unclassified"
    return f"{label} on {host}"


def _fmt_day(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%d %b %Y %H:%M UTC")


def _fmt_clock(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%H:%M UTC")


def _fmt_duration(first: datetime, last: datetime) -> str:
    seconds = max(0, int((last - first).total_seconds()))
    hours, rem = divmod(seconds, 3600)
    minutes = rem // 60
    if hours >= 24:
        days, hours = divmod(hours, 24)
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _count_word(n: int) -> str:
    return _COUNT_WORDS.get(n, str(n))


def _join_and(parts: list[str]) -> str:
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return f"{', '.join(parts[:-1])}, and {parts[-1]}"


def _missing(value: str | None) -> bool:
    return value in {None, "", "—", "unknown host"}


def _privilege_label(tier: str | None) -> str:
    if not tier:
        return "Unknown"
    return _PRIVILEGE_LABEL.get(tier, tier.replace("_", " "))


def _is_privileged(tier: str | None) -> bool:
    return bool(tier) and tier in PRIVILEGED_TIERS


def _split_technique(value: str) -> Technique:
    raw = (value or "").strip()
    if " - " in raw:
        tid, name = raw.split(" - ", 1)
        return Technique(technique_id=tid.strip(), name=name.strip())
    if raw.startswith("T") and " " in raw:
        tid, name = raw.split(" ", 1)
        return Technique(technique_id=tid.strip(), name=name.strip())
    return Technique(technique_id=raw, name="")


def _identity_record(item: ScoredIncident, user_id: str):
    for alert in item.incident.alerts:
        if alert.identity and alert.identity.user_id == user_id:
            return alert.identity
        if alert.entities.user_id == user_id and alert.identity:
            return alert.identity
    return None


def _host_record(item: ScoredIncident, host: str):
    for alert in item.incident.alerts:
        for asset in (alert.asset, alert.dest_asset):
            if asset and (asset.host_id == host or asset.hostname == host):
                return asset
        if alert.entities.host_id == host and alert.asset:
            return alert.asset
    return None


def compose_what_happened(item: ScoredIncident) -> str:
    roles = incident_roles(item)
    identity = roles["initial_identity"]
    host = _short_host(roles["source_host"] if not _missing(roles["source_host"]) else roles["affected_asset"])
    clock = _fmt_clock(item.incident.first_seen)
    n = len(item.incident.alerts)
    sensors = _join_and(list(item.incident.unique_products))
    tactics = list(item.incident.unique_tactics)
    first_t = tactics[0] if tactics else None
    last_t = tactics[-1] if tactics else None
    dest = roles["destination"]

    paragraphs: list[str] = []
    if not _missing(identity) and host != "unknown host":
        paragraphs.append(f"{identity} was active on {host} starting at {clock}.")
    elif host != "unknown host":
        paragraphs.append(f"Activity started on {host} at {clock}.")
    else:
        paragraphs.append(f"Activity started at {clock}.")

    count = _count_word(n)
    if sensors and first_t and last_t and first_t != last_t:
        paragraphs.append(
            f"{count} related alerts from {sensors} show activity moving from {first_t} to {last_t}."
        )
    elif sensors:
        paragraphs.append(f"{count} related alerts from {sensors} support this incident.")
    else:
        paragraphs.append(f"{count} related alerts support this incident.")

    tactic_set = set(tactics)
    if "Impact" in tactic_set:
        paragraphs.append(
            "The last alert shows impact activity. That can mean ransomware staging."
        )
    elif "Exfiltration" in tactic_set:
        paragraphs.append("The last alert shows data leaving a host.")
    elif last_t:
        paragraphs.append(f"The last mapped stage is {last_t}.")

    if "Exfiltration" in tactic_set and _missing(dest):
        paragraphs.append("The destination is unknown.")

    text = "\n\n".join(paragraphs)
    fallback = f"{count} related alerts support this incident. Review the timeline."
    return enforce_readability(text, fallback)


def compose_why_it_matters(item: ScoredIncident) -> str:
    tactics = set(item.incident.unique_tactics)
    badges = set(context_badges(item))
    parts: list[str] = []
    if {"Credential Access", "Lateral Movement", "Impact"} <= tactics:
        parts.append(
            "The activity includes credential access, lateral movement, and an attempt to remove recovery data."
        )
    elif {"Credential Access", "Lateral Movement"} <= tactics:
        parts.append("The activity includes credential access and lateral movement.")
    elif "Exfiltration" in tactics and "Crown Jewel" in badges:
        parts.append("Data left a system that stores sensitive records.")
    elif "Impact" in tactics:
        parts.append("Impact activity can wipe backups on the affected host.")
    else:
        return why_this_matters(item)
    if "Production" in badges:
        parts.append("The host is in production.")
    if "Crown Jewel" in badges:
        parts.append("A crown-jewel system is in scope.")
    text = " ".join(parts)
    return enforce_readability(text, why_this_matters(item))


def compose_immediate_action(card: IncidentCard) -> str:
    actions = card.recommended_actions or card.containment
    grouped = group_recommended_actions(actions)
    contain = grouped["Contain"]
    chosen = contain[:3] if contain else actions[:1]
    if not chosen:
        chosen = [next_recommended_action(card)]
    text = " ".join(action if action.endswith(".") else f"{action}." for action in chosen)
    fallback = chosen[0] if chosen else "Review the timeline."
    return enforce_readability(text, fallback)


def compose_ranking_explanation(
    item: ScoredIncident,
    peer: ScoredIncident | None,
) -> str:
    rank = item.risk_rank
    tactics = list(item.incident.unique_tactics)
    sensors = list(item.incident.unique_products)
    bits = [
        f"ZeroNoise ranked this incident #{rank}."
        if rank
        else "ZeroNoise ranked this incident high."
    ]
    bits.append("Related alerts form one attack path.")
    if tactics:
        bits.append(f"The incident crossed {len(tactics)} ATT&CK stages.")
    if sensors:
        bits.append(f"It involved {len(sensors)} sensors.")
    if "Credential Access" in tactics:
        bits.append("It included credential access.")
    if "Impact" in tactics:
        bits.append("It ended with Impact activity.")
    elif "Exfiltration" in tactics:
        bits.append("It ended with exfiltration.")
    if peer is not None:
        bits.append(
            f"By comparison, {peer.incident.incident_id} produced "
            f"{peer.incident.total_event_count} raw alerts but scored only "
            f"{peer.risk.risk_score:.0f}."
        )
        bits.append("Alert volume alone did not set this rank.")
    fallback = "ZeroNoise put this case first. The attack reached a late stage."
    return enforce_readability(" ".join(bits), fallback)


def compose_why_real(item: ScoredIncident, card: IncidentCard) -> str:
    tactics = list(item.incident.unique_tactics)
    sensors = list(item.incident.unique_products)
    minutes = max(
        1,
        int((item.incident.last_seen - item.incident.first_seen).total_seconds() // 60),
    )
    bits = ["This is unlikely to be one isolated false alert."]
    if len(sensors) >= 2:
        bits.append(
            f"{_join_and(sensors)} recorded related activity within {minutes} minutes."
        )
    elif sensors:
        bits.append(f"{sensors[0]} recorded related activity within {minutes} minutes.")
    if len(tactics) >= 2:
        bits.append(
            f"The sequence follows a path from {tactics[0]} to {tactics[-1]}."
        )
    bits.append("Review the timeline before you contain the host.")
    generated = enforce_readability(" ".join(bits), bits[0] + " Review the timeline.")
    existing = (card.why_not_false_positive or "").strip()
    if existing and is_readable(existing):
        return existing
    return generated


def volume_contrast_peer(
    item: ScoredIncident,
    peers: list[ScoredIncident] | None,
) -> ScoredIncident | None:
    if not peers:
        return None
    candidates = [
        peer
        for peer in peers
        if peer.incident.incident_id != item.incident.incident_id
        and peer.incident.total_event_count >= 40
        and peer.risk.risk_score < min(40.0, item.risk.risk_score)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda peer: peer.incident.total_event_count)


def _entity_rows(item: ScoredIncident) -> list[EntityRow]:
    roles = incident_roles(item)
    facts = observable_evidence(item)
    rows: list[EntityRow] = []
    identity = roles["initial_identity"]
    if not _missing(identity):
        record = _identity_record(item, identity)
        tier = record.privilege_tier if record else None
        dept = record.department if record else None
        context_bits = []
        if dept:
            context_bits.append(dept)
        context_bits.append(_privilege_label(tier))
        rows.append(EntityRow(entity="Identity", value=identity, context=" · ".join(context_bits)))
    privileged = roles["privileged_identity"]
    priv_record = _identity_record(item, privileged) if not _missing(privileged) else None
    if (
        priv_record
        and _is_privileged(priv_record.privilege_tier)
        and privileged != identity
    ):
        rows.append(
            EntityRow(
                entity="Privileged identity",
                value=privileged,
                context=_privilege_label(priv_record.privilege_tier),
            )
        )
    source = roles["source_host"]
    if not _missing(source):
        asset = _host_record(item, source)
        env = asset.environment if asset else ""
        env_label = {"prod": "Production", "sandbox": "Sandbox", "staging": "Staging", "dev": "Dev"}.get(env, env)
        rows.append(
            EntityRow(
                entity="Source host",
                value=source,
                context=env_label,
            )
        )
        if asset and asset.hostname and asset.hostname != source:
            data = _DATA_LABELS.get(asset.data_sensitivity, (asset.data_sensitivity or "").replace("_", " "))
            rows.append(EntityRow(entity="Hostname", value=asset.hostname, context=data))
    dest = roles["destination"]
    if not _missing(dest):
        dest_asset = _host_record(item, dest)
        if dest_asset:
            rows.append(
                EntityRow(
                    entity="Destination",
                    value=dest_asset.hostname or dest,
                    context=dest_asset.environment,
                )
            )
        else:
            rows.append(EntityRow(entity="Destination", value=dest, context="Context unknown"))
    hashes = facts["hashes"]
    if hashes:
        top = max(hashes, key=lambda row: str(row.get("sensors") or ""))
        hash_value = str(top["hash"])
        count = sum(
            1
            for alert in item.incident.alerts
            if alert.entities.process_hash == hash_value
        )
        rows.append(
            EntityRow(
                entity="Process hash",
                value=hash_value,
                context=f"Seen in {count} alert{'s' if count != 1 else ''}",
            )
        )
    return rows


def _trim_repeated_activity(activity: str, item: ScoredIncident) -> str:
    """Keep the action. Drop the same user/host suffix on every row."""
    text = activity
    for user in item.incident.unique_users:
        text = text.replace(f" for {user}", "")
    for host in item.incident.unique_hosts:
        text = text.replace(f" on {host}", "")
        text = text.replace(f" on {_short_host(host)}", "")
    return " ".join(text.split())


def _humanize_gap(gap: str) -> str:
    if gap.startswith("unknown_dest_ip:"):
        return f"Destination IP {gap.split(':', 1)[1]} is not in CMDB."
    return gap


def _timeline_rows(item: ScoredIncident, card: IncidentCard) -> list[TimelineRow]:
    alerts = {alert.alert_id: alert for alert in item.incident.alerts}
    rows: list[TimelineRow] = []
    for line in card.attack_timeline:
        parsed = parse_timeline_line(line)
        alert = alerts.get(parsed["alert_id"])
        sensor = alert.source_product if alert else ""
        rows.append(
            TimelineRow(
                time=parsed["clock"] or ( _fmt_clock(alert.first_seen or alert.timestamp) if alert else "" ),
                stage=parsed["tactic"] or (alert.mitre_tactic if alert else "Unmapped"),
                activity=_trim_repeated_activity(
                    parsed["detail"] or (alert.rule_name if alert else ""),
                    item,
                ),
                sensor=sensor,
                evidence=parsed["alert_id"] or (alert.alert_id if alert else ""),
            )
        )
    if rows:
        return rows
    for alert in sorted(
        item.incident.alerts,
        key=lambda item_alert: (item_alert.first_seen or item_alert.timestamp, item_alert.alert_id),
    ):
        rows.append(
            TimelineRow(
                time=_fmt_clock(alert.first_seen or alert.timestamp),
                stage=alert.mitre_tactic,
                activity=_trim_repeated_activity(alert.rule_name, item),
                sensor=alert.source_product,
                evidence=alert.alert_id,
            )
        )
    return rows


def _driver_rows(card: IncidentCard) -> list[ReportRiskDriver]:
    return [
        ReportRiskDriver(
            factor=driver_label(driver.factor),
            contribution_pct=int(driver.contribution_pct),
            why=driver.evidence or "",
        )
        for driver in driver_rows(card)
    ]


def build_incident_report(
    item: ScoredIncident,
    card: IncidentCard,
    record: dict,
    now: datetime,
    *,
    mask: bool = False,
    peers: list[ScoredIncident] | None = None,
) -> IncidentReportModel:
    facts = observable_evidence(item)
    drivers = _driver_rows(card)
    actions = card.recommended_actions or card.containment
    grouped = group_recommended_actions(actions)
    done = set(record.get("done") or [])
    recs: dict[str, list[tuple[str, bool]]] = {}
    for key, heading in REPORT_ACTION_HEADINGS:
        bucket = grouped.get(key) or []
        if bucket:
            recs[heading] = [(action, action in done) for action in bucket]
    history = [
        CaseActivity(
            time=str(event.get("at") or ""),
            actor=str(event.get("actor") or ""),
            change=f"{str(event.get('field') or '').title()}: {event.get('old')} → {event.get('new')}",
        )
        for event in (record.get("history") or [])
    ]
    coverage = []
    present = set(card.tactics or item.incident.unique_tactics)
    for stage in KILL_CHAIN:
        count = sum(1 for alert in item.incident.alerts if alert.mitre_tactic == stage)
        coverage.append(AttackStage(stage=stage, observed=stage in present, evidence_count=count))
    techniques = [_split_technique(value) for value in (item.incident.unique_techniques or card.techniques)]
    detections = [
        DetectionEvidence(
            time=str(row["when"]),
            sensor=str(row["sensor"]),
            detection=str(row["what_was_observed"]),
            technique=str(row["technique"]),
            severity=str(row["vendor_severity"]),
            evidence=str(row["alert_id"]),
        )
        for row in facts["detections"]
    ]
    links = [
        SharedArtifact(
            artifact=_ARTIFACT_LABELS.get(str(row["fact"]), str(row["fact"])),
            value=str(row["value"]),
            supporting_alerts=int(row["event_count"]),
            alert_ids=list(row.get("alert_ids") or []),
        )
        for row in link_evidence(item)
    ]
    edges = [
        CorrelationEdge(
            source=edge.source_alert_id,
            target=edge.target_alert_id,
            link=edge.relationship_type.replace("_", " ").title(),
            delta_min=edge.time_delta_minutes,
            strength=edge.correlation_strength,
        )
        for edge in item.incident.edges
    ]
    noise = next((driver.why for driver in drivers if "Noise" in driver.factor or "FP" in driver.factor), "")
    peer = volume_contrast_peer(item, peers)
    return IncidentReportModel(
        title=display_title(item),
        engine_title=item.title,
        incident_id=item.incident.incident_id,
        priority=_priority(item.risk.risk_score),
        status=str(record.get("status") or "New"),
        owner=str(record.get("assignee") or "Unassigned"),
        risk_score=float(item.risk.risk_score),
        vendor_severity=vendor_severity(item),
        first_seen=_fmt_day(item.incident.first_seen),
        last_seen=_fmt_day(item.incident.last_seen),
        duration=_fmt_duration(item.incident.first_seen, item.incident.last_seen),
        zeronoise_rank=item.risk_rank,
        legacy_rank=item.naive_siem_rank,
        sensors=list(item.incident.unique_products),
        context_tags=context_badges(item),
        attack_path=[stage for stage in KILL_CHAIN if stage in present],
        decision_brief=DecisionBrief(
            what_happened=compose_what_happened(item),
            why_it_matters=compose_why_it_matters(item),
            immediate_action=compose_immediate_action(card),
        ),
        entities=_entity_rows(item),
        timeline=_timeline_rows(item, card),
        ranking_explanation=compose_ranking_explanation(item, peer),
        risk_drivers=drivers,
        why_real=compose_why_real(item, card),
        attack_coverage=coverage,
        techniques=techniques,
        recommendations=RecommendationGroups(groups=recs),
        evidence_links=links,
        context_gaps=[_humanize_gap(gap) for gap in facts["gaps"]] if not mask else [],
        case_activity=history,
        case_notes=str(record.get("notes") or "").strip(),
        close_reason=str(record.get("close_reason") or "").strip(),
        risk_calculation=RiskCalculationDetails(
            formula=item.risk.formula,
            raw_risk=float(item.risk.raw_weighted_score),
            fidelity_b=float(item.risk.fidelity_b),
            progression_k=float(item.risk.progression_k),
            blast_c=float(item.risk.blast_c),
            asset_risk=float(item.risk.asset_risk),
            identity_risk=float(item.risk.identity_risk),
            risk_score=float(item.risk.risk_score),
            scale=float(RISK_SCALE),
            noise_note=noise,
            drivers=drivers,
        ),
        detections=detections,
        correlation_edges=edges,
        export_metadata=ExportMetadata(
            exported_at=datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
            source="ZeroNoise case workspace",
            live_or_demo="Historical / demo snapshot. Not a live SIEM feed.",
            inputs="Offline JSONL + CMDB/IAM",
            risk_disclaimer="Risk score is not vendor severity and is not a confidence percentage.",
            masking_disclaimer=(
                "Identifiers in this file are masked for screen sharing. Masking is display-only and is not access control."
                if mask
                else "Presentation masking was off. Identifiers are shown as stored in the snapshot."
            ),
        ),
        mask=mask,
        mask_tokens=role_tokens(item),
    )


def _show(report: IncidentReportModel, value: object) -> str:
    text = "" if value is None else str(value)
    if text in {"", "—"}:
        return text
    if not report.mask:
        return text
    if report.mask_tokens:
        return mask_text(text, report.mask_tokens, True)
    return mask_identifier(text)


def _cell(report: IncidentReportModel, value: object) -> str:
    return _show(report, value).replace("|", "\\|").replace("\n", " ")


def _stacked_formula(calc: RiskCalculationDetails) -> list[str]:
    """One equation per line. The engine stores these as a single comma-joined string."""
    return [
        f"risk_score = 100 × (1 − exp(−RawRisk / {calc.scale:.0f}))",
        "RawRisk    = B × K × C",
        f"B          = min(Σ fidelity_a over unique (rule, tactic), {FIDELITY_CAP:.0f})",
        "K          = 1 + 0.35×max(0, m-1) + 0.20×max(0, s-1) + 0.50×completion",
        f"C          = {BLAST_ASSET_WEIGHT:.2f}×asset_risk + {BLAST_IDENTITY_WEIGHT:.2f}×P_priv",
    ]


def _md_table(headers: list[str], rows: list[list[str]], align: list[str] | None = None) -> list[str]:
    if not rows:
        return []
    align = align or ["left"] * len(headers)
    sep = []
    for spec in align:
        if spec == "right":
            sep.append("---:")
        else:
            sep.append("---")
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(sep) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def render_report_markdown(report: IncidentReportModel) -> str:
    show = lambda value: _show(report, value)
    cell = lambda value: _cell(report, value)
    rank = f"#{report.zeronoise_rank}" if report.zeronoise_rank else "unranked"
    legacy = f"#{report.legacy_rank}" if report.legacy_rank else "—"
    path = " → ".join(f"`{stage}`" if stage != report.attack_path[-1] else f"**`{stage}`**" for stage in report.attack_path) if report.attack_path else "none"
    tags = " ".join(f"`{tag}`" for tag in report.context_tags) or "—"
    sensors = " · ".join(report.sensors) or "—"

    lines = [
        f"# {show(report.title)}",
        "",
        f"> **{report.priority} · Risk {report.risk_score:.1f} · {report.status}**",
        f"> {show(report.engine_title)}",
        "",
        *_md_table(
            ["Field", "Value"],
            [
                ["**Incident**", f"`{cell(report.incident_id)}`"],
                ["**Owner**", cell(report.owner)],
                ["**First seen**", cell(report.first_seen)],
                ["**Last seen**", cell(report.last_seen)],
                ["**Duration**", cell(report.duration)],
                ["**ZeroNoise rank**", f"**{rank}**"],
                ["**Legacy SIEM rank**", legacy],
                ["**Vendor severity**", cell(report.vendor_severity)],
                ["**Sensors**", cell(sensors)],
            ],
        ),
        "",
        f"**Context:** {tags}",
        "",
        "Risk score ≠ vendor severity ≠ probability/confidence",
        "",
        "## Decision brief",
        "",
        "### What happened",
        "",
        show(report.decision_brief.what_happened),
        "",
        "### Why it matters",
        "",
        show(report.decision_brief.why_it_matters),
        "",
        "### What should happen now",
        "",
        "> **Immediate action**",
        ">",
        f"> {show(report.decision_brief.immediate_action)}",
        "",
        "## Key entities",
        "",
    ]
    if report.entities:
        lines.extend(
            _md_table(
                ["Entity", "Value", "Context"],
                [
                    [f"**{cell(row.entity)}**", f"`{cell(row.value)}`", cell(row.context)]
                    for row in report.entities
                ],
            )
        )
    else:
        lines.append("No resolved identities, hosts, or hashes were attached to this incident.")
    lines.extend(["", "## Attack timeline", ""])
    if report.timeline:
        lines.extend(
            _md_table(
                ["Time", "Stage", "Activity", "Sensor", "Evidence"],
                [
                    [
                        cell(row.time),
                        f"**{cell(row.stage)}**",
                        cell(row.activity),
                        cell(row.sensor),
                        f"`[{cell(row.evidence)}]`" if row.evidence else "—",
                    ]
                    for row in report.timeline
                ],
            )
        )
    else:
        lines.append("No timeline rows were generated for this incident.")
    lines.extend(
        [
            "",
            "**Observed attack path**",
            "",
            path,
            "",
            f"## Why ZeroNoise ranked this {rank}",
            "",
            show(report.ranking_explanation),
            "",
        ]
    )
    if report.risk_drivers:
        lines.extend(
            _md_table(
                ["Risk driver", "Contribution", "Why"],
                [
                    [
                        f"**{cell(driver.factor)}**",
                        f"**{driver.contribution_pct}%**" if driver.contribution_pct else f"{driver.contribution_pct}%",
                        cell(driver.why),
                    ]
                    for driver in report.risk_drivers
                ],
                align=["left", "right", "left"],
            )
        )
        lines.extend(
            [
                "",
                "> Contribution percentages explain the score. They are **not incident probabilities**.",
                "",
            ]
        )
    lines.extend(
        [
            "## Why this may be a real attack",
            "",
            show(report.why_real),
            "",
            "## ATT&CK coverage",
            "",
        ]
    )
    lines.extend(
        _md_table(
            ["Stage", "Status", "Evidence"],
            [
                [
                    cell(row.stage),
                    "**Observed**" if row.observed else "Not observed",
                    str(row.evidence_count) if row.observed else "—",
                ]
                for row in report.attack_coverage
            ],
            align=["left", "left", "right"],
        )
    )
    lines.extend(["", "**Techniques**", ""])
    if report.techniques:
        tech_bits = []
        for tech in report.techniques:
            label = f"`{show(tech.technique_id)}`"
            if tech.name:
                label += f" {show(tech.name)}"
            tech_bits.append(label)
        lines.append(" · ".join(tech_bits))
    else:
        lines.append("No mapped techniques.")
    lines.extend(["", "## Recommended work", ""])
    if report.recommendations.groups:
        for heading, actions in report.recommendations.groups.items():
            lines.extend([f"### {heading}", ""])
            for action, checked in actions:
                mark = "x" if checked else " "
                lines.append(f"- [{mark}] {show(action)}")
            lines.append("")
    else:
        lines.append("- No entity-specific actions were generated.")
        lines.append("")
    if report.close_reason:
        lines.extend([f"Close reason: {show(report.close_reason)}", ""])
    lines.extend(
        [
            "> Checking a task records case progress only. It does not perform the action.",
            "",
            "## Evidence linking",
            "",
        ]
    )
    if report.evidence_links:
        lines.extend(
            _md_table(
                ["Shared artifact", "Value", "Supporting alerts"],
                [
                    [cell(row.artifact), f"`{cell(row.value)}`", str(row.supporting_alerts)]
                    for row in report.evidence_links
                ],
                align=["left", "left", "right"],
            )
        )
        lines.extend(
            [
                "",
                "These shared artifacts explain why ZeroNoise grouped the detections into one incident.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "Single-alert incident — no shared identity, host, IP, or hash links.",
                "",
            ]
        )
    if report.context_gaps:
        lines.extend(["## Context gaps", ""])
        for gap in report.context_gaps:
            lines.append(f"- {show(gap)}")
        lines.append("")
    lines.extend(["## Case activity", ""])
    if report.case_activity:
        lines.extend(
            _md_table(
                ["Time", "Actor", "Change"],
                [
                    [cell(row.time), cell(row.actor), cell(row.change)]
                    for row in report.case_activity
                ],
            )
        )
        lines.append("")
    else:
        lines.extend(["No case changes in this session. History is not invented.", ""])
    if report.case_notes:
        lines.extend(["### Case notes", "", show(report.case_notes), ""])
    else:
        lines.extend(["### Case notes", "", "No notes have been saved in this session.", ""])

    calc = report.risk_calculation
    lines.extend(
        [
            "---",
            "",
            "# Technical appendix",
            "",
            "## A. Risk calculation",
            "",
            "```text",
            *_stacked_formula(calc),
            "```",
            "",
        ]
    )
    lines.extend(
        _md_table(
            ["Term", "Value", "Meaning"],
            [
                ["**RawRisk**", f"{calc.raw_risk:.3f}", "B × K × C"],
                ["**B**", f"{calc.fidelity_b:.3f}", "Alert fidelity"],
                ["**K**", f"{calc.progression_k:.3f}", "Kill-chain progression"],
                ["**C**", f"{calc.blast_c:.3f}", "Blast radius"],
                ["**asset_risk**", f"{calc.asset_risk:.3f}", "Host / data sensitivity"],
                ["**identity_risk**", f"{calc.identity_risk:.3f}", "Account privilege"],
                ["**risk_score**", f"{calc.risk_score:.3f}", "Saturating map of RawRisk"],
                ["**scale**", f"{calc.scale:.0f}", "Normalization constant"],
            ],
            align=["left", "right", "left"],
        )
    )
    lines.append("")
    if calc.noise_note:
        lines.extend([f"FPR comparison: {show(calc.noise_note)}", ""])
    lines.extend(
        [
            "Ablation percentages are contribution shares. They are not incident probability.",
            "",
            "## B. Raw detections",
            "",
        ]
    )
    if report.detections:
        lines.extend(
            _md_table(
                ["Time", "Sensor", "Detection", "ATT&CK", "Severity", "Evidence"],
                [
                    [
                        cell(row.time),
                        cell(row.sensor),
                        cell(row.detection),
                        cell(row.technique),
                        cell(row.severity),
                        f"`[{cell(row.evidence)}]`",
                    ]
                    for row in report.detections
                ],
            )
        )
    else:
        lines.append("No detections were attached to this incident.")
    lines.extend(["", "## C. Correlation details", ""])
    if report.correlation_edges:
        lines.extend(
            _md_table(
                ["From", "To", "Link", "Δ min", "Strength"],
                [
                    [
                        f"`{cell(edge.source)}`",
                        f"`{cell(edge.target)}`",
                        cell(edge.link),
                        f"{edge.delta_min:.1f}",
                        f"{edge.strength:.2f}",
                    ]
                    for edge in report.correlation_edges
                ],
            )
        )
        lines.extend(["", "These rows are graph relationships. They are not the shared-artifact summary above.", ""])
    else:
        lines.extend(["No inter-alert edges were recorded.", ""])
    meta = report.export_metadata
    lines.extend(
        [
            "## D. Export metadata",
            "",
            meta.workspace,
            f"Exported {meta.exported_at}.",
            meta.live_or_demo,
            f"Input data sources: {meta.inputs}.",
            meta.risk_disclaimer,
            meta.masking_disclaimer,
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def analyst_prose_fields(report: IncidentReportModel) -> list[str]:
    fields = [
        report.decision_brief.what_happened,
        report.decision_brief.why_it_matters,
        report.ranking_explanation,
        report.why_real,
        report.decision_brief.immediate_action,
    ]
    fields.extend(driver.why for driver in report.risk_drivers if driver.why)
    for actions in report.recommendations.groups.values():
        fields.extend(action for action, _ in actions)
    return fields
