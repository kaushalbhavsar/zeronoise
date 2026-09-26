"""Analyst-facing labels derived from incident facts.

scenario_id is never read. Badges, rank deltas, and correlation
sentences are produced from CMDB/IAM/ATT&CK/edges only.
"""

from __future__ import annotations

from engine.schemas import EnrichedAlert, GraphEdge, IncidentCard, RiskDriver, ScoredIncident

DRIVER_LABELS = {
    "Alert Fidelity": "Alert Fidelity",
    "Kill-Chain Progression": "Kill-Chain Progression",
    "Blast Radius": "Blast Radius",
    "FP/Noise Suppression": "Noise / FP Suppression",
}

HIGH_FP_THRESHOLD = 0.60
PRIVILEGED_TIERS = frozenset({"tier_0_domain_admin", "tier_1_cloud_admin"})


def _assets(item: ScoredIncident):
    assets = []
    for alert in item.incident.alerts:
        if alert.asset:
            assets.append(alert.asset)
        if alert.dest_asset:
            assets.append(alert.dest_asset)
    return assets


def _identities(item: ScoredIncident):
    return [alert.identity for alert in item.incident.alerts if alert.identity]


def context_badges(item: ScoredIncident) -> list[str]:
    """Labels from live context. Never keyed on scenario_id."""
    badges: list[str] = []
    assets = _assets(item)
    identities = _identities(item)
    tactics = set(item.incident.unique_tactics)
    envs = {asset.environment for asset in assets}
    sensitivities = {asset.data_sensitivity for asset in assets}
    events = max(1, item.incident.total_event_count)
    mean_fpr = (
        sum(alert.false_positive_rate * alert.event_count for alert in item.incident.alerts)
        / events
    )

    if "crown_jewel_pii_pci" in sensitivities:
        badges.append("Crown Jewel")
    if "prod" in envs:
        badges.append("Production")
    if "crown_jewel_pii_pci" in sensitivities or "confidential" in sensitivities:
        badges.append("PCI/PII")
    if any(ident.privilege_tier == "tier_0_domain_admin" for ident in identities):
        badges.append("Tier-0 Admin")
    elif any(ident.privilege_tier in PRIVILEGED_TIERS for ident in identities):
        badges.append("Privileged Identity")
    if "Exfiltration" in tactics:
        badges.append("Exfiltration")
    if "Impact" in tactics:
        badges.append("Impact")
    if len(item.incident.unique_products) >= 2:
        badges.append("Cross-Sensor")
    if mean_fpr >= HIGH_FP_THRESHOLD:
        badges.append("High FP Rule")
    if "sandbox" in envs and "prod" not in envs:
        badges.append("Sandbox")
    return badges


def rank_delta(ai_rank: int | None, legacy_rank: int | None) -> int | None:
    if not ai_rank or not legacy_rank:
        return None
    return legacy_rank - ai_rank


def rank_delta_label(delta: int | None) -> str:
    if delta is None:
        return "—"
    if delta > 0:
        return f"↑ {delta} position{'s' if delta != 1 else ''}"
    if delta < 0:
        return f"↓ {abs(delta)} position{'s' if delta != -1 else ''}"
    return "same rank"


def driver_rows(card: IncidentCard) -> list[RiskDriver]:
    return list(card.why_prioritized or card.risk.drivers)


def driver_label(factor: str) -> str:
    return DRIVER_LABELS.get(factor, factor)


def _alert_by_id(item: ScoredIncident) -> dict[str, EnrichedAlert]:
    return {alert.alert_id: alert for alert in item.incident.alerts}


def _shared_user(left: EnrichedAlert, right: EnrichedAlert) -> str | None:
    if left.entities.user_id and left.entities.user_id == right.entities.user_id:
        return left.entities.user_id
    return None


def _hosts(alert: EnrichedAlert) -> set[str]:
    return {
        value
        for value in (
            alert.entities.host_id,
            alert.asset.host_id if alert.asset else None,
            alert.dest_asset.host_id if alert.dest_asset else None,
        )
        if value
    }


def _shared_host(left: EnrichedAlert, right: EnrichedAlert) -> str | None:
    shared = _hosts(left) & _hosts(right)
    return sorted(shared)[0] if shared else None


def _shared_ip(left: EnrichedAlert, right: EnrichedAlert) -> str | None:
    if left.entities.src_ip and left.entities.src_ip == right.entities.src_ip:
        return left.entities.src_ip
    return None


def _shared_hash(left: EnrichedAlert, right: EnrichedAlert) -> str | None:
    if left.entities.process_hash and left.entities.process_hash == right.entities.process_hash:
        return left.entities.process_hash
    return None


def describe_edge(edge: GraphEdge, item: ScoredIncident) -> str:
    by_id = _alert_by_id(item)
    left = by_id.get(edge.source_alert_id)
    right = by_id.get(edge.target_alert_id)
    if edge.relationship_type == "SHARED_IDENTITY":
        user = _shared_user(left, right) if left and right else None
        return f"Shared identity: {user}" if user else "Shared identity"
    if edge.relationship_type == "SHARED_HOST":
        host = _shared_host(left, right) if left and right else None
        return f"Shared host: {host}" if host else "Shared host"
    if edge.relationship_type == "DESTINATION_PIVOT":
        return "Destination IP became source/pivot"
    if edge.relationship_type == "HOST_IP_PIVOT":
        return "Destination IP resolved to the later host"
    if edge.relationship_type == "SHARED_ATTACKER_IP":
        ip = _shared_ip(left, right) if left and right else None
        return f"Shared attacker IP: {ip}" if ip else "Shared attacker IP"
    if edge.relationship_type == "PROCESS_HASH":
        digest = _shared_hash(left, right) if left and right else None
        return f"Shared process hash: {digest}" if digest else "Shared process hash"
    return edge.relationship_type.replace("_", " ").title()


def raw_alert_ids(item: ScoredIncident) -> list[str]:
    """Deduplicated survivor → original SIEM row IDs, order preserved."""
    originals: list[str] = []
    seen: set[str] = set()
    for alert in item.incident.alerts:
        members = alert.original_alert_ids or alert.member_alert_ids or [alert.alert_id]
        for alert_id in members:
            if alert_id not in seen:
                seen.add(alert_id)
                originals.append(alert_id)
    return originals


def correlation_evidence(item: ScoredIncident) -> list[dict[str, str]]:
    """Why these alerts were grouped — one row per graph edge."""
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for edge in item.incident.edges:
        key = (edge.source_alert_id, edge.target_alert_id, edge.relationship_type)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "from": edge.source_alert_id,
                "to": edge.target_alert_id,
                "reason": describe_edge(edge, item),
            }
        )
    return rows


def grouped_correlation_evidence(item: ScoredIncident) -> list[dict[str, object]]:
    """One pair of alerts with every observed relationship."""
    groups: dict[tuple[str, str], list[str]] = {}
    order: list[tuple[str, str]] = []
    for row in correlation_evidence(item):
        pair = (row["from"], row["to"])
        if pair not in groups:
            groups[pair] = []
            order.append(pair)
        if row["reason"] not in groups[pair]:
            groups[pair].append(row["reason"])
    return [{"from": left, "to": right, "reasons": groups[(left, right)]} for left, right in order]


ACTION_GROUPS = ("Validate", "Contain", "Preserve", "Recover")


def group_recommended_actions(actions: list[str]) -> dict[str, list[str]]:
    """Bucket analyst steps. Recording completion is not executing infra."""
    buckets: dict[str, list[str]] = {name: [] for name in ACTION_GROUPS}
    for action in actions:
        lower = action.lower()
        if any(token in lower for token in ("preserve", "telemetry", "forensic", "snapshot")):
            buckets["Preserve"].append(action)
        elif any(token in lower for token in ("recover", "restore", "reimage")):
            buckets["Recover"].append(action)
        elif any(
            token in lower
            for token in (
                "review",
                "validate",
                "authentication",
                "high-fp",
                "cmdb",
                "before paging",
                "before closing",
            )
        ):
            buckets["Validate"].append(action)
        else:
            buckets["Contain"].append(action)
    return buckets


def urgency_sentence(item: ScoredIncident) -> str:
    """One factual sentence for why this card is at the top of the queue."""
    tactics = set(item.incident.unique_tactics)
    badges = context_badges(item)
    asset = item.incident.unique_hosts[0] if item.incident.unique_hosts else "an unresolved host"
    if "Exfiltration" in tactics and "Crown Jewel" in badges:
        return f"Observed exfiltration involving {asset}, a crown-jewel production system."
    if "Impact" in tactics:
        return f"Destructive activity is in progress on {asset}."
    if "Lateral Movement" in tactics and "Credential Access" in tactics:
        return f"Credential access is followed by lateral movement on {asset}."
    if "High FP Rule" in badges and "Sandbox" in badges:
        return f"High-volume Critical alerts are concentrated on sandbox host {asset}."
    if tactics:
        return f"Observed {' → '.join(item.incident.unique_tactics)} on {asset}."
    return f"{item.incident.total_event_count} raw events collapsed into this incident."


def badge_tone(name: str) -> str:
    """Production is context, not a healthy state."""
    if name in {"Crown Jewel", "Tier-0 Admin", "Exfiltration", "Impact"}:
        return "hot"
    if name in {"High FP Rule", "Sandbox"}:
        return "warn"
    return "ctx"


def review_reduction_label(raw_alert_count: int, incident_count: int) -> str:
    """Volume compression of alerts → incidents. Not measured fatigue."""
    if raw_alert_count <= 0:
        return "No alerts in this snapshot"
    pct = round(100.0 * (1.0 - incident_count / raw_alert_count))
    return f"{pct}% fewer items to review"


def significant_rank_moves(
    items: list[ScoredIncident],
    *,
    min_abs_delta: int = 5,
) -> list[ScoredIncident]:
    """Incidents whose AI rank differs from legacy by at least min_abs_delta."""
    moved: list[ScoredIncident] = []
    for item in items:
        delta = rank_delta(item.risk_rank, item.naive_siem_rank)
        if delta is not None and abs(delta) >= min_abs_delta:
            moved.append(item)
    moved.sort(key=lambda item: (-abs(rank_delta(item.risk_rank, item.naive_siem_rank) or 0), item.risk_rank or 0))
    return moved


def parse_timeline_line(line: str) -> dict[str, str]:
    """Split a deterministic timeline line into clock, alert id, tactic, detail."""
    head, sep, tail = line.partition(" — ")
    if not sep:
        return {"clock": "", "alert_id": "", "tactic": "", "detail": line}
    if "]" not in head:
        return {"clock": "", "alert_id": "", "tactic": "", "detail": line}
    prefix, tactic = head.rsplit("]", 1)
    clock = prefix.split("[")[0].strip()
    alert_id = prefix.split("[", 1)[1].rstrip("]").strip()
    return {
        "clock": clock,
        "alert_id": alert_id,
        "tactic": tactic.strip(),
        "detail": tail.strip(),
    }


def exposed_assets(item: ScoredIncident) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for alert in item.incident.alerts:
        for asset in (alert.asset, alert.dest_asset):
            if not asset or asset.host_id in seen:
                continue
            seen.add(asset.host_id)
            lines.append(
                f"{asset.hostname} ({asset.host_id}) · {asset.environment} · "
                f"{asset.data_sensitivity} · crit {asset.business_criticality}"
            )
    if not lines:
        for host in item.incident.unique_hosts:
            lines.append(f"{host} · environment not resolved in CMDB")
    return lines


def exposed_identities(item: ScoredIncident) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for alert in item.incident.alerts:
        ident = alert.identity
        if not ident or ident.user_id in seen:
            continue
        seen.add(ident.user_id)
        lines.append(f"{ident.user_id} · {ident.department} · {ident.privilege_tier}")
    if not lines:
        for user in item.incident.unique_users:
            lines.append(f"{user} · privilege not resolved in IAM")
    return lines


def why_this_matters(item: ScoredIncident) -> str:
    """Inferred assessment. Not an observed fact and not a business-impact estimate."""
    badges = set(context_badges(item))
    tactics = set(item.incident.unique_tactics)
    if "Exfiltration" in tactics and "Crown Jewel" in badges:
        return (
            "Assessment: observed exfiltration involves a crown-jewel system, "
            "so data exposure is the primary concern. Confirm destination and volume "
            "on the cited timeline before treating this as confirmed theft."
        )
    if "Impact" in tactics:
        return (
            "Assessment: Impact-stage activity can destroy recoverability. "
            "The mapped sequence supports urgency; confirm the host is still reachable."
        )
    if "High FP Rule" in badges and "Sandbox" in badges:
        return (
            "Assessment: volume is high but the host is sandbox-only and the rule "
            "has a high historical false-positive rate. This may be noise."
        )
    if "Lateral Movement" in tactics and "Credential Access" in tactics:
        return (
            "Assessment: credential access followed by lateral movement is consistent "
            "with an expanding intrusion. Privilege and destination still need confirmation."
        )
    if "Crown Jewel" in badges or "PCI/PII" in badges:
        return (
            "Assessment: a sensitive asset is in scope, so the incident outranks "
            "volume-only noise even when vendor severity is moderate."
        )
    return (
        "Assessment: ranking reflects fidelity, kill-chain depth, and asset or "
        "identity context — not raw alert count. Uncertainty remains until "
        "independent sensors or later stages appear."
    )


def evidence_summary(item: ScoredIncident) -> str:
    sensors = ", ".join(item.incident.unique_products) or "no mapped sensors"
    tactics = " → ".join(item.incident.unique_tactics) or "no mapped tactics"
    return (
        f"{len(item.incident.alerts)} deduplicated events from {sensors} "
        f"({item.incident.total_event_count} raw). Mapped sequence: {tactics}."
    )


def next_recommended_action(card: IncidentCard) -> str:
    actions = card.recommended_actions or card.containment
    if actions:
        return actions[0]
    return "Review the timeline and assign an owner before closing."
