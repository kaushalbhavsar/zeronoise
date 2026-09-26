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
