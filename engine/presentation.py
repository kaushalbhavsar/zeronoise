"""Analyst-facing labels derived from incident facts.

scenario_id is never read. Badges, rank deltas, and correlation
sentences are produced from CMDB/IAM/ATT&CK/edges only.
"""

from __future__ import annotations

from datetime import timezone

from engine.readability import enforce_readability
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


def _edge_fact(edge: GraphEdge, item: ScoredIncident) -> tuple[str, str]:
    by_id = _alert_by_id(item)
    left = by_id.get(edge.source_alert_id)
    right = by_id.get(edge.target_alert_id)
    if edge.relationship_type == "SHARED_IDENTITY":
        return "Shared identity", _shared_user(left, right) or "—"
    if edge.relationship_type == "SHARED_HOST":
        return "Shared host", _shared_host(left, right) or "—"
    if edge.relationship_type == "SHARED_ATTACKER_IP":
        return "Shared source IP", _shared_ip(left, right) or "—"
    if edge.relationship_type == "PROCESS_HASH":
        return "Shared process hash", _shared_hash(left, right) or "—"
    if edge.relationship_type == "DESTINATION_PIVOT":
        dest = left.entities.dest_ip if left else None
        return "Destination became source", dest or "—"
    if edge.relationship_type == "HOST_IP_PIVOT":
        dest = left.entities.dest_ip if left else None
        return "Destination resolved to host", dest or "—"
    return edge.relationship_type.replace("_", " ").title(), "—"


def link_evidence(item: ScoredIncident) -> list[dict[str, object]]:
    """Correlation collapsed onto the shared fact, not onto alert-id pairs."""
    buckets: dict[tuple[str, str], set[str]] = {}
    order: list[tuple[str, str]] = []
    for edge in item.incident.edges:
        kind, value = _edge_fact(edge, item)
        key = (kind, value)
        if key not in buckets:
            buckets[key] = set()
            order.append(key)
        buckets[key].add(edge.source_alert_id)
        buckets[key].add(edge.target_alert_id)
    rows = []
    for key in order:
        kind, value = key
        alert_ids = sorted(buckets[key])
        rows.append(
            {
                "fact": kind,
                "value": value,
                "event_count": len(alert_ids),
                "alert_ids": alert_ids,
            }
        )
    rows.sort(key=lambda row: (-int(row["event_count"]), str(row["fact"]), str(row["value"])))
    return rows


def observable_evidence(item: ScoredIncident) -> dict[str, list[dict[str, object]]]:
    """Observed artifacts that support the assessment. Alert IDs are citations, not the evidence."""
    identities: dict[str, dict[str, object]] = {}
    hosts: dict[str, dict[str, object]] = {}
    network: dict[tuple[str, str], dict[str, object]] = {}
    hashes: dict[str, dict[str, object]] = {}
    detections: list[dict[str, object]] = []
    gaps: list[str] = []

    for alert in sorted(
        item.incident.alerts,
        key=lambda item_alert: (item_alert.first_seen or item_alert.timestamp, item_alert.alert_id),
    ):
        sensors = {alert.source_product}
        if alert.identity or alert.entities.user_id:
            user = (alert.identity.user_id if alert.identity else None) or alert.entities.user_id
            if user:
                row = identities.setdefault(
                    user,
                    {
                        "identity": user,
                        "department": alert.identity.department if alert.identity else "—",
                        "privilege": alert.identity.privilege_tier if alert.identity else "unresolved",
                        "sensors": set(),
                        "tactics": set(),
                    },
                )
                row["sensors"].update(sensors)
                row["tactics"].add(alert.mitre_tactic)
        for asset, role in ((alert.asset, "source"), (alert.dest_asset, "destination")):
            host = None
            if asset:
                host = asset.host_id
                row = hosts.setdefault(
                    host,
                    {
                        "host": asset.host_id,
                        "hostname": asset.hostname,
                        "environment": asset.environment,
                        "data": asset.data_sensitivity,
                        "criticality": asset.business_criticality,
                        "roles": set(),
                        "sensors": set(),
                    },
                )
                row["roles"].add(role)
                row["sensors"].update(sensors)
            elif role == "source" and alert.entities.host_id:
                host = alert.entities.host_id
                row = hosts.setdefault(
                    host,
                    {
                        "host": host,
                        "hostname": "—",
                        "environment": "unresolved",
                        "data": "unresolved",
                        "criticality": "—",
                        "roles": set(),
                        "sensors": set(),
                    },
                )
                row["roles"].add(role)
                row["sensors"].update(sensors)
        if alert.entities.src_ip:
            row = network.setdefault(
                ("source", alert.entities.src_ip),
                {"direction": "source", "ip": alert.entities.src_ip, "sensors": set(), "gaps": set()},
            )
            row["sensors"].update(sensors)
        if alert.entities.dest_ip:
            row = network.setdefault(
                ("destination", alert.entities.dest_ip),
                {"direction": "destination", "ip": alert.entities.dest_ip, "sensors": set(), "gaps": set()},
            )
            row["sensors"].update(sensors)
            if any(gap.startswith("unknown_dest_ip") for gap in alert.context_gaps):
                row["gaps"].add("not in CMDB")
        if alert.entities.process_hash:
            row = hashes.setdefault(
                alert.entities.process_hash,
                {"hash": alert.entities.process_hash, "sensors": set(), "rules": set()},
            )
            row["sensors"].update(sensors)
            row["rules"].add(alert.rule_name)
        gaps.extend(alert.context_gaps)
        detections.append(
            {
                "when": (alert.first_seen or alert.timestamp)
                .astimezone(timezone.utc)
                .strftime("%H:%M:%SZ"),
                "sensor": alert.source_product,
                "what_was_observed": alert.rule_name,
                "tactic": alert.mitre_tactic,
                "technique": alert.mitre_technique,
                "vendor_severity": alert.severity_raw,
                "identity": alert.entities.user_id or "—",
                "host": alert.entities.host_id or "—",
                "src_ip": alert.entities.src_ip or "—",
                "dest_ip": alert.entities.dest_ip or "—",
                "process_hash": alert.entities.process_hash or "—",
                "raw_events": alert.event_count,
                "alert_id": alert.alert_id,
            }
        )

    def _freeze(rows: list[dict]) -> list[dict]:
        frozen = []
        for row in rows:
            item_row = dict(row)
            for key, value in list(item_row.items()):
                if isinstance(value, set):
                    item_row[key] = ", ".join(sorted(value)) if value else "—"
            frozen.append(item_row)
        return frozen

    return {
        "identities": _freeze(list(identities.values())),
        "hosts": _freeze(list(hosts.values())),
        "network": _freeze(list(network.values())),
        "hashes": _freeze(list(hashes.values())),
        "detections": detections,
        "gaps": sorted(set(gaps)),
    }


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
    roles = incident_roles(item)
    asset = roles["affected_asset"] if roles["affected_asset"] != "—" else "an unresolved host"
    if "Exfiltration" in tactics and "Crown Jewel" in badges:
        text = f"Sensors saw data leave {asset}. That system stores sensitive data."
    elif "Impact" in tactics:
        text = f"Harmful changes are running on {asset}."
    elif "Lateral Movement" in tactics and "Credential Access" in tactics:
        text = f"Stolen credentials were used. The attacker then moved toward {asset}."
    elif "High FP Rule" in badges and "Sandbox" in badges:
        text = f"Many Critical alerts hit sandbox host {asset}."
    elif tactics:
        first = item.incident.unique_tactics[0]
        last = item.incident.unique_tactics[-1]
        if first == last:
            text = f"We saw {first} on {asset}."
        else:
            text = f"We saw {first}, then {last}, on {asset}."
    else:
        text = f"{item.incident.total_event_count} raw alerts became this incident."
    return enforce_readability(text, f"Review the activity on {asset}.")


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
        text = (
            "This incident ranks high because data left a sensitive system. "
            "Confirm the destination and size on the timeline. "
            "Do not treat this as proven theft yet."
        )
    elif "Impact" in tactics:
        text = (
            "Impact activity can wipe backups. "
            "Confirm the host is still online."
        )
    elif "High FP Rule" in badges and "Sandbox" in badges:
        text = (
            "Many alerts fired. The host is only a sandbox. "
            "The rule is often wrong. This may be noise."
        )
    elif "Lateral Movement" in tactics and "Credential Access" in tactics:
        text = (
            "The attacker stole credentials. They then moved to another host. "
            "Confirm the privilege and the destination."
        )
    elif "Crown Jewel" in badges or "PCI/PII" in badges:
        text = (
            "A sensitive system is in scope. "
            "That is why this ranks above noisy volume."
        )
    else:
        text = (
            "We rank by alert quality, attack depth, and the system at risk. "
            "We do not rank by alert count alone."
        )
    return enforce_readability(text, "This incident needs review. Check the timeline.")


def evidence_summary(item: ScoredIncident) -> str:
    sensors = ", ".join(item.incident.unique_products) or "no mapped sensors"
    tactics = " → ".join(item.incident.unique_tactics) or "no mapped tactics"
    return enforce_readability(
        f"{len(item.incident.alerts)} alerts came from {sensors}. They map to {tactics}.",
        f"{len(item.incident.alerts)} alerts support this incident.",
    )


def next_recommended_action(card: IncidentCard) -> str:
    actions = card.recommended_actions or card.containment
    if actions:
        return actions[0]
    return "Review the timeline. Then assign an owner before you close the case."


def vendor_severity(item: ScoredIncident) -> str:
    return item.incident.max_severity


def incident_roles(item: ScoredIncident) -> dict[str, str]:
    """Roles used by the queue, title, brief, and evidence — same facts everywhere.

    Distinguishes initial identity, privileged identity, source host, and destination.
    Title asset matches the risk-scorer title (highest-sensitivity resolved asset).
    """
    from engine.risk_config import get_active_risk_config

    cfg = get_active_risk_config()

    alerts = sorted(
        item.incident.alerts,
        key=lambda alert: (alert.first_seen or alert.timestamp, alert.alert_id),
    )
    initial_identity = "—"
    for alert in alerts:
        user = alert.entities.user_id or (alert.identity.user_id if alert.identity else None)
        if user:
            initial_identity = user
            break

    privileged_identity = "—"
    priv_score = -1.0
    for alert in item.incident.alerts:
        ident = alert.identity
        if not ident:
            continue
        score = cfg.privilege_weight(ident.privilege_tier)
        if score > priv_score:
            priv_score = score
            privileged_identity = ident.user_id

    source_host = "—"
    for alert in alerts:
        host = alert.entities.host_id or (alert.asset.host_id if alert.asset else None)
        if host:
            source_host = host
            break

    destination = "—"
    for alert in alerts:
        if alert.dest_asset and alert.mitre_tactic == "Exfiltration":
            destination = alert.dest_asset.host_id
            break
    if destination == "—":
        for alert in reversed(alerts):
            if alert.dest_asset:
                destination = alert.dest_asset.host_id
                break

    title_asset = "—"
    title_score = -1.0
    for alert in item.incident.alerts:
        for asset in (alert.asset, alert.dest_asset):
            if not asset:
                continue
            score = cfg.data_weight(asset.data_sensitivity) + cfg.environment_weight(
                asset.environment
            )
            if score > title_score:
                title_score = score
                title_asset = asset.hostname
    if title_asset == "—" and item.incident.unique_hosts:
        title_asset = item.incident.unique_hosts[0]

    title_identity = privileged_identity if privileged_identity != "—" else initial_identity
    if title_identity == "—" and item.incident.unique_users:
        title_identity = item.incident.unique_users[0]

    return {
        "initial_identity": initial_identity,
        "privileged_identity": privileged_identity,
        "source_host": source_host,
        "destination": destination,
        "affected_asset": title_asset,
        "title_identity": title_identity,
    }


def mask_identifier(value: str | None) -> str:
    """Presentation masking only — not access control."""
    if not value or value in {"—", "Unassigned", "You"}:
        return value or "—"
    if value.replace(".", "").isdigit() and value.count(".") == 3:
        a, b, _, _ = value.split(".")
        return f"{a}.{b}.x.x"
    if len(value) <= 4:
        return "••••"
    return f"{value[:4]}••••"


def mask_text(text: str, tokens: list[str] | tuple[str, ...], enabled: bool) -> str:
    """Replace known identifiers in prose. Presentation only."""
    if not enabled or not text:
        return text
    out = text
    for token in sorted({item for item in tokens if item}, key=len, reverse=True):
        if token in {"—", "Unassigned", "You"}:
            continue
        out = out.replace(token, mask_identifier(token))
    return out


def role_tokens(item: ScoredIncident) -> list[str]:
    roles = incident_roles(item)
    tokens = [item.incident.incident_id, item.title, *roles.values()]
    tokens.extend(item.incident.unique_users)
    tokens.extend(item.incident.unique_hosts)
    for alert in item.incident.alerts:
        tokens.append(alert.alert_id)
        if alert.entities.src_ip:
            tokens.append(alert.entities.src_ip)
        if alert.entities.dest_ip:
            tokens.append(alert.entities.dest_ip)
        if alert.asset:
            tokens.extend([alert.asset.host_id, alert.asset.hostname, alert.asset.ip_address])
        if alert.dest_asset:
            tokens.extend(
                [alert.dest_asset.host_id, alert.dest_asset.hostname, alert.dest_asset.ip_address]
            )
    return [token for token in tokens if token]


METRIC_DEFINITIONS = {
    "open": (
        "Organization-wide snapshot, not the current queue filter. "
        "Window: this demo reporting period. "
        "Calculation: cases whose session status is New, Acknowledged, Investigating, or Escalated."
    ),
    "p0_p1": (
        "Organization-wide snapshot, not the current queue filter. "
        "Window: this demo reporting period. "
        "Calculation: open cases with risk_score ≥ 70 (P0 ≥ 85, P1 ≥ 70). Not vendor severity."
    ),
    "unacked": (
        "Organization-wide snapshot, not the current queue filter. "
        "Window: this demo reporting period. "
        "Calculation: open cases whose session status is still New."
    ),
    "assigned": (
        "Organization-wide snapshot, not the current queue filter. "
        "Window: this demo reporting period. "
        "Calculation: open cases whose session owner is not Unassigned."
    ),
    "prod": (
        "Organization-wide snapshot, not the current queue filter. "
        "Window: this demo reporting period. "
        "Calculation: open cases with at least one CMDB asset in environment=prod. "
        "Production is scope, not a healthy state."
    ),
    "matching": (
        "Current queue filters only. "
        "Window: this demo reporting period. "
        "Calculation: incidents remaining after preset, search, priority, status, and environment filters."
    ),
    "raw": (
        "Organization-wide snapshot. Window: this demo reporting period. "
        "Calculation: raw SIEM rows loaded from the JSONL file before dedup."
    ),
    "dedup": (
        "Organization-wide snapshot. Window: this demo reporting period. "
        "Calculation: survivors after rule+entity collapse inside the 15-minute window."
    ),
    "incidents": (
        "Organization-wide snapshot. Window: this demo reporting period. "
        "Calculation: correlated connected components after the 4-hour join window."
    ),
    "high": (
        "Organization-wide snapshot. Window: this demo reporting period. "
        "Calculation: pipeline high_priority_count (risk-based), not vendor Critical."
    ),
    "edges": (
        "Organization-wide snapshot. Window: this demo reporting period. "
        "Calculation: incidents that have at least one inter-alert correlation edge."
    ),
}
