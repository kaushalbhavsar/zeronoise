"""Normalize vendor-shaped alerts and enrich them from CMDB / IAM.

Deduplication collapses repetitive bursts. scenario_id is preserved on the
record for demo validation only and is never consulted here for grouping.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from dateutil.parser import isoparse

from config import DEDUP_WINDOW_MINUTES
from engine.schemas import AlertEntities, Asset, EnrichedAlert, Identity, RawAlert

PRODUCT_ALIASES: dict[str, str] = {
    "crowdstrike": "EDR",
    "edr": "EDR",
    "okta": "IAM",
    "iam": "IAM",
    "azure ad": "IAM",
    "entra": "IAM",
    "darktrace": "NDR",
    "ndr": "NDR",
    "zeek": "NDR",
    "f5": "WAF",
    "waf": "WAF",
    "cloudflare": "WAF",
    "symantec dlp": "DLP",
    "dlp": "DLP",
    "splunk": "SIEM",
    "siem": "SIEM",
    "qradar": "SIEM",
}

TACTIC_ALIASES: dict[str, str] = {
    "initial-access": "Initial Access",
    "initial access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "privilege escalation": "Privilege Escalation",
    "credential-access": "Credential Access",
    "credential access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "lateral movement": "Lateral Movement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

SEVERITY_ALIASES: dict[str, str] = {
    "low": "Low",
    "info": "Low",
    "informational": "Low",
    "1": "Low",
    "medium": "Medium",
    "med": "Medium",
    "2": "Medium",
    "high": "High",
    "3": "High",
    "critical": "Critical",
    "crit": "Critical",
    "4": "Critical",
    "5": "Critical",
}


def _as_dt(value: datetime | str | None) -> datetime:
    if value is None:
        raise ValueError("alert is missing a timestamp")
    if isinstance(value, datetime):
        dt = value
    else:
        dt = isoparse(str(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _pick(*values: object) -> object | None:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _severity(raw: object | None) -> str:
    if raw is None:
        return "Medium"
    key = str(raw).strip().lower()
    if key in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[key]
    try:
        numeric = float(key)
    except ValueError as exc:
        raise ValueError(f"unsupported severity: {raw!r}") from exc
    if numeric <= 1:
        return "Low"
    if numeric <= 2:
        return "Medium"
    if numeric <= 3:
        return "High"
    return "Critical"


def _product(raw: object | None) -> str:
    if raw is None:
        raise ValueError("alert is missing a source product")
    key = str(raw).strip().lower()
    if key in PRODUCT_ALIASES:
        return PRODUCT_ALIASES[key]
    raise ValueError(f"unsupported source product: {raw!r}")


def _tactic(raw: object | None) -> str:
    if raw is None:
        raise ValueError("alert is missing a MITRE tactic")
    key = str(raw).strip().lower()
    if key in TACTIC_ALIASES:
        return TACTIC_ALIASES[key]
    raise ValueError(f"unsupported MITRE tactic: {raw!r}")


def _clamp01(value: object | None, default: float) -> float:
    if value is None:
        return default
    return min(1.0, max(0.0, float(value)))


def normalize_raw(raw: dict | RawAlert) -> EnrichedAlert:
    payload = raw if isinstance(raw, RawAlert) else RawAlert.model_validate(raw)
    entities = payload.entities
    if isinstance(entities, dict):
        entities = AlertEntities.model_validate(entities)
    if entities is None:
        entities = AlertEntities()
    entities = AlertEntities(
        user_id=_pick(entities.user_id, payload.user_id),
        host_id=_pick(entities.host_id, payload.host_id),
        src_ip=_pick(entities.src_ip, payload.src_ip),
        dest_ip=_pick(entities.dest_ip, payload.dest_ip),
        process_hash=_pick(entities.process_hash, payload.process_hash),
    )
    alert_id = str(_pick(payload.alert_id, payload.id) or "")
    if not alert_id:
        raise ValueError("alert is missing an id")
    rule = str(_pick(payload.rule_name, payload.signature) or "").strip()
    if not rule:
        raise ValueError(f"{alert_id}: missing rule name")
    technique = str(_pick(payload.mitre_technique, payload.technique) or "").strip()
    if not technique:
        raise ValueError(f"{alert_id}: missing MITRE technique")
    return EnrichedAlert(
        alert_id=alert_id,
        timestamp=_as_dt(_pick(payload.timestamp, payload.time)),
        source_product=_product(_pick(payload.source_product, payload.product, payload.vendor)),
        rule_name=rule,
        severity_raw=_severity(_pick(payload.severity_raw, payload.severity, payload.sev)),
        confidence=_clamp01(payload.confidence, 0.5),
        false_positive_rate=_clamp01(_pick(payload.false_positive_rate, payload.fp_rate), 0.35),
        mitre_tactic=_tactic(_pick(payload.mitre_tactic, payload.tactic)),
        mitre_technique=technique,
        entities=entities,
        event_count=max(1, payload.event_count),
        scenario_id=payload.scenario_id,
        member_alert_ids=[alert_id],
    )


class ContextIndex:
    def __init__(self, assets: Iterable[Asset], identities: Iterable[Identity]) -> None:
        self.by_host = {asset.host_id: asset for asset in assets}
        self.by_ip = {asset.ip_address: asset for asset in self.by_host.values()}
        self.by_user = {identity.user_id: identity for identity in identities}

    def resolve_asset(self, host_id: str | None, ip: str | None) -> Asset | None:
        if host_id and host_id in self.by_host:
            return self.by_host[host_id]
        if ip and ip in self.by_ip:
            return self.by_ip[ip]
        return None

    def enrich(self, alert: EnrichedAlert) -> EnrichedAlert:
        asset = self.resolve_asset(alert.entities.host_id, alert.entities.src_ip)
        dest_asset = self.resolve_asset(None, alert.entities.dest_ip)
        if dest_asset and asset is None:
            asset = dest_asset
        identity = self.by_user.get(alert.entities.user_id or "")
        updates: dict = {"asset": asset, "dest_asset": dest_asset, "identity": identity}
        # Entity resolution: promote CMDB host_id onto the alert so later
        # correlation joins IP-only and host-id observations of the same asset.
        if asset and not alert.entities.host_id:
            updates["entities"] = alert.entities.model_copy(update={"host_id": asset.host_id})
        return alert.model_copy(update=updates)


def enrich_alerts(
    alerts: Iterable[EnrichedAlert],
    assets: Iterable[Asset],
    identities: Iterable[Identity],
) -> list[EnrichedAlert]:
    index = ContextIndex(assets, identities)
    enriched = [index.enrich(alert) for alert in alerts]
    enriched.sort(key=lambda a: (a.timestamp, a.alert_id))
    return enriched


def _dedup_key(alert: EnrichedAlert) -> tuple[str, ...]:
    ent = alert.entities
    return (
        alert.rule_name,
        ent.user_id or "",
        ent.host_id or "",
        ent.src_ip or "",
        ent.dest_ip or "",
    )


def deduplicate_alerts(
    alerts: Iterable[EnrichedAlert],
    window_minutes: int = DEDUP_WINDOW_MINUTES,
) -> list[EnrichedAlert]:
    """Collapse same-rule, same-entity bursts inside the dedup window.

    The surviving alert keeps the earliest timestamp, the maximum confidence,
    the mean false-positive rate, and a summed event_count. Member IDs are
    retained for analyst traceability.
    """
    ordered = sorted(alerts, key=lambda a: (a.timestamp, a.alert_id))
    buckets: dict[tuple[str, ...], list[EnrichedAlert]] = {}
    for alert in ordered:
        key = _dedup_key(alert)
        family = buckets.setdefault(key, [])
        merged = False
        window_seconds = window_minutes * 60
        for idx, existing in enumerate(family):
            delta = abs((alert.timestamp - existing.timestamp).total_seconds())
            if delta <= window_seconds:
                members = list(existing.member_alert_ids or [existing.alert_id])
                members.extend(alert.member_alert_ids or [alert.alert_id])
                total = existing.event_count + alert.event_count
                mean_fpr = (
                    existing.false_positive_rate * existing.event_count
                    + alert.false_positive_rate * alert.event_count
                ) / total
                family[idx] = existing.model_copy(
                    update={
                        "event_count": total,
                        "confidence": max(existing.confidence, alert.confidence),
                        "false_positive_rate": min(1.0, mean_fpr),
                        "member_alert_ids": members,
                    }
                )
                merged = True
                break
        if not merged:
            family.append(
                alert.model_copy(
                    update={"member_alert_ids": list(alert.member_alert_ids or [alert.alert_id])}
                )
            )
    collapsed = [alert for family in buckets.values() for alert in family]
    collapsed.sort(key=lambda a: (a.timestamp, a.alert_id))
    return collapsed


def normalize_and_enrich(
    raw_alerts: Iterable[dict],
    assets: Iterable[Asset] | Iterable[dict],
    identities: Iterable[Identity] | Iterable[dict],
) -> list[EnrichedAlert]:
    parsed_assets = [
        asset if isinstance(asset, Asset) else Asset.model_validate(asset) for asset in assets
    ]
    parsed_identities = [
        ident if isinstance(ident, Identity) else Identity.model_validate(ident)
        for ident in identities
    ]
    normalized = [normalize_raw(raw) for raw in raw_alerts]
    return enrich_alerts(normalized, parsed_assets, parsed_identities)
