"""Normalize vendor-shaped alerts and enrich them from CMDB / IAM.

A single malformed row or an unknown asset/user must not fail the
pipeline. Unknown context is recorded on the alert and later scored
with neutral weights. scenario_id is preserved for demo validation
only and is never consulted for grouping.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
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
    "ids": "SIEM",
    "snort": "SIEM",
    "suricata": "SIEM",
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


def parse_jsonl(source: Path | Iterable[str]) -> tuple[list[dict], list[str]]:
    """Parse JSONL, skipping blank and malformed lines."""
    rows: list[dict] = []
    errors: list[str] = []
    if isinstance(source, Path):
        lines = source.read_text(encoding="utf-8").splitlines()
    else:
        lines = list(source)
    for idx, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            errors.append(f"line {idx}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(payload, dict):
            errors.append(f"line {idx}: expected an object, got {type(payload).__name__}")
            continue
        rows.append(payload)
    return rows, errors


def normalize_ip(value: object | None) -> str | None:
    """Strip, parse, and canonicalize an IPv4/IPv6 address."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _as_dt(value: datetime | str | None) -> datetime:
    if value is None:
        raise ValueError("alert is missing a timestamp")
    if isinstance(value, datetime):
        dt = value
    else:
        dt = isoparse(str(value).strip())
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
    host_id = _pick(entities.host_id, payload.host_id)
    user_id = _pick(entities.user_id, payload.user_id)
    entities = AlertEntities(
        user_id=str(user_id).strip() if user_id else None,
        host_id=str(host_id).strip() if host_id else None,
        src_ip=normalize_ip(_pick(entities.src_ip, payload.src_ip)),
        dest_ip=normalize_ip(_pick(entities.dest_ip, payload.dest_ip)),
        process_hash=_pick(entities.process_hash, payload.process_hash),
    )
    alert_id = str(_pick(payload.alert_id, payload.id) or "").strip()
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
        original_alert_id=alert_id,
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
        original_alert_ids=[alert_id],
        member_alert_ids=[alert_id],
        first_seen=_as_dt(_pick(payload.timestamp, payload.time)),
        last_seen=_as_dt(_pick(payload.timestamp, payload.time)),
    )


class ContextIndex:
    def __init__(self, assets: Iterable[Asset], identities: Iterable[Identity]) -> None:
        self.by_host = {asset.host_id: asset for asset in assets}
        self.by_hostname = {asset.hostname: asset for asset in self.by_host.values()}
        self.by_ip = {asset.ip_address: asset for asset in self.by_host.values()}
        self.by_user = {identity.user_id: identity for identity in identities}

    def resolve_asset(self, host_id: str | None, ip: str | None) -> Asset | None:
        if host_id and host_id in self.by_host:
            return self.by_host[host_id]
        if host_id and host_id in self.by_hostname:
            return self.by_hostname[host_id]
        if ip and ip in self.by_ip:
            return self.by_ip[ip]
        return None

    def enrich(self, alert: EnrichedAlert) -> EnrichedAlert:
        asset = self.resolve_asset(alert.entities.host_id, alert.entities.src_ip)
        dest_asset = self.resolve_asset(None, alert.entities.dest_ip)
        if dest_asset and asset is None:
            asset = dest_asset
        identity = self.by_user.get(alert.entities.user_id or "")
        entities = alert.entities
        # Resolve host IP ↔ host ID so later correlation joins both forms.
        updates: dict = {}
        if asset and not entities.host_id:
            entities = entities.model_copy(update={"host_id": asset.host_id})
        if asset and entities.src_ip and entities.src_ip == asset.ip_address:
            pass
        if dest_asset and not entities.dest_ip:
            entities = entities.model_copy(update={"dest_ip": dest_asset.ip_address})
        gaps: list[str] = []
        if entities.user_id and identity is None:
            gaps.append(f"unknown_user:{entities.user_id}")
        if entities.host_id and asset is None:
            gaps.append(f"unknown_host:{entities.host_id}")
        if entities.src_ip and asset is None and dest_asset is None:
            if entities.src_ip not in self.by_ip:
                gaps.append(f"unknown_src_ip:{entities.src_ip}")
        if entities.dest_ip and dest_asset is None and entities.dest_ip not in self.by_ip:
            gaps.append(f"unknown_dest_ip:{entities.dest_ip}")
        updates.update(
            {
                "entities": entities,
                "asset": asset,
                "dest_asset": dest_asset,
                "identity": identity,
                "context_gaps": gaps,
                "original_alert_id": alert.original_alert_id or alert.alert_id,
            }
        )
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


def _seen(alert: EnrichedAlert) -> tuple[datetime, datetime]:
    first = alert.first_seen or alert.timestamp
    last = alert.last_seen or alert.timestamp
    return first, last


def deduplicate_alerts(
    alerts: Iterable[EnrichedAlert],
    window_minutes: int = DEDUP_WINDOW_MINUTES,
) -> list[EnrichedAlert]:
    """Collapse same-rule, same-entity bursts inside a rolling window.

    A later identical alert joins the burst when it arrives within
    `window_minutes` of that burst's last_seen. Volume is retained as
    event_count and original_alert_ids so scoring can apply diminishing
    returns instead of treating each copy as a new attack stage.
    """
    ordered = sorted(alerts, key=lambda a: (a.timestamp, a.alert_id))
    buckets: dict[tuple[str, ...], list[EnrichedAlert]] = {}
    window_seconds = window_minutes * 60
    for alert in ordered:
        key = _dedup_key(alert)
        family = buckets.setdefault(key, [])
        merged = False
        incoming_first, incoming_last = _seen(alert)
        for idx, existing in enumerate(family):
            _first, last = _seen(existing)
            delta = (incoming_first - last).total_seconds()
            if 0 <= delta <= window_seconds or abs((incoming_first - last).total_seconds()) <= window_seconds:
                members = list(existing.original_alert_ids or existing.member_alert_ids or [existing.alert_id])
                members.extend(alert.original_alert_ids or alert.member_alert_ids or [alert.alert_id])
                total = existing.event_count + alert.event_count
                mean_fpr = (
                    existing.false_positive_rate * existing.event_count
                    + alert.false_positive_rate * alert.event_count
                ) / total
                first, prev_last = _seen(existing)
                family[idx] = existing.model_copy(
                    update={
                        "event_count": total,
                        "confidence": max(existing.confidence, alert.confidence),
                        "false_positive_rate": min(1.0, mean_fpr),
                        "original_alert_ids": members,
                        "member_alert_ids": members,
                        "first_seen": min(first, incoming_first),
                        "last_seen": max(prev_last, incoming_last),
                    }
                )
                merged = True
                break
        if not merged:
            ids = list(alert.original_alert_ids or alert.member_alert_ids or [alert.alert_id])
            family.append(
                alert.model_copy(
                    update={
                        "original_alert_ids": ids,
                        "member_alert_ids": ids,
                        "first_seen": incoming_first,
                        "last_seen": incoming_last,
                    }
                )
            )
    collapsed = [alert for family in buckets.values() for alert in family]
    collapsed.sort(key=lambda a: ((a.first_seen or a.timestamp), a.alert_id))
    return collapsed


def normalize_and_enrich(
    raw_alerts: Iterable[dict],
    assets: Iterable[Asset] | Iterable[dict],
    identities: Iterable[Identity] | Iterable[dict],
) -> list[EnrichedAlert]:
    enriched, _errors = normalize_and_enrich_report(raw_alerts, assets, identities)
    return enriched


def normalize_and_enrich_report(
    raw_alerts: Iterable[dict],
    assets: Iterable[Asset] | Iterable[dict],
    identities: Iterable[Identity] | Iterable[dict],
) -> tuple[list[EnrichedAlert], list[str]]:
    parsed_assets = [
        asset if isinstance(asset, Asset) else Asset.model_validate(asset) for asset in assets
    ]
    parsed_identities = [
        ident if isinstance(ident, Identity) else Identity.model_validate(ident)
        for ident in identities
    ]
    normalized: list[EnrichedAlert] = []
    errors: list[str] = []
    for idx, raw in enumerate(raw_alerts, start=1):
        try:
            normalized.append(normalize_raw(raw))
        except Exception as exc:  # noqa: BLE001 - isolate a single bad row
            ident = ""
            if isinstance(raw, dict):
                ident = str(raw.get("id") or raw.get("alert_id") or f"row {idx}")
            errors.append(f"{ident or f'row {idx}'}: {exc}")
    return enrich_alerts(normalized, parsed_assets, parsed_identities), errors
