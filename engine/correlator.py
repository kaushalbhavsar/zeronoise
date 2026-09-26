"""Correlate enriched alerts into candidate incidents.

Joins are entity + time only. scenario_id is intentionally unread.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from hashlib import sha256
from typing import Iterable

from config import CORRELATION_WINDOW_MINUTES, GENERIC_IPS, KILL_CHAIN, SEVERITY_RANK
from engine.schemas import CandidateIncident, EnrichedAlert


class UnionFind:
    def __init__(self, items: Iterable[str]) -> None:
        self.parent = {item: item for item in items}
        self.rank = {item: 0 for item in items}

    def find(self, item: str) -> str:
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        root_l, root_r = self.find(left), self.find(right)
        if root_l == root_r:
            return
        if self.rank[root_l] < self.rank[root_r]:
            self.parent[root_l] = root_r
        elif self.rank[root_l] > self.rank[root_r]:
            self.parent[root_r] = root_l
        else:
            self.parent[root_r] = root_l
            self.rank[root_l] += 1


def entity_keys(alert: EnrichedAlert) -> set[str]:
    """Resolved correlation keys. Generic public resolvers are ignored."""
    keys: set[str] = set()
    ent = alert.entities
    if ent.user_id:
        keys.add(f"user:{ent.user_id}")
    host_id = ent.host_id or (alert.asset.host_id if alert.asset else None)
    if host_id:
        keys.add(f"host:{host_id}")
    dest_host = alert.dest_asset.host_id if alert.dest_asset else None
    if dest_host:
        keys.add(f"host:{dest_host}")
    if ent.process_hash:
        keys.add(f"hash:{ent.process_hash}")
    for ip in (ent.src_ip, ent.dest_ip):
        if not ip or ip in GENERIC_IPS:
            continue
        # Prefer the CMDB host over a raw IP when both describe one asset.
        if alert.asset and ip == alert.asset.ip_address:
            continue
        if alert.dest_asset and ip == alert.dest_asset.ip_address:
            continue
        keys.add(f"ip:{ip}")
    return keys


def _within_window(left: datetime, right: datetime, minutes: int) -> bool:
    return abs((left - right).total_seconds()) <= minutes * 60


def correlate_alerts(
    alerts: Iterable[EnrichedAlert],
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> list[CandidateIncident]:
    ordered = sorted(alerts, key=lambda a: (a.timestamp, a.alert_id))
    if not ordered:
        return []

    ids = [alert.alert_id for alert in ordered]
    uf = UnionFind(ids)
    by_id = {alert.alert_id: alert for alert in ordered}
    inverted: dict[str, list[str]] = defaultdict(list)

    for alert in ordered:
        keys = entity_keys(alert)
        candidates: set[str] = set()
        for key in keys:
            candidates.update(inverted[key])
        for other_id in candidates:
            other = by_id[other_id]
            if _within_window(alert.timestamp, other.timestamp, window_minutes):
                if entity_keys(alert) & entity_keys(other):
                    uf.union(alert.alert_id, other.alert_id)
        for key in keys:
            inverted[key].append(alert.alert_id)

    groups: dict[str, list[EnrichedAlert]] = defaultdict(list)
    for alert in ordered:
        groups[uf.find(alert.alert_id)].append(alert)

    incidents = [_build_incident(group) for group in groups.values()]
    incidents.sort(key=lambda inc: (inc.first_seen, inc.incident_id))
    return incidents


def _build_incident(alerts: list[EnrichedAlert]) -> CandidateIncident:
    alerts = sorted(alerts, key=lambda a: (a.timestamp, a.alert_id))
    alert_ids = [alert.alert_id for alert in alerts]
    digest = sha256("|".join(alert_ids).encode("utf-8")).hexdigest()[:10].upper()
    tactics = []
    for tactic in KILL_CHAIN:
        if any(alert.mitre_tactic == tactic for alert in alerts):
            tactics.append(tactic)
    techniques = sorted({alert.mitre_technique for alert in alerts})
    products = sorted({alert.source_product for alert in alerts})
    users = sorted({alert.entities.user_id for alert in alerts if alert.entities.user_id})
    hosts: set[str] = set()
    for alert in alerts:
        if alert.entities.host_id:
            hosts.add(alert.entities.host_id)
        if alert.asset:
            hosts.add(alert.asset.host_id)
        if alert.dest_asset:
            hosts.add(alert.dest_asset.host_id)
    max_severity = max(alerts, key=lambda a: SEVERITY_RANK[a.severity_raw]).severity_raw
    return CandidateIncident(
        incident_id=f"INC-{digest}",
        alert_ids=alert_ids,
        alerts=alerts,
        first_seen=alerts[0].timestamp,
        last_seen=alerts[-1].timestamp,
        unique_tactics=tactics,
        unique_techniques=techniques,
        unique_products=products,
        unique_users=users,
        unique_hosts=sorted(hosts),
        total_event_count=sum(alert.event_count for alert in alerts),
        max_severity=max_severity,
    )
