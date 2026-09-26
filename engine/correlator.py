"""Correlate deduplicated alerts into candidate incidents with NetworkX.

Each alert is a graph node. Edges carry relationship_type, a time delta,
and a correlation_strength. scenario_id is never read.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from hashlib import sha256
from typing import Iterable

import networkx as nx

from config import (
    CORRELATION_WINDOW_MINUTES,
    GENERIC_IPS,
    INFRA_HOST_TOKENS,
    KILL_CHAIN,
    MAX_COMPONENT_NODES,
    SCANNER_FANOUT_HOSTS,
    SEVERITY_RANK,
    STRONG_EDGE_THRESHOLD,
    TEMPORAL_SPLIT_GAP_MINUTES,
)
from engine.schemas import CandidateIncident, EnrichedAlert, GraphEdge, RelationshipType

RELATIONSHIP_STRENGTH: dict[RelationshipType, float] = {
    "DESTINATION_PIVOT": 0.95,
    "HOST_IP_PIVOT": 0.95,
    "SHARED_IDENTITY": 0.92,
    "SHARED_HOST": 0.90,
    "PROCESS_HASH": 0.88,
    "SHARED_ATTACKER_IP": 0.55,
}
INFRA_HOST_STRENGTH = 0.40


def _first(alert: EnrichedAlert) -> datetime:
    return alert.first_seen or alert.timestamp


def _last(alert: EnrichedAlert) -> datetime:
    return alert.last_seen or alert.timestamp


def host_ids(alert: EnrichedAlert) -> set[str]:
    hosts: set[str] = set()
    if alert.entities.host_id:
        hosts.add(alert.entities.host_id)
    if alert.asset:
        hosts.add(alert.asset.host_id)
    if alert.dest_asset:
        hosts.add(alert.dest_asset.host_id)
    return hosts


def asset_ip(alert: EnrichedAlert) -> str | None:
    if alert.asset:
        return alert.asset.ip_address
    return None


def is_infra_host(host_id: str, hostname: str | None = None) -> bool:
    text = f"{host_id} {hostname or ''}".lower()
    return any(token in text for token in INFRA_HOST_TOKENS)


def entity_keys(alert: EnrichedAlert) -> set[str]:
    """Debug helper: correlation keys that are not generic infrastructure."""
    keys: set[str] = set()
    if alert.entities.user_id:
        keys.add(f"user:{alert.entities.user_id}")
    for host in host_ids(alert):
        if not is_infra_host(host, alert.asset.hostname if alert.asset else None):
            keys.add(f"host:{host}")
    if alert.entities.process_hash:
        keys.add(f"hash:{alert.entities.process_hash}")
    for ip in (alert.entities.src_ip, alert.entities.dest_ip):
        if ip and ip not in GENERIC_IPS:
            keys.add(f"ip:{ip}")
    return keys


def temporally_close(
    left: EnrichedAlert,
    right: EnrichedAlert,
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> bool:
    if _last(left) < _first(right):
        gap = (_first(right) - _last(left)).total_seconds()
    elif _last(right) < _first(left):
        gap = (_first(left) - _last(right)).total_seconds()
    else:
        gap = 0.0
    return gap <= window_minutes * 60


def time_delta_minutes(left: EnrichedAlert, right: EnrichedAlert) -> float:
    delta = abs((_first(right) - _first(left)).total_seconds()) / 60.0
    return round(delta, 2)


def _scanner_ips(alerts: list[EnrichedAlert]) -> set[str]:
    fanout: dict[str, set[str]] = defaultdict(set)
    for alert in alerts:
        src = alert.entities.src_ip
        if not src or src in GENERIC_IPS:
            continue
        dests = host_ids(alert)
        if alert.entities.dest_ip:
            dests.add(alert.entities.dest_ip)
        fanout[src].update(dests)
    return {ip for ip, dests in fanout.items() if len(dests) >= SCANNER_FANOUT_HOSTS}


def _infra_hosts(alerts: list[EnrichedAlert]) -> set[str]:
    marked: set[str] = set()
    for alert in alerts:
        hostname = alert.asset.hostname if alert.asset else None
        for host in host_ids(alert):
            if is_infra_host(host, hostname):
                marked.add(host)
    return marked


def relationships(
    earlier: EnrichedAlert,
    later: EnrichedAlert,
    scanner_ips: set[str],
    infra: set[str],
) -> list[tuple[RelationshipType, float]]:
    rels: list[tuple[RelationshipType, float]] = []
    user_a, user_b = earlier.entities.user_id, later.entities.user_id
    if user_a and user_a == user_b:
        rels.append(("SHARED_IDENTITY", RELATIONSHIP_STRENGTH["SHARED_IDENTITY"]))

    hosts_a, hosts_b = host_ids(earlier), host_ids(later)
    shared_hosts = hosts_a & hosts_b
    if shared_hosts:
        strength = (
            RELATIONSHIP_STRENGTH["SHARED_HOST"]
            if shared_hosts - infra
            else INFRA_HOST_STRENGTH
        )
        rels.append(("SHARED_HOST", strength))

    src_a, src_b = earlier.entities.src_ip, later.entities.src_ip
    if src_a and src_a == src_b and src_a not in GENERIC_IPS:
        same_target = bool(hosts_a & hosts_b) or (
            earlier.entities.dest_ip
            and earlier.entities.dest_ip == later.entities.dest_ip
        )
        if src_a in scanner_ips and not same_target:
            pass
        else:
            rels.append(("SHARED_ATTACKER_IP", RELATIONSHIP_STRENGTH["SHARED_ATTACKER_IP"]))

    dest_a, dest_b = earlier.entities.dest_ip, later.entities.dest_ip
    if dest_a and dest_a == src_b and dest_a not in GENERIC_IPS:
        rels.append(("DESTINATION_PIVOT", RELATIONSHIP_STRENGTH["DESTINATION_PIVOT"]))
    if dest_b and dest_b == src_a and dest_b not in GENERIC_IPS:
        rels.append(("DESTINATION_PIVOT", RELATIONSHIP_STRENGTH["DESTINATION_PIVOT"]))

    later_ip = asset_ip(later)
    if dest_a and later_ip and dest_a == later_ip and _first(later) >= _first(earlier):
        rels.append(("HOST_IP_PIVOT", RELATIONSHIP_STRENGTH["HOST_IP_PIVOT"]))

    hash_a, hash_b = earlier.entities.process_hash, later.entities.process_hash
    if hash_a and hash_a == hash_b:
        rels.append(("PROCESS_HASH", RELATIONSHIP_STRENGTH["PROCESS_HASH"]))
    return rels


def build_correlation_graph(
    alerts: Iterable[EnrichedAlert],
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> nx.MultiGraph:
    ordered = sorted(alerts, key=lambda a: (_first(a), a.alert_id))
    graph: nx.MultiGraph = nx.MultiGraph()
    for alert in ordered:
        graph.add_node(alert.alert_id, alert=alert)
    if len(ordered) < 2:
        return graph
    scanner_ips = _scanner_ips(ordered)
    infra = _infra_hosts(ordered)
    for i, earlier in enumerate(ordered):
        for later in ordered[i + 1 :]:
            if not temporally_close(earlier, later, window_minutes):
                continue
            delta = time_delta_minutes(earlier, later)
            for rel, strength in relationships(earlier, later, scanner_ips, infra):
                graph.add_edge(
                    earlier.alert_id,
                    later.alert_id,
                    relationship_type=rel,
                    time_delta_minutes=delta,
                    correlation_strength=strength,
                )
    return graph


def _temporal_segments(
    nodes: set[str],
    by_id: dict[str, EnrichedAlert],
    gap_minutes: int = TEMPORAL_SPLIT_GAP_MINUTES,
) -> list[set[str]]:
    ordered = sorted(nodes, key=lambda aid: (_first(by_id[aid]), aid))
    segments: list[set[str]] = [set()]
    previous: EnrichedAlert | None = None
    for alert_id in ordered:
        alert = by_id[alert_id]
        if previous is not None:
            gap = (_first(alert) - _last(previous)).total_seconds() / 60.0
            if gap > gap_minutes:
                segments.append(set())
        segments[-1].add(alert_id)
        previous = alert
    return [segment for segment in segments if segment]


def _split_mega_component(
    graph: nx.MultiGraph,
    nodes: set[str],
    by_id: dict[str, EnrichedAlert],
) -> list[set[str]]:
    if len(nodes) <= MAX_COMPONENT_NODES:
        return [nodes]
    subgraph = graph.subgraph(nodes).copy()
    weak = [
        (src, dst, key)
        for src, dst, key, data in subgraph.edges(keys=True, data=True)
        if data.get("correlation_strength", 0.0) < STRONG_EDGE_THRESHOLD
    ]
    subgraph.remove_edges_from(weak)
    parts = [set(component) for component in nx.connected_components(subgraph)]
    split: list[set[str]] = []
    for part in parts:
        if len(part) <= MAX_COMPONENT_NODES:
            split.append(part)
            continue
        for segment in _temporal_segments(part, by_id):
            if len(segment) <= MAX_COMPONENT_NODES:
                split.append(segment)
                continue
            by_host: dict[str, set[str]] = defaultdict(set)
            for alert_id in segment:
                hosts = host_ids(by_id[alert_id])
                key = sorted(hosts)[0] if hosts else alert_id
                by_host[key].add(alert_id)
            split.extend(by_host.values())
    return split


def cluster_alerts(
    graph: nx.MultiGraph,
    by_id: dict[str, EnrichedAlert],
) -> list[set[str]]:
    clusters: list[set[str]] = []
    for component in nx.connected_components(graph):
        clusters.extend(_split_mega_component(graph, set(component), by_id))
    return clusters


def _edges_for(graph: nx.MultiGraph, nodes: set[str]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    subgraph = graph.subgraph(nodes)
    for src, dst, data in subgraph.edges(data=True):
        left, right = sorted((src, dst))
        edges.append(
            GraphEdge(
                source_alert_id=left,
                target_alert_id=right,
                relationship_type=data["relationship_type"],
                time_delta_minutes=float(data["time_delta_minutes"]),
                correlation_strength=float(data["correlation_strength"]),
            )
        )
    edges.sort(
        key=lambda edge: (
            edge.source_alert_id,
            edge.target_alert_id,
            edge.relationship_type,
        )
    )
    return edges


def _build_incident(
    alerts: list[EnrichedAlert],
    edges: list[GraphEdge],
) -> CandidateIncident:
    alerts = sorted(alerts, key=lambda a: (_first(a), a.alert_id))
    alert_ids = [alert.alert_id for alert in alerts]
    digest = sha256("|".join(alert_ids).encode("utf-8")).hexdigest()[:10].upper()
    tactics = [
        tactic
        for tactic in KILL_CHAIN
        if any(alert.mitre_tactic == tactic for alert in alerts)
    ]
    techniques = sorted({alert.mitre_technique for alert in alerts})
    products = sorted({alert.source_product for alert in alerts})
    users = sorted({alert.entities.user_id for alert in alerts if alert.entities.user_id})
    hosts: set[str] = set()
    for alert in alerts:
        hosts.update(host_ids(alert))
    first_seen = min(_first(alert) for alert in alerts)
    last_seen = max(_last(alert) for alert in alerts)
    max_severity = max(alerts, key=lambda a: SEVERITY_RANK[a.severity_raw]).severity_raw
    return CandidateIncident(
        incident_id=f"INC-{digest}",
        alert_ids=alert_ids,
        alerts=alerts,
        first_seen=first_seen,
        last_seen=last_seen,
        unique_tactics=tactics,
        unique_techniques=techniques,
        unique_products=products,
        unique_users=users,
        unique_hosts=sorted(hosts),
        total_event_count=sum(alert.event_count for alert in alerts),
        max_severity=max_severity,
        edges=edges,
    )


def correlate_alerts(
    alerts: Iterable[EnrichedAlert],
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> list[CandidateIncident]:
    ordered = sorted(alerts, key=lambda a: (_first(a), a.alert_id))
    if not ordered:
        return []
    by_id = {alert.alert_id: alert for alert in ordered}
    graph = build_correlation_graph(ordered, window_minutes=window_minutes)
    incidents = [
        _build_incident(
            [by_id[alert_id] for alert_id in cluster],
            _edges_for(graph, cluster),
        )
        for cluster in cluster_alerts(graph, by_id)
    ]
    incidents.sort(key=lambda inc: (inc.first_seen, inc.incident_id))
    return incidents
