"""Queue view model — maps scored incidents into dense operational strips.

Presentation only. Does not recompute risk, ranks, or correlation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from engine.presentation import (
    context_badges,
    incident_roles,
    next_recommended_action,
    rank_delta,
    urgency_sentence,
)
from engine.schemas import IncidentCard, ScoredIncident

STAGE_SHORT: dict[str, str] = {
    "Initial Access": "INITIAL",
    "Execution": "EXEC",
    "Persistence": "PERSIST",
    "Privilege Escalation": "PRIV-ESC",
    "Credential Access": "CREDENTIAL",
    "Discovery": "DISCOVERY",
    "Lateral Movement": "LATERAL",
    "Collection": "COLLECTION",
    "Exfiltration": "EXFIL",
    "Impact": "IMPACT",
}

# Prefer consequential stages when selecting the strip label.
_STAGE_WEIGHT: dict[str, int] = {
    "Impact": 100,
    "Exfiltration": 90,
    "Lateral Movement": 80,
    "Credential Access": 70,
    "Collection": 60,
    "Privilege Escalation": 55,
    "Persistence": 50,
    "Execution": 40,
    "Discovery": 30,
    "Initial Access": 20,
}

SENSOR_SHORT: dict[str, str] = {
    "EDR": "EDR",
    "IAM": "IAM",
    "NDR": "NDR",
    "WAF": "WAF",
    "DLP": "DLP",
    "SIEM": "SIEM",
}

ENV_TAG: dict[str, str] = {
    "prod": "PROD",
    "staging": "STAGING",
    "dev": "DEV",
    "sandbox": "SANDBOX",
}

SortKey = Literal[
    "zeronoise_rank",
    "legacy_rank",
    "rank_delta",
    "risk_score",
    "age",
    "priority",
    "status",
    "owner",
]

RankingMode = Literal["zeronoise", "legacy"]


class IncidentQueueRow(BaseModel):
    """One horizontal strip on the SOC incident board."""

    incident_id: str
    priority: str
    risk_score: float
    zeronoise_rank: int | None = None
    legacy_rank: int | None = None
    rank_delta: int | None = None
    title: str
    engine_title: str
    primary_asset: str | None = None
    primary_asset_full: str | None = None
    asset_tag: str | None = None
    latest_attack_stage: str | None = None
    latest_attack_stage_full: str | None = None
    age: str
    age_minutes: int = 0
    sensors: list[str] = Field(default_factory=list)
    raw_alert_count: int = 0
    deduplicated_event_count: int = 0
    status: str
    owner: str | None = None
    why_high: str = ""
    attack_path: str = ""
    top_identity: str | None = None
    next_action: str = ""


def priority_band(score: float) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    if score >= 30:
        return "P3"
    return "P4"


def compact_age(ts: datetime, now: datetime) -> str:
    minutes = max(0, int((now - ts).total_seconds() // 60))
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h"
    return f"{hours // 24}d"


def age_minutes(ts: datetime, now: datetime) -> int:
    return max(0, int((now - ts).total_seconds() // 60))


def queue_title(item: ScoredIncident) -> str:
    """Short scan title (2–6 words). Engine title stays secondary."""
    tactics = set(item.incident.unique_tactics)
    badges = context_badges(item)
    if "Impact" in tactics:
        return "Ransomware staging"
    if "Exfiltration" in tactics and "Crown Jewel" in badges:
        return "Crown-jewel exfiltration"
    if "Exfiltration" in tactics:
        return "Data exfiltration"
    if "High FP Rule" in badges and "Sandbox" in badges:
        return "WAF exploit burst"
    if "Lateral Movement" in tactics and "Credential Access" in tactics:
        return "Credential harvesting"
    if "Credential Access" in tactics:
        return "Credential access"
    if "Lateral Movement" in tactics:
        return "Lateral movement"
    if item.incident.total_event_count >= 40 and tactics <= {"Initial Access", "Discovery"}:
        return "External scanning"
    if "Initial Access" in tactics:
        return "Admin login anomaly"
    if tactics:
        return next(iter(tactics))
    return "Unclassified activity"


def short_asset_label(name: str | None) -> str | None:
    if not name or name == "—":
        return None
    return name.split(".")[0]


def asset_context_tag(item: ScoredIncident) -> str | None:
    badges = context_badges(item)
    if "Crown Jewel" in badges:
        return "CROWN JEWEL"
    envs = {
        alert.asset.environment
        for alert in item.incident.alerts
        if alert.asset
    }
    envs |= {
        alert.dest_asset.environment
        for alert in item.incident.alerts
        if alert.dest_asset
    }
    if "prod" in envs:
        return "PROD"
    if "sandbox" in envs:
        return "SANDBOX"
    if envs:
        return ENV_TAG.get(sorted(envs)[0], sorted(envs)[0].upper())
    return None


def latest_attack_stage(item: ScoredIncident) -> tuple[str | None, str | None]:
    """Most consequential observed ATT&CK stage. Never invents stages."""
    tactics = list(item.incident.unique_tactics)
    if not tactics:
        return None, None
    best = max(tactics, key=lambda t: _STAGE_WEIGHT.get(t, 0))
    return STAGE_SHORT.get(best, best.upper()[:10]), best


def sensor_labels(item: ScoredIncident) -> list[str]:
    seen: list[str] = []
    for product in item.incident.unique_products:
        label = SENSOR_SHORT.get(product, product)
        if label not in seen:
            seen.append(label)
    return seen


def compact_rank_delta(delta: int | None) -> str:
    """↑26 / ↓13 / —  (color-independent arrows)."""
    if delta is None or delta == 0:
        return "—"
    if delta > 0:
        return f"↑{delta}"
    return f"↓{abs(delta)}"


def format_rank_cell(
    *,
    mode: RankingMode,
    zeronoise_rank: int | None,
    legacy_rank: int | None,
    delta: int | None,
) -> str:
    if mode == "legacy":
        if legacy_rank is None:
            return "—"
        return f"#{legacy_rank}"
    if zeronoise_rank is None:
        return "—"
    move = compact_rank_delta(delta)
    if move == "—":
        return f"#{zeronoise_rank}"
    return f"#{zeronoise_rank} {move}"


def rank_tooltip(zeronoise_rank: int | None, legacy_rank: int | None) -> str:
    zn = f"#{zeronoise_rank}" if zeronoise_rank else "—"
    leg = f"#{legacy_rank}" if legacy_rank else "—"
    return f"ZeroNoise rank {zn}. Legacy SIEM rank {leg}."


def compression_label(raw: int, deduped: int) -> str:
    return f"{raw} → {deduped}"


def compression_tooltip(raw: int, deduped: int) -> str:
    return f"{raw} raw alerts were reduced to {deduped} analyst-relevant events."


def display_owner(owner: str | None) -> str:
    if not owner or owner in {"—", ""}:
        return "Unassigned"
    return owner


def display_asset(asset: str | None) -> str:
    return asset or "—"


def attack_path_label(item: ScoredIncident) -> str:
    tactics = item.incident.unique_tactics
    if not tactics:
        return "No mapped stages"
    return " → ".join(tactics)


def why_rank_line(item: ScoredIncident) -> str:
    stages = len(item.incident.unique_tactics)
    sensors = len(item.incident.unique_products)
    bits = [f"{stages} ATT&CK stage{'s' if stages != 1 else ''}", f"{sensors} sensor{'s' if sensors != 1 else ''}"]
    short, full = latest_attack_stage(item)
    if full:
        bits.append(full)
    if short in {"IMPACT", "EXFIL"}:
        bits.append(f"{full} observed")
    return " · ".join(bits)


def build_queue_row(
    item: ScoredIncident,
    now: datetime,
    *,
    status: str,
    owner: str | None,
    card: IncidentCard | None = None,
) -> IncidentQueueRow:
    roles = incident_roles(item)
    asset_full = roles["affected_asset"]
    asset = short_asset_label(asset_full if asset_full != "—" else None)
    stage_short, stage_full = latest_attack_stage(item)
    delta = rank_delta(item.risk_rank, item.naive_siem_rank)
    raw = item.incident.total_event_count
    deduped = len(item.incident.alerts)
    identity = roles["title_identity"]
    if identity == "—":
        identity = None
    next_action = ""
    if card is not None:
        next_action = next_recommended_action(card)
    return IncidentQueueRow(
        incident_id=item.incident.incident_id,
        priority=priority_band(item.risk.risk_score),
        risk_score=item.risk.risk_score,
        zeronoise_rank=item.risk_rank,
        legacy_rank=item.naive_siem_rank,
        rank_delta=delta,
        title=queue_title(item),
        engine_title=item.title,
        primary_asset=asset,
        primary_asset_full=asset_full if asset_full != "—" else None,
        asset_tag=asset_context_tag(item),
        latest_attack_stage=stage_short,
        latest_attack_stage_full=stage_full,
        age=compact_age(item.incident.first_seen, now),
        age_minutes=age_minutes(item.incident.first_seen, now),
        sensors=sensor_labels(item),
        raw_alert_count=raw,
        deduplicated_event_count=deduped,
        status=status,
        owner=display_owner(owner),
        why_high=why_rank_line(item),
        attack_path=attack_path_label(item),
        top_identity=identity,
        next_action=next_action or urgency_sentence(item),
    )


def sort_queue_rows(
    rows: list[IncidentQueueRow],
    sort_key: SortKey,
    *,
    ascending: bool = True,
) -> list[IncidentQueueRow]:
    """Sort strips. Default ZeroNoise rank ascending = best first."""

    def priority_ord(row: IncidentQueueRow) -> int:
        return {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}.get(row.priority, 9)

    def key_fn(row: IncidentQueueRow):
        if sort_key == "zeronoise_rank":
            return (row.zeronoise_rank is None, row.zeronoise_rank or 10**9, row.incident_id)
        if sort_key == "legacy_rank":
            return (row.legacy_rank is None, row.legacy_rank or 10**9, row.incident_id)
        if sort_key == "rank_delta":
            # Higher promotion first when descending; ascending = most deprioritized first.
            delta = row.rank_delta if row.rank_delta is not None else 0
            return (-delta if not ascending else delta, row.zeronoise_rank or 10**9, row.incident_id)
        if sort_key == "risk_score":
            return (row.risk_score, row.incident_id)
        if sort_key == "age":
            return (row.age_minutes, row.incident_id)
        if sort_key == "priority":
            return (priority_ord(row), -(row.risk_score), row.incident_id)
        if sort_key == "status":
            return (row.status, row.zeronoise_rank or 10**9, row.incident_id)
        if sort_key == "owner":
            return (row.owner or "Unassigned", row.zeronoise_rank or 10**9, row.incident_id)
        return (row.zeronoise_rank or 10**9, row.incident_id)

    ranked = sorted(rows, key=key_fn)
    if sort_key in {"risk_score", "age"} and not ascending:
        ranked.reverse()
    elif sort_key in {"zeronoise_rank", "legacy_rank", "priority", "status", "owner"} and not ascending:
        ranked.reverse()
    elif sort_key == "rank_delta":
        # key_fn already encodes ascending/descending for delta
        pass
    return ranked


def default_sort_key(mode: RankingMode) -> SortKey:
    return "legacy_rank" if mode == "legacy" else "zeronoise_rank"


def row_aria_label(row: IncidentQueueRow, *, mode: RankingMode) -> str:
    asset = display_asset(row.primary_asset)
    stage = row.latest_attack_stage or "unknown stage"
    owner = display_owner(row.owner)
    rank = format_rank_cell(
        mode=mode,
        zeronoise_rank=row.zeronoise_rank,
        legacy_rank=row.legacy_rank,
        delta=row.rank_delta,
    )
    return (
        f"{row.priority} risk {row.risk_score:.0f} rank {rank} "
        f"{row.title} on {asset} stage {stage} status {row.status} owner {owner}"
    )


def board_summary_metrics(
    *,
    active: int,
    high_priority: int,
    raw_alerts: int,
    correlated_signals: int,
    noise_reduction_pct: float,
) -> dict[str, str]:
    return {
        "active": f"{active} Active",
        "high": f"{high_priority} P0/P1",
        "raw": f"{raw_alerts} Raw Alerts",
        "signals": f"{correlated_signals} Correlated Signals",
        "noise": f"{noise_reduction_pct:.0f}% Noise Reduction",
    }
