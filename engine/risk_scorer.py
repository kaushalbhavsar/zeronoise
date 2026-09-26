"""Deterministic incident risk scoring and driver attribution.

The real score operates on deduplicated, correlated incidents:

    fidelity_a = severity_weight
                 × confidence
                 × (1 - 0.7 × FPR)
                 × (1 + 0.10 × log1p(event_count - 1))

    B = min(Σ fidelity_a over unique (rule_name, mitre_tactic), 35)

    K = 1 + 0.35×max(0, m-1) + 0.20×max(0, s-1)
        + 0.50×int(Exfiltration or Impact)

    asset_score = 0.35×env + 0.35×data + 0.30×criticality   (≈ 0.4–2.0)
    P_priv      = highest involved privilege weight
    I           = asset_score × P_priv

    risk = min(100, B × K × I × (1 - NOISE_DISCOUNT_CAP × noise))

Noise is an explicit suppressor and can only reduce the product.
scenario_id is never read. LLM state is never read.
"""

from __future__ import annotations

import math
from typing import Iterable

from config import (
    ASSET_CRIT_BLEND,
    ASSET_DATA_BLEND,
    ASSET_ENV_BLEND,
    ASSET_SCORE_MAX,
    ASSET_SCORE_MIN,
    COMPLETION_TACTICS,
    CRITICALITY_WEIGHT,
    DATA_WEIGHT,
    ENVIRONMENT_WEIGHT,
    FIDELITY_CAP,
    FIDELITY_FPR_COEFF,
    FIDELITY_VOLUME_COEFF,
    NEUTRAL_IMPACT,
    NEUTRAL_PRIVILEGE,
    NOISE_DISCOUNT_CAP,
    PRIVILEGE_WEIGHT,
    PROGRESSION_BASE,
    PROGRESSION_COMPLETION_BONUS,
    PROGRESSION_SENSOR_COEFF,
    PROGRESSION_TACTIC_COEFF,
    SEVERITY_WEIGHTS,
    UNOBSERVED_PRIVILEGE,
)
from engine.schemas import (
    Asset,
    CandidateIncident,
    EnrichedAlert,
    Identity,
    RiskBreakdown,
    RiskDriver,
    ScoredIncident,
)

FORMULA = (
    "risk = min(100, B × K × I × (1 - {cap} × noise)), "
    "I = asset_score × P_priv, "
    "B = min(Σ fidelity_a over unique (rule, tactic), {cap_b}), "
    "K = 1 + 0.35×max(0,m-1) + 0.20×max(0,s-1) + 0.50×completion"
).format(cap=NOISE_DISCOUNT_CAP, cap_b=FIDELITY_CAP)


def _clip(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _assets_for(incident: CandidateIncident) -> list[Asset]:
    seen: dict[str, Asset] = {}
    for alert in incident.alerts:
        for asset in (alert.asset, alert.dest_asset):
            if asset:
                seen[asset.host_id] = asset
    return list(seen.values())


def _identities_for(incident: CandidateIncident) -> list[Identity]:
    seen: dict[str, Identity] = {}
    for alert in incident.alerts:
        if alert.identity:
            seen[alert.identity.user_id] = alert.identity
    return list(seen.values())


def diminishing_volume(event_count: int) -> float:
    """Logarithmic volume factor from the fidelity formula.

    1 event → 1.00. Repeated copies of the same rule add less each time.
    """
    return 1.0 + FIDELITY_VOLUME_COEFF * math.log1p(max(0, event_count - 1))


def fidelity_a(
    *,
    severity_raw: str,
    confidence: float,
    false_positive_rate: float,
    event_count: int,
) -> float:
    """Per-alert threat fidelity before (rule, tactic) collapse."""
    return (
        SEVERITY_WEIGHTS[severity_raw]
        * confidence
        * (1.0 - FIDELITY_FPR_COEFF * false_positive_rate)
        * diminishing_volume(event_count)
    )


def _collapse_unique_signals(
    alerts: Iterable[EnrichedAlert],
) -> dict[tuple[str, str], dict]:
    """Keep one bucket per meaningful (rule_name, mitre_tactic) pair."""
    buckets: dict[tuple[str, str], dict] = {}
    for alert in alerts:
        key = (alert.rule_name, alert.mitre_tactic)
        events = max(1, alert.event_count)
        bucket = buckets.get(key)
        if bucket is None:
            buckets[key] = {
                "event_count": events,
                "conf_w": alert.confidence * events,
                "fpr_w": alert.false_positive_rate * events,
                "severity": alert.severity_raw,
            }
            continue
        bucket["event_count"] += events
        bucket["conf_w"] += alert.confidence * events
        bucket["fpr_w"] += alert.false_positive_rate * events
        if SEVERITY_WEIGHTS[alert.severity_raw] > SEVERITY_WEIGHTS[bucket["severity"]]:
            bucket["severity"] = alert.severity_raw
    return buckets


def score_threat_fidelity(incident: CandidateIncident) -> tuple[float, list[str]]:
    """Base threat fidelity B over unique (rule, tactic) pairs."""
    buckets = _collapse_unique_signals(incident.alerts)
    scores: list[float] = []
    evidence: list[str] = []
    for (rule, tactic), bucket in sorted(buckets.items()):
        events = bucket["event_count"]
        score = fidelity_a(
            severity_raw=bucket["severity"],
            confidence=bucket["conf_w"] / events,
            false_positive_rate=bucket["fpr_w"] / events,
            event_count=events,
        )
        scores.append(score)
        evidence.append(
            f"{rule} / {tactic} · sev={bucket['severity']} "
            f"n={events} → {score:.3f}"
        )
    total = sum(scores)
    capped = min(total, FIDELITY_CAP)
    if total > FIDELITY_CAP:
        evidence.append(f"Σ fidelity={total:.3f} capped at {FIDELITY_CAP:.1f}")
    else:
        evidence.append(f"Σ fidelity={total:.3f} over {len(scores)} unique (rule, tactic)")
    return capped, evidence


def score_progression(incident: CandidateIncident) -> tuple[float, list[str]]:
    """Kill-chain progression K."""
    tactics = [t for t in incident.unique_tactics if t]
    sensors = [p for p in incident.unique_products if p]
    m = len(tactics)
    s = len(sensors)
    completion = bool(COMPLETION_TACTICS.intersection(tactics))
    value = (
        PROGRESSION_BASE
        + PROGRESSION_TACTIC_COEFF * max(0, m - 1)
        + PROGRESSION_SENSOR_COEFF * max(0, s - 1)
        + PROGRESSION_COMPLETION_BONUS * int(completion)
    )
    evidence = [
        f"distinct tactics m={m} ({', '.join(tactics) or 'none'})",
        f"distinct sensors s={s} ({', '.join(sensors) or 'none'})",
        f"completion={completion} (Exfiltration or Impact)",
        f"K={value:.3f}",
    ]
    return value, evidence


def _asset_score(asset: Asset) -> float:
    value = (
        ASSET_ENV_BLEND * ENVIRONMENT_WEIGHT[asset.environment]
        + ASSET_DATA_BLEND * DATA_WEIGHT[asset.data_sensitivity]
        + ASSET_CRIT_BLEND * CRITICALITY_WEIGHT[asset.business_criticality]
    )
    return _clip(value, ASSET_SCORE_MIN, ASSET_SCORE_MAX)


def score_business_impact(incident: CandidateIncident) -> tuple[float, list[str]]:
    """Highest-risk touched asset, normalized to ≈ 0.4–2.0."""
    assets = _assets_for(incident)
    if not assets:
        unresolved = sorted(
            {
                alert.entities.host_id
                for alert in incident.alerts
                if alert.entities.host_id
            }
        )
        note = (
            f"Unresolved host(s) {', '.join(unresolved)}; applying neutral impact {NEUTRAL_IMPACT:.2f}."
            if unresolved
            else f"No CMDB match; applying neutral impact {NEUTRAL_IMPACT:.2f}."
        )
        return NEUTRAL_IMPACT, [note]
    best = -1.0
    evidence: list[str] = []
    for asset in assets:
        value = _asset_score(asset)
        if value >= best:
            best = value
            evidence = [
                (
                    f"{asset.hostname} env={asset.environment} "
                    f"sensitivity={asset.data_sensitivity} "
                    f"criticality={asset.business_criticality} → {value:.3f}"
                )
            ]
    return best, evidence


def score_privilege(incident: CandidateIncident) -> tuple[float, list[str]]:
    """Highest-risk identity involved (P_priv)."""
    identities = _identities_for(incident)
    if not identities:
        claimed = sorted(
            {
                alert.entities.user_id
                for alert in incident.alerts
                if alert.entities.user_id
            }
        )
        if claimed:
            return NEUTRAL_PRIVILEGE, [
                f"IAM miss for {', '.join(claimed)}; applying neutral privilege {NEUTRAL_PRIVILEGE:.2f}."
            ]
        return UNOBSERVED_PRIVILEGE, [
            f"No identity observed; applying unobserved privilege {UNOBSERVED_PRIVILEGE:.2f}."
        ]
    best = -1.0
    evidence: list[str] = []
    for identity in identities:
        value = PRIVILEGE_WEIGHT[identity.privilege_tier]
        if value >= best:
            best = value
            evidence = [
                f"{identity.user_id} ({identity.department}) "
                f"tier={identity.privilege_tier} → P_priv={value:.3f}"
            ]
    return best, evidence


def score_noise(incident: CandidateIncident, progression_k: float) -> tuple[float, list[str]]:
    """High when a bursty, high-FPR, single-stage incident is just noise."""
    events = max(1, incident.total_event_count)
    stages = max(1, len(incident.unique_techniques))
    burst = _clip(math.log1p(events) / math.log1p(40), 0.0, 1.0)
    mean_fpr = (
        sum(a.false_positive_rate * a.event_count for a in incident.alerts) / events
    )
    k_progress = _clip((progression_k - PROGRESSION_BASE) / 2.5, 0.0, 1.0)
    repetition = 1.0 - min(1.0, stages / max(1.0, math.log2(events) + 1.0))
    value = burst * mean_fpr * (1.0 - 0.85 * k_progress) * (0.55 + 0.45 * repetition)
    evidence = [
        f"event_count={events} volume_factor={diminishing_volume(events):.2f}",
        f"distinct techniques/stages={stages} (volume is not a stage count)",
        f"mean FPR={mean_fpr:.3f}",
        f"K-progress dampener={k_progress:.3f}",
    ]
    return _clip(value, 0.0, 1.0), evidence


def naive_siem_score(incident: CandidateIncident) -> float:
    """Deliberately naive: sum raw-alert severity weights. No dedup credit."""
    return float(
        sum(SEVERITY_WEIGHTS[alert.severity_raw] * alert.event_count for alert in incident.alerts)
    )


def _title(incident: CandidateIncident) -> str:
    assets = _assets_for(incident)
    identities = _identities_for(incident)
    if assets:
        jewel = max(assets, key=_asset_score)
        where = f"{jewel.hostname} ({jewel.environment})"
    elif incident.unique_hosts:
        where = incident.unique_hosts[0]
    else:
        where = "unattributed entities"
    if incident.unique_tactics:
        if len(incident.unique_tactics) == 1:
            what = incident.unique_tactics[0]
        else:
            what = f"{incident.unique_tactics[0]} → {incident.unique_tactics[-1]}"
    else:
        what = incident.alerts[0].rule_name
    if identities:
        who = max(
            identities, key=lambda ident: PRIVILEGE_WEIGHT[ident.privilege_tier]
        ).user_id
    elif incident.unique_users:
        who = incident.unique_users[0]
    else:
        who = "no identity"
    return f"{what} on {where} involving {who}"


def _attribution_pcts(factors: dict[str, float]) -> dict[str, float]:
    """Partition 100% by how close each factor is to its configured ceiling."""
    scaled = {
        "threat_fidelity": factors["threat_fidelity"] / FIDELITY_CAP,
        "attack_progression": min(factors["attack_progression"] / 4.0, 1.25),
        "asset_impact": factors["asset_impact"] / ASSET_SCORE_MAX,
        "identity_privilege": factors["identity_privilege"] / 1.8,
    }
    total = sum(scaled.values())
    if total <= 0:
        n = len(scaled)
        return {name: round(100.0 / n, 4) for name in scaled}
    return {name: round(100.0 * value / total, 4) for name, value in scaled.items()}


def score_incident(incident: CandidateIncident) -> ScoredIncident:
    fidelity, fid_ev = score_threat_fidelity(incident)
    progression, prog_ev = score_progression(incident)
    asset, asset_ev = score_business_impact(incident)
    privilege, priv_ev = score_privilege(incident)
    impact = asset * privilege
    raw = fidelity * progression * impact

    pcts = _attribution_pcts(
        {
            "threat_fidelity": fidelity,
            "attack_progression": progression,
            "asset_impact": asset,
            "identity_privilege": privilege,
        }
    )
    drivers = [
        RiskDriver(
            name="threat_fidelity",
            score=round(fidelity, 6),
            weight=1.0,
            contribution=round(raw * pcts["threat_fidelity"] / 100.0, 6),
            contribution_pct=pcts["threat_fidelity"],
            evidence=fid_ev,
        ),
        RiskDriver(
            name="attack_progression",
            score=round(progression, 6),
            weight=1.0,
            contribution=round(raw * pcts["attack_progression"] / 100.0, 6),
            contribution_pct=pcts["attack_progression"],
            evidence=prog_ev,
        ),
        RiskDriver(
            name="asset_impact",
            score=round(asset, 6),
            weight=1.0,
            contribution=round(raw * pcts["asset_impact"] / 100.0, 6),
            contribution_pct=pcts["asset_impact"],
            evidence=asset_ev + [f"I = asset_score × P_priv = {impact:.3f}"],
        ),
        RiskDriver(
            name="identity_privilege",
            score=round(privilege, 6),
            weight=1.0,
            contribution=round(raw * pcts["identity_privilege"] / 100.0, 6),
            contribution_pct=pcts["identity_privilege"],
            evidence=priv_ev,
        ),
    ]

    noise, noise_evidence = score_noise(incident, progression)
    discount = NOISE_DISCOUNT_CAP * noise
    risk = min(100.0, raw * (1.0 - discount))
    noise_driver = RiskDriver(
        name="noise_discount",
        score=round(noise, 6),
        weight=NOISE_DISCOUNT_CAP,
        contribution=round(-(raw * discount), 6),
        contribution_pct=round(-100.0 * discount, 4),
        evidence=noise_evidence
        + [f"applied discount={discount:.3f} (cap={NOISE_DISCOUNT_CAP})"],
    )
    breakdown = RiskBreakdown(
        risk_score=round(risk, 4),
        raw_weighted_score=round(raw, 4),
        noise_score=round(noise, 6),
        noise_discount=round(discount, 6),
        drivers=drivers + [noise_driver],
        formula=FORMULA,
    )
    return ScoredIncident(
        incident=incident,
        risk=breakdown,
        legacy_score=round(naive_siem_score(incident), 3),
        title=_title(incident),
    )


def score_incidents(incidents: Iterable[CandidateIncident]) -> list[ScoredIncident]:
    scored = [score_incident(incident) for incident in incidents]
    scored.sort(key=lambda item: (-item.risk.risk_score, item.incident.incident_id))
    legacy_order = sorted(
        scored, key=lambda item: (-item.legacy_score, item.incident.incident_id)
    )
    ranks = {
        item.incident.incident_id: idx for idx, item in enumerate(legacy_order, start=1)
    }
    for item in scored:
        item.naive_siem_rank = ranks[item.incident.incident_id]
    return scored


def positive_attribution_sum(breakdown: RiskBreakdown) -> float:
    """Sum of the constructive driver percentages (must be ~100)."""
    return sum(
        driver.contribution_pct
        for driver in breakdown.drivers
        if driver.name != "noise_discount"
    )
