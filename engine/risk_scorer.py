"""Deterministic incident risk scoring and counterfactual attribution.

The real score operates on deduplicated, correlated incidents:

    B = min(Σ fidelity_a over unique (rule_name, mitre_tactic), 35)
    K = 1 + 0.35×max(0, m-1) + 0.20×max(0, s-1) + 0.50×completion
    C = BLAST_ASSET_WEIGHT × asset_risk + BLAST_IDENTITY_WEIGHT × P_priv
    RawRisk = B × K × C
    risk_score = 100 × (1 − exp(−RawRisk / RISK_SCALE))

RawRisk is not shown to the analyst. Attribution is counterfactual
ablation, not an independent percentage split of B, K, and C.
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
    ATTRIBUTION_FACTORS,
    BLAST_ASSET_WEIGHT,
    BLAST_BASELINE,
    BLAST_IDENTITY_WEIGHT,
    COMPLETION_TACTICS,
    CRITICALITY_WEIGHT,
    DATA_WEIGHT,
    ENVIRONMENT_WEIGHT,
    FIDELITY_BASELINE,
    FIDELITY_CAP,
    FIDELITY_FPR_COEFF,
    FIDELITY_VOLUME_COEFF,
    NEUTRAL_IMPACT,
    NEUTRAL_PRIVILEGE,
    PRIVILEGE_WEIGHT,
    PROGRESSION_BASE,
    PROGRESSION_BASELINE,
    PROGRESSION_COMPLETION_BONUS,
    PROGRESSION_SENSOR_COEFF,
    PROGRESSION_TACTIC_COEFF,
    RISK_SCALE,
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
    "risk_score = 100 × (1 − exp(−RawRisk / {scale})), "
    "RawRisk = B × K × C, "
    "C = {wa}×asset_risk + {wp}×P_priv, "
    "B = min(Σ fidelity_a over unique (rule, tactic), {cap_b}), "
    "K = 1 + 0.35×max(0,m-1) + 0.20×max(0,s-1) + 0.50×completion"
).format(
    scale=RISK_SCALE,
    wa=BLAST_ASSET_WEIGHT,
    wp=BLAST_IDENTITY_WEIGHT,
    cap_b=FIDELITY_CAP,
)


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
    """Logarithmic volume factor from the fidelity formula."""
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
    *,
    fpr_override: float | None = None,
) -> dict[tuple[str, str], dict]:
    """Keep one bucket per meaningful (rule_name, mitre_tactic) pair."""
    buckets: dict[tuple[str, str], dict] = {}
    for alert in alerts:
        key = (alert.rule_name, alert.mitre_tactic)
        events = max(1, alert.event_count)
        fpr = alert.false_positive_rate if fpr_override is None else fpr_override
        bucket = buckets.get(key)
        if bucket is None:
            buckets[key] = {
                "event_count": events,
                "conf_w": alert.confidence * events,
                "fpr_w": fpr * events,
                "severity": alert.severity_raw,
            }
            continue
        bucket["event_count"] += events
        bucket["conf_w"] += alert.confidence * events
        bucket["fpr_w"] += fpr * events
        if SEVERITY_WEIGHTS[alert.severity_raw] > SEVERITY_WEIGHTS[bucket["severity"]]:
            bucket["severity"] = alert.severity_raw
    return buckets


def _fidelity_from_buckets(buckets: dict[tuple[str, str], dict]) -> tuple[float, list[str]]:
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
            f"The {rule} rule fired during {tactic}. "
            f"Severity is {bucket['severity']}. It covers {events} events."
        )
    total = sum(scores)
    capped = min(total, FIDELITY_CAP)
    if total > FIDELITY_CAP:
        evidence.append(f"Alert quality was capped at {FIDELITY_CAP:.0f}.")
    else:
        evidence.append(f"Alert quality uses {len(scores)} unique rule and tactic pairs.")
    return capped, evidence


def score_threat_fidelity(
    incident: CandidateIncident,
    *,
    fpr_override: float | None = None,
) -> tuple[float, list[str]]:
    """Base threat fidelity B over unique (rule, tactic) pairs."""
    return _fidelity_from_buckets(
        _collapse_unique_signals(incident.alerts, fpr_override=fpr_override)
    )


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
        f"This incident uses {m} ATT&CK tactics.",
        f"It was seen by {s} sensors.",
        (
            "A late stage is present. That means Exfiltration or Impact."
            if completion
            else "No late stage is present. We did not see Exfiltration or Impact."
        ),
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
            f"Host {', '.join(unresolved)} is not in CMDB. We used a mid impact score."
            if unresolved
            else "No CMDB match. We used a mid impact score."
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
                    f"{asset.hostname} is a {asset.environment} system. "
                    f"It holds {asset.data_sensitivity} data."
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
                f"IAM has no record for {', '.join(claimed)}. We used a mid privilege score."
            ]
        return UNOBSERVED_PRIVILEGE, [
            "No user was seen. We used a low privilege score."
        ]
    best = -1.0
    evidence: list[str] = []
    for identity in identities:
        value = PRIVILEGE_WEIGHT[identity.privilege_tier]
        if value >= best:
            best = value
            evidence = [
                f"{identity.user_id} is in {identity.department}. "
                f"The account tier is {identity.privilege_tier}."
            ]
    return best, evidence


def blast_radius(asset_risk: float, identity_risk: float) -> float:
    """Context multiplier C. Weights live in config.py."""
    return BLAST_ASSET_WEIGHT * asset_risk + BLAST_IDENTITY_WEIGHT * identity_risk


def raw_risk(fidelity_b: float, progression_k: float, blast_c: float) -> float:
    return fidelity_b * progression_k * blast_c


def normalize_risk(raw: float, scale: float = RISK_SCALE) -> float:
    """Monotonic saturating map into [0, 100]. Does not expose RawRisk."""
    if raw <= 0 or scale <= 0:
        return 0.0
    return 100.0 * (1.0 - math.exp(-raw / scale))


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


def _join_evidence(lines: list[str]) -> str:
    sentences = []
    for line in lines:
        text = line.strip()
        if not text:
            continue
        sentences.append(text if text.endswith((".", "!", "?")) else text + ".")
    return " ".join(sentences)


def integer_partition(weights: dict[str, float], order: tuple[str, ...]) -> dict[str, int]:
    """Largest-remainder rounding so integer percents sum to exactly 100."""
    positive = {name: max(0.0, weights.get(name, 0.0)) for name in order}
    total = sum(positive.values())
    if total <= 0:
        pcts = {name: 0 for name in order}
        pcts[order[0]] = 100
        return pcts
    exact = {name: 100.0 * positive[name] / total for name in order}
    floored = {name: int(math.floor(exact[name])) for name in order}
    remainder = 100 - sum(floored.values())
    leftovers = sorted(
        order,
        key=lambda name: (-(exact[name] - floored[name]), name),
    )
    for name in leftovers[:remainder]:
        floored[name] += 1
    return floored


def ablation_attribution(
    incident: CandidateIncident,
    *,
    fidelity_b: float,
    progression_k: float,
    blast_c: float,
    evidence: dict[str, str],
) -> list[RiskDriver]:
    """Counterfactual ablation. Only positive score drops enter the 100% pie."""
    real = normalize_risk(raw_risk(fidelity_b, progression_k, blast_c))
    drop_b = real - normalize_risk(raw_risk(FIDELITY_BASELINE, progression_k, blast_c))
    drop_k = real - normalize_risk(raw_risk(fidelity_b, PROGRESSION_BASELINE, blast_c))
    drop_c = real - normalize_risk(raw_risk(fidelity_b, progression_k, BLAST_BASELINE))
    clean_b, _ = score_threat_fidelity(incident, fpr_override=0.0)
    without_fp = normalize_risk(raw_risk(clean_b, progression_k, blast_c))
    fp_suppression = without_fp - real
    weights = {
        ATTRIBUTION_FACTORS[0]: drop_b,
        ATTRIBUTION_FACTORS[1]: drop_k,
        ATTRIBUTION_FACTORS[2]: drop_c,
        ATTRIBUTION_FACTORS[3]: fp_suppression,
    }
    pcts = integer_partition(weights, ATTRIBUTION_FACTORS)
    return [
        RiskDriver(
            factor=name,
            contribution_pct=pcts[name],
            evidence=evidence.get(name, ""),
        )
        for name in ATTRIBUTION_FACTORS
    ]


def score_incident(incident: CandidateIncident) -> ScoredIncident:
    fidelity_b, fid_ev = score_threat_fidelity(incident)
    progression_k, prog_ev = score_progression(incident)
    asset_risk, asset_ev = score_business_impact(incident)
    identity_risk, priv_ev = score_privilege(incident)
    blast_c = blast_radius(asset_risk, identity_risk)
    raw = raw_risk(fidelity_b, progression_k, blast_c)
    risk = normalize_risk(raw)
    clean_b, _ = score_threat_fidelity(incident, fpr_override=0.0)
    drivers = ablation_attribution(
        incident,
        fidelity_b=fidelity_b,
        progression_k=progression_k,
        blast_c=blast_c,
        evidence={
            ATTRIBUTION_FACTORS[0]: _join_evidence(fid_ev),
            ATTRIBUTION_FACTORS[1]: _join_evidence(prog_ev),
            ATTRIBUTION_FACTORS[2]: (
                f"C = {BLAST_ASSET_WEIGHT:.2f}×{asset_risk:.3f} + "
                f"{BLAST_IDENTITY_WEIGHT:.2f}×{identity_risk:.3f} = {blast_c:.3f}; "
                + _join_evidence(asset_ev + priv_ev)
            ),
            ATTRIBUTION_FACTORS[3]: (
                f"B with FPR=0 is {clean_b:.3f} vs observed B={fidelity_b:.3f}"
            ),
        },
    )
    breakdown = RiskBreakdown(
        risk_score=round(risk, 4),
        fidelity_b=round(fidelity_b, 6),
        progression_k=round(progression_k, 6),
        blast_c=round(blast_c, 6),
        asset_risk=round(asset_risk, 6),
        identity_risk=round(identity_risk, 6),
        drivers=drivers,
        formula=FORMULA,
        raw_weighted_score=round(raw, 4),
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
    for idx, item in enumerate(scored, start=1):
        item.risk_rank = idx
        item.naive_siem_rank = ranks[item.incident.incident_id]
    return scored


def positive_attribution_sum(breakdown: RiskBreakdown) -> float:
    """Integer ablation percentages must sum to 100."""
    return float(sum(driver.contribution_pct for driver in breakdown.drivers))
