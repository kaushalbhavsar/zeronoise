"""Deterministic incident risk scoring and driver attribution.

The formula is a weighted sum of six [0, 1] components, then a noise
discount that can only reduce the score:

    raw   = Σ w_i * s_i
    risk  = 100 * raw * (1 - NOISE_DISCOUNT_CAP * noise)

    contribution_pct_i = 100 * (w_i * s_i) / raw

scenario_id is never read. LLM state is never read.
"""

from __future__ import annotations

import math
from typing import Iterable

from config import (
    ENV_SCORE,
    KILL_CHAIN,
    LATE_STAGE_SCORE,
    NEUTRAL_IMPACT,
    NEUTRAL_PRIVILEGE,
    NOISE_DISCOUNT_CAP,
    PRIVILEGE_SCORE,
    RISK_WEIGHTS,
    SENSITIVITY_SCORE,
    SEVERITY_RANK,
)
from engine.schemas import (
    Asset,
    CandidateIncident,
    Identity,
    RiskBreakdown,
    RiskDriver,
    ScoredIncident,
)

FORMULA = (
    "risk = 100 * (Σ w_i * s_i) * (1 - {cap} * noise), "
    "where drivers are business_impact, identity_privilege, "
    "attack_progression, signal_quality, blast_radius, severity_residual"
).format(cap=NOISE_DISCOUNT_CAP)


def _clip01(value: float) -> float:
    return max(0.0, min(1.0, value))


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


def score_business_impact(incident: CandidateIncident) -> tuple[float, list[str]]:
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
    best = 0.0
    evidence: list[str] = []
    for asset in assets:
        env = ENV_SCORE[asset.environment]
        sens = SENSITIVITY_SCORE[asset.data_sensitivity]
        crit = (asset.business_criticality - 1) / 4.0
        value = 0.40 * env + 0.40 * sens + 0.20 * crit
        if value >= best:
            best = value
            evidence = [
                (
                    f"{asset.hostname} env={asset.environment} "
                    f"sensitivity={asset.data_sensitivity} "
                    f"criticality={asset.business_criticality} → {value:.3f}"
                )
            ]
    return _clip01(best), evidence


def score_privilege(incident: CandidateIncident) -> tuple[float, list[str]]:
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
        return 0.0, ["No identity observed on this incident."]
    best = 0.0
    evidence: list[str] = []
    for identity in identities:
        value = PRIVILEGE_SCORE[identity.privilege_tier]
        if value >= best:
            best = value
            evidence = [
                f"{identity.user_id} ({identity.department}) "
                f"tier={identity.privilege_tier} → {value:.3f}"
            ]
    return _clip01(best), evidence


def score_progression(incident: CandidateIncident) -> tuple[float, list[str]]:
    tactics = incident.unique_tactics
    n_tactics = len(tactics)
    coverage = _clip01(n_tactics / 6.0)
    late = max((LATE_STAGE_SCORE.get(t, 0.0) for t in tactics), default=0.0)
    indices = [KILL_CHAIN.index(t) for t in tactics if t in KILL_CHAIN]
    if indices:
        span = (max(indices) - min(indices)) / (len(KILL_CHAIN) - 1)
    else:
        span = 0.0
    multi_product = _clip01((len(incident.unique_products) - 1) / 3.0)
    value = 0.35 * coverage + 0.35 * late + 0.20 * span + 0.10 * multi_product
    evidence = [
        f"tactics={n_tactics} ({', '.join(tactics) or 'none'})",
        f"latest stage score={late:.2f}",
        f"kill-chain span={span:.2f}",
        f"products={', '.join(incident.unique_products)}",
    ]
    return _clip01(value), evidence


def score_signal_quality(incident: CandidateIncident) -> tuple[float, list[str]]:
    qualities = [
        alert.confidence * (1.0 - alert.false_positive_rate) for alert in incident.alerts
    ]
    mean_q = sum(qualities) / len(qualities) if qualities else 0.0
    product_boost = _clip01(0.35 + 0.22 * len(set(incident.unique_products)))
    technique_boost = _clip01(0.40 + 0.10 * len(incident.unique_techniques))
    value = 0.60 * mean_q + 0.25 * product_boost + 0.15 * technique_boost
    evidence = [
        f"mean confidence×(1-FPR)={mean_q:.3f}",
        f"distinct products={len(incident.unique_products)}",
        f"distinct techniques={len(incident.unique_techniques)}",
    ]
    return _clip01(value), evidence


def score_blast_radius(incident: CandidateIncident) -> tuple[float, list[str]]:
    hosts = len(incident.unique_hosts)
    users = len(incident.unique_users)
    value = 1.0 - math.exp(-0.45 * max(0, hosts + users - 1))
    evidence = [f"{hosts} host(s), {users} identity(ies) → {value:.3f}"]
    return _clip01(value), evidence


def score_severity(incident: CandidateIncident) -> tuple[float, list[str]]:
    rank = SEVERITY_RANK[incident.max_severity]
    value = rank / 4.0
    return value, [f"max vendor severity={incident.max_severity} ({value:.2f})"]


def score_noise(incident: CandidateIncident) -> tuple[float, list[str]]:
    """High when a bursty, high-FPR, single-stage incident is just noise."""
    events = max(1, incident.total_event_count)
    burst = math.log1p(events) / math.log1p(200)
    burst = _clip01(burst)
    mean_fpr = sum(a.false_positive_rate * a.event_count for a in incident.alerts) / events
    progression, _ = score_progression(incident)
    # Progression suppresses the noise penalty: a real campaign that happens
    # to generate many events is not treated like a scanner.
    value = burst * mean_fpr * (1.0 - 0.85 * progression)
    evidence = [
        f"event_count={events} burst={burst:.3f}",
        f"mean FPR={mean_fpr:.3f}",
        f"progression dampener={progression:.3f}",
    ]
    return _clip01(value), evidence


def _legacy_score(incident: CandidateIncident) -> float:
    """Vendor-severity-and-volume ranking used by a typical SIEM queue."""
    return (
        1000.0 * SEVERITY_RANK[incident.max_severity]
        + 10.0 * len(incident.alerts)
        + float(incident.total_event_count)
    )


def _title(incident: CandidateIncident) -> str:
    assets = _assets_for(incident)
    identities = _identities_for(incident)
    if assets:
        jewel = max(
            assets,
            key=lambda a: (
                SENSITIVITY_SCORE[a.data_sensitivity],
                ENV_SCORE[a.environment],
                a.business_criticality,
            ),
        )
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
            identities, key=lambda ident: PRIVILEGE_SCORE[ident.privilege_tier]
        ).user_id
    elif incident.unique_users:
        who = incident.unique_users[0]
    else:
        who = "no identity"
    return f"{what} on {where} involving {who}"


def score_incident(incident: CandidateIncident) -> ScoredIncident:
    components = [
        ("business_impact", *score_business_impact(incident)),
        ("identity_privilege", *score_privilege(incident)),
        ("attack_progression", *score_progression(incident)),
        ("signal_quality", *score_signal_quality(incident)),
        ("blast_radius", *score_blast_radius(incident)),
        ("severity_residual", *score_severity(incident)),
    ]
    drivers: list[RiskDriver] = []
    raw = 0.0
    for name, score, evidence in components:
        weight = RISK_WEIGHTS[name]
        contribution = weight * score
        raw += contribution
        drivers.append(
            RiskDriver(
                name=name,
                score=round(score, 6),
                weight=weight,
                contribution=round(contribution, 6),
                contribution_pct=0.0,
                evidence=evidence,
            )
        )
    if raw > 0:
        for driver in drivers:
            driver.contribution_pct = round(100.0 * driver.contribution / raw, 4)
    noise, noise_evidence = score_noise(incident)
    discount = NOISE_DISCOUNT_CAP * noise
    risk = 100.0 * raw * (1.0 - discount)
    # Attach noise as a documented reducer, not a rank-inventing term.
    noise_driver = RiskDriver(
        name="noise_discount",
        score=round(noise, 6),
        weight=NOISE_DISCOUNT_CAP,
        contribution=round(-100.0 * raw * discount, 6),
        contribution_pct=round(-100.0 * discount, 4),
        evidence=noise_evidence
        + [f"applied discount={discount:.3f} (cap={NOISE_DISCOUNT_CAP})"],
    )
    breakdown = RiskBreakdown(
        risk_score=round(risk, 4),
        raw_weighted_score=round(100.0 * raw, 4),
        noise_score=round(noise, 6),
        noise_discount=round(discount, 6),
        drivers=drivers + [noise_driver],
        formula=FORMULA,
    )
    return ScoredIncident(
        incident=incident,
        risk=breakdown,
        legacy_score=round(_legacy_score(incident), 3),
        title=_title(incident),
    )


def score_incidents(incidents: Iterable[CandidateIncident]) -> list[ScoredIncident]:
    scored = [score_incident(incident) for incident in incidents]
    scored.sort(key=lambda item: (-item.risk.risk_score, item.incident.incident_id))
    return scored


def positive_attribution_sum(breakdown: RiskBreakdown) -> float:
    """Sum of the six constructive driver percentages (must be ~100)."""
    return sum(
        driver.contribution_pct
        for driver in breakdown.drivers
        if driver.name != "noise_discount"
    )
