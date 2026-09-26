"""Explainable incident cards.

The deterministic explainer is the source of truth. An optional LLM may
rewrite prose only. It is forbidden from changing scores, ranking,
entities, alert IDs, tactics, or attribution percentages.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Iterable

from config import LLM_BASE_URL, LLM_ENABLED, LLM_MODEL, SENSITIVITY_SCORE
from engine.schemas import (
    Asset,
    Identity,
    IncidentCard,
    RiskDriver,
    ScoredIncident,
)


def _assets(scored: ScoredIncident) -> list[Asset]:
    seen: dict[str, Asset] = {}
    for alert in scored.incident.alerts:
        for asset in (alert.asset, alert.dest_asset):
            if asset:
                seen[asset.host_id] = asset
    return list(seen.values())


def _identities(scored: ScoredIncident) -> list[Identity]:
    seen: dict[str, Identity] = {}
    for alert in scored.incident.alerts:
        if alert.identity:
            seen[alert.identity.user_id] = alert.identity
    return list(seen.values())


def _top_drivers(scored: ScoredIncident, n: int = 3) -> list[RiskDriver]:
    return sorted(
        scored.risk.drivers, key=lambda d: (-d.contribution_pct, d.factor)
    )[:n]


def deterministic_summary(scored: ScoredIncident) -> str:
    inc = scored.incident
    assets = _assets(scored)
    identities = _identities(scored)
    top = _top_drivers(scored, 2)
    driver_txt = " and ".join(
        f"{d.factor} ({d.contribution_pct}%)" for d in top
    )
    asset_txt = "unattributed systems"
    if assets:
        jewel = max(assets, key=lambda a: SENSITIVITY_SCORE[a.data_sensitivity])
        asset_txt = (
            f"{jewel.hostname} ({jewel.environment}, {jewel.data_sensitivity})"
        )
    who = identities[0].user_id if identities else "no resolved identity"
    chain = " → ".join(inc.unique_tactics) if inc.unique_tactics else "a single tactic"
    return (
        f"Risk {scored.risk.risk_score:.1f}/100 from {inc.total_event_count} raw events "
        f"collapsed into {len(inc.alerts)} correlated alert group(s). "
        f"Primary drivers: {driver_txt}. "
        f"Activity involves {who} against {asset_txt} and spans {chain}."
    )


def deterministic_narrative(scored: ScoredIncident) -> str:
    inc = scored.incident
    lines: list[str] = []
    lines.append(
        f"Incident {inc.incident_id} opened at {inc.first_seen.isoformat()} "
        f"and last updated at {inc.last_seen.isoformat()}."
    )
    if inc.unique_tactics:
        lines.append(
            "Observed ATT&CK progression: " + " → ".join(inc.unique_tactics) + "."
        )
    products = ", ".join(inc.unique_products)
    lines.append(
        f"Evidence arrived from {products} across {len(inc.alerts)} "
        f"deduplicated alerts ({inc.total_event_count} raw events)."
    )
    if inc.unique_users:
        lines.append("Identities: " + ", ".join(inc.unique_users) + ".")
    if inc.unique_hosts:
        lines.append("Hosts: " + ", ".join(inc.unique_hosts) + ".")
    fp = next(
        (d for d in scored.risk.drivers if d.factor == "FP/Noise Suppression"),
        None,
    )
    if fp and fp.contribution_pct >= 15:
        lines.append(
            "FP/noise suppression removed a material share of the score "
            f"({fp.contribution_pct}%) because historical false-positive rates are high."
        )
    lines.append(
        "Vendor severity is treated as a residual signal only "
        f"(max={inc.max_severity}); it does not dominate ranking."
    )
    return " ".join(lines)


def deterministic_containment(scored: ScoredIncident) -> list[str]:
    inc = scored.incident
    tactics = set(inc.unique_tactics)
    actions: list[str] = []
    if inc.unique_users:
        actions.append(
            "Disable or step-up-MFA the involved identities: "
            + ", ".join(inc.unique_users)
            + "."
        )
    if "Credential Access" in tactics:
        actions.append(
            "Reset credentials and revoke refresh tokens for involved accounts; "
            "check for newly created privileged group memberships."
        )
    if "Lateral Movement" in tactics or inc.unique_hosts:
        hosts = ", ".join(inc.unique_hosts[:6]) or "involved hosts"
        actions.append(f"Isolate {hosts} from production east-west paths.")
    if "Exfiltration" in tactics or "Collection" in tactics:
        actions.append(
            "Block observed egress destinations and snapshot the crown-jewel datastore "
            "for forensic preservation."
        )
    if "Persistence" in tactics:
        actions.append(
            "Review scheduled tasks, new services, and persistence artifacts on "
            "the first-seen workstation."
        )
    if not actions:
        actions.append(
            "Validate the alert against CMDB ownership and close as noise only after "
            "confirming no shared identity or host with a higher-risk incident."
        )
    actions.append(
        "Do not page solely because vendor severity is Critical — confirm "
        "business impact and kill-chain progression first."
    )
    return actions


def contrastive_explanation(
    scored: ScoredIncident,
    other: ScoredIncident | None,
) -> str | None:
    if other is None or other.incident.incident_id == scored.incident.incident_id:
        return None
    a, b = scored, other
    a_events = a.incident.total_event_count
    b_events = b.incident.total_event_count
    a_impact = next(d.score for d in a.risk.drivers if d.name == "asset_impact")
    b_impact = next(d.score for d in b.risk.drivers if d.name == "asset_impact")
    a_prog = next(d.score for d in a.risk.drivers if d.name == "attack_progression")
    b_prog = next(d.score for d in b.risk.drivers if d.name == "attack_progression")
    volume_note = (
        f"{a.incident.incident_id} has {a_events} raw events versus "
        f"{b.incident.incident_id} with {b_events}."
    )
    if a.risk.risk_score >= b.risk.risk_score:
        relation = (
            f"{a.incident.incident_id} outranks {b.incident.incident_id} on risk "
            f"({a.risk.risk_score:.1f} vs {b.risk.risk_score:.1f})"
        )
    else:
        relation = (
            f"{a.incident.incident_id} ranks below {b.incident.incident_id} on risk "
            f"({a.risk.risk_score:.1f} vs {b.risk.risk_score:.1f})"
        )
    return (
        f"{relation} because blast-radius C is {a_impact:.2f} vs {b_impact:.2f} "
        f"and kill-chain K is {a_prog:.2f} vs {b_prog:.2f}. {volume_note} "
        "Raw volume and vendor Critical labels are not sufficient to win the queue."
    )


def why_not_false_positive(scored: ScoredIncident) -> str:
    inc = scored.incident
    mean_fpr = (
        sum(alert.false_positive_rate * alert.event_count for alert in inc.alerts)
        / max(1, inc.total_event_count)
    )
    sensors = len(inc.unique_products)
    stages = len(inc.unique_tactics)
    if mean_fpr >= 0.6 and stages <= 2:
        return (
            f"Mean historical FPR is {mean_fpr:.2f} across {inc.total_event_count} raw events "
            f"and only {stages} tactic(s) from {sensors} sensor(s). "
            "This looks like a noisy signature unless new kill-chain stages appear."
        )
    return (
        f"Mean FPR is {mean_fpr:.2f}, but {stages} ATT&CK tactic(s) and {sensors} sensor(s) "
        f"plus blast-radius C={scored.risk.blast_c:.2f} are inconsistent with a single "
        "false-positive flood. Confirm with the timeline before closing."
    )


def attack_timeline(scored: ScoredIncident) -> list[str]:
    lines: list[str] = []
    for alert in sorted(
        scored.incident.alerts,
        key=lambda item: (item.first_seen or item.timestamp, item.alert_id),
    ):
        start = (alert.first_seen or alert.timestamp).isoformat()
        lines.append(
            f"{start}  {alert.source_product}  {alert.severity_raw}  "
            f"{alert.mitre_tactic}  {alert.rule_name}  n={alert.event_count}"
        )
    return lines


def build_card(
    scored: ScoredIncident,
    *,
    contrast_with: ScoredIncident | None = None,
    risk_rank: int | None = None,
    legacy_rank: int | None = None,
) -> IncidentCard:
    inc = scored.incident
    contrastive = contrastive_explanation(scored, contrast_with)
    actions = deterministic_containment(scored)
    return IncidentCard(
        incident_id=inc.incident_id,
        title=scored.title,
        risk_score=scored.risk.risk_score,
        legacy_score=scored.legacy_score,
        risk_rank=risk_rank,
        priority_rank=risk_rank,
        legacy_rank=legacy_rank if legacy_rank is not None else scored.naive_siem_rank,
        naive_siem_rank=scored.naive_siem_rank if scored.naive_siem_rank is not None else legacy_rank,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        alert_count=len(inc.alerts),
        raw_event_count=inc.total_event_count,
        max_severity=inc.max_severity,
        tactics=list(inc.unique_tactics),
        products=list(inc.unique_products),
        users=list(inc.unique_users),
        hosts=list(inc.unique_hosts),
        assets=_assets(scored),
        identities=_identities(scored),
        executive_summary=deterministic_summary(scored),
        narrative=deterministic_narrative(scored),
        containment=actions,
        recommended_actions=list(actions),
        why_prioritized=list(scored.risk.drivers),
        why_not_false_positive=why_not_false_positive(scored),
        attack_timeline=attack_timeline(scored),
        contrastive=contrastive,
        contrastive_explanation=contrastive or "",
        risk=scored.risk,
        alert_ids=list(inc.alert_ids),
        edges=list(inc.edges),
        llm_enhanced=False,
        explanation_source="deterministic",
    )


def _locked_facts(card: IncidentCard) -> dict:
    return {
        "incident_id": card.incident_id,
        "title": card.title,
        "risk_score": card.risk_score,
        "legacy_score": card.legacy_score,
        "alert_ids": card.alert_ids,
        "tactics": card.tactics,
        "users": card.users,
        "hosts": card.hosts,
        "raw_event_count": card.raw_event_count,
        "max_severity": card.max_severity,
        "attribution": [
            {
                "factor": d.factor,
                "contribution_pct": d.contribution_pct,
            }
            for d in card.risk.drivers
        ],
        "containment_seeds": card.containment,
        "deterministic_summary": card.executive_summary,
        "deterministic_narrative": card.narrative,
    }


def _call_llm(prompt: str) -> dict | None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    base = LLM_BASE_URL or "https://api.openai.com/v1"
    body = json.dumps(
        {
            "model": LLM_MODEL,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You rewrite SOC incident explanations. You must use only "
                        "the supplied facts. Never invent entities, alert IDs, "
                        "tactics, scores, or percentages. Return JSON with keys "
                        "executive_summary, narrative, containment (array of strings)."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base.rstrip('/')}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    try:
        content = payload["choices"][0]["message"]["content"]
        return json.loads(content)
    except (KeyError, IndexError, json.JSONDecodeError, TypeError):
        return None


def enhance_with_llm(card: IncidentCard) -> IncidentCard:
    """Optional prose rewrite. Scores, IDs, tactics, and attribution stay frozen."""
    if not LLM_ENABLED:
        return card
    facts = _locked_facts(card)
    rewritten = _call_llm(
        "Rewrite the analyst-facing prose using only these facts:\n"
        + json.dumps(facts, default=str)
    )
    if not rewritten:
        return card
    summary = rewritten.get("executive_summary") or card.executive_summary
    narrative = rewritten.get("narrative") or card.narrative
    containment = rewritten.get("containment") or card.containment
    if not isinstance(containment, list):
        containment = card.containment
    # Re-bind every immutable field from the original card.
    return card.model_copy(
        update={
            "executive_summary": str(summary),
            "narrative": str(narrative),
            "containment": [str(item) for item in containment],
            "llm_enhanced": True,
            "explanation_source": "llm",
            "risk_score": card.risk_score,
            "legacy_score": card.legacy_score,
            "risk": card.risk,
            "alert_ids": card.alert_ids,
            "tactics": card.tactics,
            "users": card.users,
            "hosts": card.hosts,
        }
    )


def explain_incidents(
    scored: Iterable[ScoredIncident],
    *,
    risk_ranks: dict[str, int] | None = None,
    legacy_ranks: dict[str, int] | None = None,
    contrast_target: ScoredIncident | None = None,
    contrast_fallback: ScoredIncident | None = None,
    use_llm: bool | None = None,
) -> list[IncidentCard]:
    cards: list[IncidentCard] = []
    scored_list = list(scored)
    apply_llm = LLM_ENABLED if use_llm is None else use_llm
    for item in scored_list:
        other = contrast_target
        if other is None or other.incident.incident_id == item.incident.incident_id:
            other = contrast_fallback
        if other is not None and other.incident.incident_id == item.incident.incident_id:
            other = None
        card = build_card(
            item,
            contrast_with=other,
            risk_rank=(risk_ranks or {}).get(item.incident.incident_id),
            legacy_rank=(legacy_ranks or {}).get(item.incident.incident_id),
        )
        if apply_llm:
            card = enhance_with_llm(card)
        cards.append(card)
    return cards
