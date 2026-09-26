"""Explainable incident cards.

Deterministic Python templates are the source of truth and the offline
fallback. An optional OpenAI or Gemini call may rewrite prose only. It
cannot invent entities, change scores, or override attribution.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Iterable

from config import (
    KILL_CHAIN,
    LLM_BASE_URL,
    LLM_ENABLED,
    LLM_GEMINI_MODEL,
    LLM_MODEL,
    LLM_PROVIDER,
    LLM_TIMEOUT_SECONDS,
    SENSITIVITY_SCORE,
)
from engine.schemas import (
    Asset,
    Identity,
    IncidentCard,
    RiskDriver,
    ScoredIncident,
)

PRIVILEGED_TIERS = frozenset({"tier_0_domain_admin", "tier_1_cloud_admin"})
HIGH_VALUE = "crown_jewel_pii_pci"
BRACKET_ID = re.compile(r"\[([A-Za-z0-9._:-]+)\]")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

LLM_SYSTEM_PROMPT = """You are assisting a SOC analyst.

You may only use facts present in the supplied incident JSON.

Never invent alerts, users, hosts, IP addresses, tactics, techniques, timestamps, or business impact.

Every attack timeline step must cite at least one supplied alert_id using the form [alert_id].

Risk-driver percentages must exactly match the deterministic values supplied by the scoring engine. Do not emit why_prioritized.

Do not modify risk_score, priority_rank, or naive_siem_rank.

Describe uncertainty explicitly. Prefer “unlikely to be isolated noise” over “definitely malicious”.

Return JSON with exactly these keys:
  executive_summary (string)
  contrastive_explanation (string)
  why_not_false_positive (string)
  attack_timeline (array of strings)
  recommended_actions (array of strings)
"""


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


def _utc_clock(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%H:%M UTC")


def _alert_facts(scored: ScoredIncident) -> list[dict]:
    facts: list[dict] = []
    for alert in scored.incident.alerts:
        facts.append(
            {
                "alert_id": alert.alert_id,
                "original_alert_ids": list(alert.original_alert_ids or [alert.alert_id]),
                "timestamp": (alert.first_seen or alert.timestamp).isoformat(),
                "source_product": alert.source_product,
                "rule_name": alert.rule_name,
                "severity_raw": alert.severity_raw,
                "mitre_tactic": alert.mitre_tactic,
                "mitre_technique": alert.mitre_technique,
                "user_id": alert.entities.user_id,
                "host_id": alert.entities.host_id,
                "src_ip": alert.entities.src_ip,
                "dest_ip": alert.entities.dest_ip,
                "event_count": alert.event_count,
            }
        )
    return facts


def _known_tokens(card: IncidentCard) -> dict[str, set[str]]:
    alert_ids = set(card.alert_ids)
    for fact in card.alert_facts:
        alert_ids.add(str(fact.get("alert_id") or ""))
        alert_ids.update(str(item) for item in fact.get("original_alert_ids") or [])
    ips = set()
    for fact in card.alert_facts:
        for key in ("src_ip", "dest_ip"):
            if fact.get(key):
                ips.add(str(fact[key]))
    hosts = set(card.hosts)
    hostnames = {asset.hostname for asset in card.assets}
    users = set(card.users)
    techniques = set(card.techniques)
    tactics = set(card.tactics)
    return {
        "alert_ids": {item for item in alert_ids if item},
        "ips": ips,
        "hosts": hosts | hostnames,
        "users": users,
        "techniques": techniques,
        "tactics": tactics,
    }


def _kill_chain_ordered(tactics: list[str]) -> bool:
    indices = [KILL_CHAIN.index(name) for name in tactics if name in KILL_CHAIN]
    return indices == sorted(indices) and len(indices) >= 2


def deterministic_summary(scored: ScoredIncident) -> str:
    inc = scored.incident
    assets = _assets(scored)
    identities = _identities(scored)
    who = identities[0].user_id if identities else (
        inc.unique_users[0] if inc.unique_users else "an unresolved identity"
    )
    if assets:
        jewel = max(assets, key=lambda a: SENSITIVITY_SCORE[a.data_sensitivity])
        where = f"{jewel.hostname} ({jewel.environment}, {jewel.data_sensitivity})"
    elif inc.unique_hosts:
        where = inc.unique_hosts[0]
    else:
        where = "unattributed systems"
    chain = " → ".join(inc.unique_tactics) if inc.unique_tactics else "an unmapped tactic"
    sensors = ", ".join(inc.unique_products) or "unknown sensors"
    start = _utc_clock(inc.first_seen)
    return (
        f"From {start}, {who} was observed against {where} across {len(inc.alerts)} "
        f"correlated alert group(s) ({inc.total_event_count} raw events) from {sensors}. "
        f"The mapped sequence is {chain}. "
        f"Risk {scored.risk.risk_score:.1f}/100; legacy SIEM score {scored.legacy_score:.0f}."
    )


def deterministic_narrative(scored: ScoredIncident) -> str:
    inc = scored.incident
    parts = [
        f"Incident {inc.incident_id} opened at {inc.first_seen.isoformat()} "
        f"and last updated at {inc.last_seen.isoformat()}."
    ]
    if inc.unique_tactics:
        parts.append("Observed ATT&CK progression: " + " → ".join(inc.unique_tactics) + ".")
    parts.append(
        f"Evidence arrived from {', '.join(inc.unique_products) or 'unknown sensors'} "
        f"across {len(inc.alerts)} deduplicated alerts ({inc.total_event_count} raw events)."
    )
    if inc.unique_users:
        parts.append("Identities: " + ", ".join(inc.unique_users) + ".")
    if inc.unique_hosts:
        parts.append("Hosts: " + ", ".join(inc.unique_hosts) + ".")
    return " ".join(parts)


def _alert_user(alert) -> str | None:
    if alert.entities.user_id:
        return alert.entities.user_id
    if alert.identity:
        return alert.identity.user_id
    return None


def _alert_host(alert) -> str | None:
    if alert.entities.host_id:
        return alert.entities.host_id
    if alert.asset:
        return alert.asset.host_id
    return None


def _unique(values: Iterable[str | None]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _has_edr(products: Iterable[str]) -> bool:
    tokens = ("crowdstrike", "edr", "sentinelone", "defender", "carbon black")
    return any(any(token in product.lower() for token in tokens) for product in products)


def deterministic_containment(scored: ScoredIncident) -> list[str]:
    """Concrete, entity-cited actions. Never 'involved hosts' when IDs exist."""
    inc = scored.incident
    identities = _identities(scored)
    assets = _assets(scored)
    actions: list[str] = []
    seen: set[str] = set()

    def add(text: str) -> None:
        if text and text not in seen:
            seen.add(text)
            actions.append(text)

    privileged = [ident.user_id for ident in identities if ident.privilege_tier in PRIVILEGED_TIERS]
    cred_users = _unique(
        _alert_user(alert)
        for alert in inc.alerts
        if alert.mitre_tactic == "Credential Access"
    )
    auth_users = _unique(
        _alert_user(alert)
        for alert in inc.alerts
        if alert.mitre_tactic == "Initial Access"
    )
    isolate_hosts = _unique(
        _alert_host(alert)
        for alert in inc.alerts
        if alert.mitre_tactic in {"Initial Access", "Execution", "Lateral Movement", "Impact"}
    )
    egress_hosts = _unique(
        _alert_host(alert)
        for alert in inc.alerts
        if alert.mitre_tactic in {"Exfiltration", "Collection"}
    )
    impact_hosts = _unique(
        _alert_host(alert) for alert in inc.alerts if alert.mitre_tactic == "Impact"
    )
    persist_hosts = _unique(
        _alert_host(alert) for alert in inc.alerts if alert.mitre_tactic == "Persistence"
    )
    envs = {asset.environment for asset in assets}
    sandbox_only = bool(envs) and envs <= {"sandbox", "dev"} and "prod" not in envs
    mean_fpr = (
        sum(alert.false_positive_rate * alert.event_count for alert in inc.alerts)
        / max(1, inc.total_event_count)
    )
    loudest = max(inc.alerts, key=lambda alert: (alert.false_positive_rate, alert.event_count))

    for user_id in privileged:
        add(f"Disable or rotate {user_id} credentials.")
    for user_id in cred_users:
        if user_id not in privileged:
            add(f"Disable or rotate {user_id} credentials.")

    if sandbox_only:
        for host in isolate_hosts:
            add(
                f"Contain {host} in the sandbox VLAN; do not isolate production "
                "systems for this alert."
            )
    else:
        for host in isolate_hosts:
            add(f"Isolate {host} from the network.")

    for host in egress_hosts:
        add(f"Restrict outbound connectivity from {host}.")
    if _has_edr(inc.unique_products):
        add("Preserve EDR telemetry before remediation.")
    for user_id in auth_users:
        add(f"Review authentication activity associated with {user_id}.")
    for host in impact_hosts:
        add(f"Stop backup-deletion and destructive tooling on {host}.")
    for host in persist_hosts:
        add(f"Review scheduled tasks and new services on {host}.")
    if mean_fpr >= 0.60:
        add(
            f"Review high-FP rule '{loudest.rule_name}' (FPR {loudest.false_positive_rate:.2f}) "
            "before paging production."
        )
    if not actions:
        if inc.unique_hosts:
            add(f"Validate ownership of {inc.unique_hosts[0]} in CMDB before closing.")
        elif inc.unique_users:
            add(f"Review recent activity for {inc.unique_users[0]} before closing.")
        else:
            add(
                "Validate the alert against CMDB ownership and close as noise only after "
                "confirming no shared identity or host with a higher-risk incident."
            )
    return actions


def contrastive_explanation(
    scored: ScoredIncident,
    other: ScoredIncident | None,
) -> str | None:
    if other is None or other.incident.incident_id == scored.incident.incident_id:
        return None
    a, b = scored, other
    volume_note = (
        f"{a.incident.incident_id} has {a.incident.total_event_count} raw events versus "
        f"{b.incident.incident_id} with {b.incident.total_event_count}."
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
        f"Legacy SIEM ranks by raw severity × volume (naive score {a.legacy_score:.0f} "
        f"vs {b.legacy_score:.0f}, SIEM #{a.naive_siem_rank} vs #{b.naive_siem_rank}). "
        f"{relation} because blast-radius C is {a.risk.blast_c:.2f} vs {b.risk.blast_c:.2f} "
        f"and kill-chain K is {a.risk.progression_k:.2f} vs {b.risk.progression_k:.2f}. "
        f"{volume_note} Raw volume and vendor Critical labels are not sufficient to win the queue."
    )


def why_not_false_positive(scored: ScoredIncident) -> str:
    inc = scored.incident
    assets = _assets(scored)
    identities = _identities(scored)
    tactics = list(inc.unique_tactics)
    sensors = list(inc.unique_products)
    reasons: list[str] = []
    if len(sensors) >= 2:
        reasons.append(
            f"{', '.join(sensors[:-1])}, and {sensors[-1]} independently observed the activity"
            if len(sensors) > 2
            else f"{sensors[0]} and {sensors[1]} independently observed the activity"
        )
    if len(tactics) >= 2:
        reasons.append(
            "a temporally coherent sequence spanning " + ", ".join(tactics)
            if _kill_chain_ordered(tactics)
            else "more than one MITRE tactic (" + ", ".join(tactics) + ")"
        )
    if "Credential Access" in tactics:
        reasons.append("credential-access behavior")
    if "Lateral Movement" in tactics:
        reasons.append("lateral movement")
    if any(asset.data_sensitivity == HIGH_VALUE for asset in assets):
        jewel = next(asset.hostname for asset in assets if asset.data_sensitivity == HIGH_VALUE)
        reasons.append(f"a high-value destination ({jewel})")
    if any(ident.privilege_tier in PRIVILEGED_TIERS for ident in identities):
        who = next(
            ident.user_id for ident in identities if ident.privilege_tier in PRIVILEGED_TIERS
        )
        reasons.append(f"a privileged account ({who})")
    if "Exfiltration" in tactics or "Impact" in tactics:
        late = "exfiltration" if "Exfiltration" in tactics else "impact"
        reasons.append(f"a late-stage {late} signal")

    mean_fpr = (
        sum(alert.false_positive_rate * alert.event_count for alert in inc.alerts)
        / max(1, inc.total_event_count)
    )
    if len(reasons) >= 2:
        lead, *rest = reasons
        extra = "; ".join(rest)
        return (
            f"This is unlikely to be isolated noise because {lead}"
            + (f", plus {extra}" if extra else "")
            + ". That assessment is uncertain and should be confirmed on the cited timeline."
        )
    if mean_fpr >= 0.6 and len(tactics) <= 2:
        return (
            f"This may still be isolated noise: mean historical FPR is {mean_fpr:.2f} "
            f"across {inc.total_event_count} raw events, with only {len(tactics)} tactic(s) "
            f"from {len(sensors)} sensor(s). New kill-chain stages would change that assessment."
        )
    return (
        f"The available signals are limited ({len(tactics)} tactic(s), {len(sensors)} sensor(s), "
        f"mean FPR {mean_fpr:.2f}). Treat as uncertain until more independent evidence appears."
    )


def attack_timeline(scored: ScoredIncident) -> list[str]:
    lines: list[str] = []
    for alert in sorted(
        scored.incident.alerts,
        key=lambda item: (item.first_seen or item.timestamp, item.alert_id),
    ):
        who = alert.entities.user_id
        host = alert.entities.host_id
        target = ""
        if who and host:
            target = f" for {who} on {host}"
        elif who:
            target = f" for {who}"
        elif host:
            target = f" on {host}"
        clock = (alert.first_seen or alert.timestamp).astimezone(timezone.utc).strftime("%H:%M")
        lines.append(
            f"{clock}  [{alert.alert_id}] {alert.mitre_tactic} — {alert.rule_name}{target}"
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
        techniques=list(inc.unique_techniques),
        products=list(inc.unique_products),
        users=list(inc.unique_users),
        hosts=list(inc.unique_hosts),
        assets=_assets(scored),
        identities=_identities(scored),
        alert_facts=_alert_facts(scored),
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


def llm_incident_payload(card: IncidentCard) -> dict[str, Any]:
    """Structured facts only — never the rest of the alert stream."""
    return {
        "incident_id": card.incident_id,
        "priority_rank": card.priority_rank or card.risk_rank,
        "naive_siem_rank": card.naive_siem_rank or card.legacy_rank,
        "ai_rank": card.priority_rank or card.risk_rank,
        "risk_score": card.risk_score,
        "risk_attribution": [
            {"factor": driver.factor, "contribution_pct": driver.contribution_pct}
            for driver in (card.why_prioritized or card.risk.drivers)
        ],
        "alert_ids": list(card.alert_ids),
        "alerts": list(card.alert_facts),
        "timestamps": {
            "first_seen": card.first_seen.isoformat(),
            "last_seen": card.last_seen.isoformat(),
        },
        "entities": {
            "users": list(card.users),
            "hosts": list(card.hosts),
        },
        "cmdb_context": [
            {
                "host_id": asset.host_id,
                "hostname": asset.hostname,
                "environment": asset.environment,
                "data_sensitivity": asset.data_sensitivity,
                "business_criticality": asset.business_criticality,
            }
            for asset in card.assets
        ],
        "iam_context": [
            {
                "user_id": ident.user_id,
                "department": ident.department,
                "privilege_tier": ident.privilege_tier,
            }
            for ident in card.identities
        ],
        "mitre_tactics": list(card.tactics),
        "mitre_techniques": list(card.techniques),
        "correlation_edges": [
            {
                "source_alert_id": edge.source_alert_id,
                "target_alert_id": edge.target_alert_id,
                "relationship_type": edge.relationship_type,
                "time_delta_minutes": edge.time_delta_minutes,
                "correlation_strength": edge.correlation_strength,
            }
            for edge in card.edges
        ],
    }


def resolve_llm_provider() -> str:
    return (os.environ.get("LLM_PROVIDER") or LLM_PROVIDER or "").strip().lower()


def resolve_llm_api_key(provider: str | None = None) -> str:
    name = provider or resolve_llm_provider()
    if name == "gemini":
        return (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
    if name == "openai":
        return (os.environ.get("OPENAI_API_KEY") or "").strip()
    return (
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or ""
    ).strip()


def llm_is_configured() -> bool:
    if os.environ.get("LLM_ENABLED", "").strip().lower() in {"0", "false", "no"}:
        return False
    provider = resolve_llm_provider()
    if provider in {"openai", "gemini"}:
        return bool(resolve_llm_api_key(provider))
    if LLM_ENABLED:
        return bool(resolve_llm_api_key("openai") or resolve_llm_api_key("gemini"))
    return False


def _post_json(url: str, body: dict, headers: dict[str, str]) -> dict | None:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=LLM_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def _call_openai(payload: dict[str, Any]) -> dict | None:
    api_key = resolve_llm_api_key("openai")
    if not api_key:
        return None
    base = (os.environ.get("LLM_BASE_URL") or LLM_BASE_URL or "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("LLM_MODEL") or LLM_MODEL
    result = _post_json(
        f"{base}/chat/completions",
        {
            "model": model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": LLM_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": "Write the ExplainableIncidentCard prose from this incident JSON:\n"
                    + json.dumps(payload, default=str),
                },
            ],
        },
        {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    if not result:
        return None
    try:
        return json.loads(result["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        return None


def _call_gemini(payload: dict[str, Any]) -> dict | None:
    api_key = resolve_llm_api_key("gemini")
    if not api_key:
        return None
    model = os.environ.get("GEMINI_MODEL") or LLM_GEMINI_MODEL
    query = urllib.parse.urlencode({"key": api_key})
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?{query}"
    )
    result = _post_json(
        url,
        {
            "system_instruction": {"parts": [{"text": LLM_SYSTEM_PROMPT}]},
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": "Write the ExplainableIncidentCard prose from this incident JSON:\n"
                            + json.dumps(payload, default=str)
                        }
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
            },
        },
        {"Content-Type": "application/json"},
    )
    if not result:
        return None
    try:
        text = result["candidates"][0]["content"]["parts"][0]["text"]
        return json.loads(text)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        return None


def _call_llm(payload: dict[str, Any]) -> dict | None:
    provider = resolve_llm_provider()
    if provider == "gemini":
        return _call_gemini(payload)
    if provider == "openai" or (not provider and resolve_llm_api_key("openai")):
        return _call_openai(payload)
    if resolve_llm_api_key("gemini"):
        return _call_gemini(payload)
    return None


def timeline_cites_real_ids(lines: list[str], known_ids: set[str]) -> bool:
    if not lines:
        return False
    for line in lines:
        cited = BRACKET_ID.findall(line)
        if not cited:
            return False
        if any(item not in known_ids for item in cited):
            return False
        if not any(item in known_ids for item in cited):
            return False
    return True


def _text_uses_only_known_facts(text: str, known: dict[str, set[str]]) -> bool:
    for cited in BRACKET_ID.findall(text):
        if cited not in known["alert_ids"]:
            return False
    for ip in IPV4.findall(text):
        if ip not in known["ips"]:
            return False
    return True


def apply_llm_prose(card: IncidentCard, rewritten: dict[str, Any]) -> IncidentCard:
    """Accept LLM prose only after evidence checks. Scores and ranks stay frozen."""
    known = _known_tokens(card)
    summary = rewritten.get("executive_summary")
    contrastive = rewritten.get("contrastive_explanation")
    fp_text = rewritten.get("why_not_false_positive")
    timeline = rewritten.get("attack_timeline")
    actions = rewritten.get("recommended_actions")

    updates: dict[str, Any] = {
        "risk_score": card.risk_score,
        "priority_rank": card.priority_rank,
        "naive_siem_rank": card.naive_siem_rank,
        "why_prioritized": list(card.why_prioritized),
        "risk": card.risk,
        "alert_ids": list(card.alert_ids),
        "tactics": list(card.tactics),
        "techniques": list(card.techniques),
        "users": list(card.users),
        "hosts": list(card.hosts),
    }

    def take_text(value: object) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        return text if _text_uses_only_known_facts(text, known) else None

    summary_ok = take_text(summary)
    contrastive_ok = take_text(contrastive)
    fp_ok = take_text(fp_text)
    timeline_ok: list[str] | None = None
    if isinstance(timeline, list):
        cleaned = [str(line).strip() for line in timeline if str(line).strip()]
        if cleaned and timeline_cites_real_ids(cleaned, known["alert_ids"]) and all(
            _text_uses_only_known_facts(line, known) for line in cleaned
        ):
            timeline_ok = cleaned
    actions_ok: list[str] | None = None
    if isinstance(actions, list):
        cleaned_actions = [str(item).strip() for item in actions if str(item).strip()]
        if cleaned_actions and all(_text_uses_only_known_facts(item, known) for item in cleaned_actions):
            actions_ok = cleaned_actions

    def present(value: object) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, list):
            return bool(value)
        return True

    provided = [
        present(summary),
        present(contrastive),
        present(fp_text),
        present(timeline),
        present(actions),
    ]
    accepted = [
        summary_ok is not None if present(summary) else True,
        contrastive_ok is not None if present(contrastive) else True,
        fp_ok is not None if present(fp_text) else True,
        timeline_ok is not None if present(timeline) else True,
        actions_ok is not None if present(actions) else True,
    ]
    if not any(provided) or not all(accepted):
        return card
    if summary_ok:
        updates["executive_summary"] = summary_ok
    if contrastive_ok:
        updates["contrastive"] = contrastive_ok
        updates["contrastive_explanation"] = contrastive_ok
    if fp_ok:
        updates["why_not_false_positive"] = fp_ok
    if timeline_ok:
        updates["attack_timeline"] = timeline_ok
    if actions_ok:
        updates["recommended_actions"] = actions_ok
        updates["containment"] = actions_ok
    updates["llm_enhanced"] = True
    updates["explanation_source"] = "llm"
    return card.model_copy(update=updates)


def enhance_with_llm(card: IncidentCard) -> IncidentCard:
    """Optional prose rewrite. Missing keys or a failed call keep the template card."""
    if not llm_is_configured() and not resolve_llm_api_key():
        return card
    rewritten = _call_llm(llm_incident_payload(card))
    if not rewritten or not isinstance(rewritten, dict):
        return card
    return apply_llm_prose(card, rewritten)


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
    apply_llm = llm_is_configured() if use_llm is None else use_llm
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
