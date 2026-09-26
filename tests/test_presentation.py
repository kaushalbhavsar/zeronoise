from __future__ import annotations

from config import ALERTS_PATH, CMDB_PATH, IAM_PATH
from engine.pipeline import run_pipeline
from engine.presentation import (
    context_badges,
    correlation_evidence,
    rank_delta,
    rank_delta_label,
    raw_alert_ids,
)
from engine.risk_scorer import score_incident, score_incidents
from tests.test_risk_scoring import _breach_incident, _scanner_incident


def test_badges_come_from_incident_facts_not_scenario() -> None:
    breach = score_incident(_breach_incident())
    scanner = score_incident(_scanner_incident())
    assert "Crown Jewel" in context_badges(breach)
    assert "Production" in context_badges(breach)
    assert "PCI/PII" in context_badges(breach)
    assert "Exfiltration" in context_badges(breach)
    assert "Cross-Sensor" in context_badges(breach)
    assert "Sandbox" not in context_badges(breach)
    assert "Sandbox" in context_badges(scanner)
    assert "High FP Rule" in context_badges(scanner)
    assert "Crown Jewel" not in context_badges(scanner)
    for item in (breach, scanner):
        for alert in item.incident.alerts:
            alert.scenario_id = "should_not_matter"
        assert "quiet_crown_jewel" not in context_badges(item)
        assert "noisy_false_priority" not in context_badges(item)


def test_rank_delta_promotes_when_legacy_is_worse() -> None:
    assert rank_delta(1, 27) == 26
    assert rank_delta_label(26) == "↑ 26 positions"
    assert rank_delta_label(-3) == "↓ 3 positions"
    assert rank_delta_label(0) == "same rank"


def test_score_incidents_sets_both_ranks() -> None:
    ranked = score_incidents([_scanner_incident(), _breach_incident()])
    assert ranked[0].risk_rank == 1
    assert ranked[1].risk_rank == 2
    scanner = next(item for item in ranked if item.incident.alerts[0].alert_id.startswith("S"))
    assert scanner.naive_siem_rank == 1
    assert scanner.risk_rank == 2


def test_correlation_evidence_cites_real_alert_ids() -> None:
    breach = score_incident(_breach_incident())
    rows = correlation_evidence(breach)
    known = set(breach.incident.alert_ids)
    assert rows
    for row in rows:
        assert row["from"] in known
        assert row["to"] in known
        assert row["reason"]


def test_driver_labels_match_console_copy() -> None:
    from engine.presentation import driver_label

    assert driver_label("FP/Noise Suppression") == "Noise / FP Suppression"
    assert driver_label("Blast Radius") == "Blast Radius"
    assert driver_label("Kill-Chain Progression") == "Kill-Chain Progression"
    assert driver_label("Alert Fidelity") == "Alert Fidelity"


def test_run_pipeline_accepts_path_strings() -> None:
    result = run_pipeline(str(ALERTS_PATH), str(CMDB_PATH), str(IAM_PATH), use_llm=False)
    assert result.metrics.raw_alert_count >= 280
    assert result.metrics.high_priority_count >= 1
    assert result.risk_ranked[0].risk_rank == 1
    first = result.legacy_ranked[0]
    assert first.naive_siem_rank == 1
    assert first.incident.incident_id != result.risk_ranked[0].incident.incident_id
    m = result.metrics
    assert m.fatigue_reduction_pct == round(100.0 * (1.0 - m.incident_count / m.raw_alert_count), 2)
    assert m.volume_compression_pct == round(
        100.0 * (1.0 - m.deduplicated_alert_count / m.raw_alert_count), 2
    )
    top = result.risk_ranked[0]
    card = result.cards[0]
    assert sum(d.contribution_pct for d in card.why_prioritized) == 100
    assert card.attack_timeline[0][0].isdigit()
    assert any(f"[{alert_id}]" in " ".join(card.attack_timeline) for alert_id in top.incident.alert_ids)
    evidence = correlation_evidence(top)
    assert evidence
    assert all(row["from"] in top.incident.alert_ids for row in evidence)
    originals = raw_alert_ids(top)
    assert originals
    assert set(top.incident.alert_ids) <= set(originals) or len(originals) >= len(top.incident.alert_ids)


def test_seed_pipeline_actions_name_real_crown_jewel_entities() -> None:
    result = run_pipeline(str(ALERTS_PATH), str(CMDB_PATH), str(IAM_PATH), use_llm=False)
    crown = next(
        card
        for card in result.cards
        if "usr_admin_root" in card.users and "prd-billing-db-01" in card.hosts
    )
    blob = " ".join(crown.recommended_actions)
    assert "Disable or rotate usr_admin_root credentials." in crown.recommended_actions
    assert "Isolate prd-app-02 from the network." in crown.recommended_actions
    assert "Restrict outbound connectivity from prd-billing-db-01." in crown.recommended_actions
    assert "Preserve EDR telemetry before remediation." in crown.recommended_actions
    assert "Review authentication activity associated with usr_svc_deploy." in crown.recommended_actions
    assert "involved hosts" not in blob
    assert "involved accounts" not in blob
