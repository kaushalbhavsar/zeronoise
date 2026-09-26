"""End-to-end acceptance for the mandatory attack scenarios."""

from __future__ import annotations

from datetime import datetime

from data.generate_synthetic_data import generate_dataset
from engine.explainer import enhance_with_llm, explain_incidents
from engine.pipeline import fingerprint, run_pipeline
from engine.risk_scorer import positive_attribution_sum


def _pipeline():
    assets, identities, alerts = generate_dataset(seed=42)
    return run_pipeline(alerts=alerts, assets=assets, identities=identities, use_llm=False)


def test_seed_42_dataset_matches_required_shape() -> None:
    assets, identities, alerts = generate_dataset(seed=42)
    assert len(assets) >= 8
    assert len(identities) >= 5
    assert 280 <= len(alerts) <= 320
    by_sid = {}
    for alert in alerts:
        by_sid.setdefault(alert["scenario_id"], []).append(alert)
    assert len(by_sid["quiet_crown_jewel"]) == 4
    assert all(a["sev"] == "Medium" for a in by_sid["quiet_crown_jewel"])
    assert len(by_sid["ransomware_staging"]) == 6
    assert len(by_sid["noisy_false_priority"]) == 120
    assert 160 <= len(by_sid["background_noise"]) <= 180
    times = [datetime.fromisoformat(a["time"]) for a in alerts]
    assert (max(times) - min(times)).total_seconds() >= 20 * 3600
    crown = by_sid["quiet_crown_jewel"]
    assert {a["user_id"] for a in crown} >= {"usr_svc_deploy", "usr_admin_root"}
    assert {a["host_id"] for a in crown} >= {"prd-app-02", "prd-billing-db-01"}
    billing = next(a for a in assets if a["host_id"] == "prd-billing-db-01")
    assert billing["environment"] == "prod"
    assert billing["data_sensitivity"] == "crown_jewel_pii_pci"
    assert billing["business_criticality"] == 5
    sandbox = next(a for a in assets if a["host_id"] == "dev-sandbox-04")
    assert sandbox["environment"] == "sandbox"
    assert sandbox["business_criticality"] == 1
    assert sandbox["data_sensitivity"] == "public"


def test_pipeline_is_deterministic_for_fixed_seed() -> None:
    left = _pipeline()
    right = _pipeline()
    assert fingerprint(left) == fingerprint(right)
    assert [c.incident_id for c in left.cards] == [c.incident_id for c in right.cards]
    assert [c.risk_score for c in left.cards] == [c.risk_score for c in right.cards]


def test_mandatory_ranking_outcomes() -> None:
    result = _pipeline()
    m = result.metrics
    assert m.ransomware_staging_risk_rank == 1
    assert m.quiet_crown_jewel_risk_rank == 2
    assert m.noisy_false_priority_legacy_rank == 1
    assert m.quiet_crown_jewel_legacy_rank is not None
    assert m.quiet_crown_jewel_legacy_rank > 1
    assert m.noisy_false_priority_risk_rank is not None
    assert m.noisy_false_priority_risk_rank > 2
    assert m.ranking_inverted is True


def test_fatigue_reduction_is_measurable_and_high_volume_collapses() -> None:
    result = _pipeline()
    assert result.metrics.fatigue_reduction_pct >= 60.0
    assert result.metrics.deduplicated_alert_count < result.metrics.raw_alert_count * 0.7
    scanner = next(
        item
        for item in result.incidents
        if any(a.scenario_id == "noisy_false_priority" for a in item.incident.alerts)
    )
    assert scanner.incident.total_event_count == 120
    assert len(scanner.incident.alerts) < 120
    crown = next(
        item
        for item in result.incidents
        if any(a.scenario_id == "quiet_crown_jewel" for a in item.incident.alerts)
    )
    assert len(crown.incident.alerts) == 4


def test_background_noise_does_not_weld_into_a_giant_incident() -> None:
    result = _pipeline()
    for item in result.incidents:
        sids = {alert.scenario_id for alert in item.incident.alerts}
        if sids == {"background_noise"}:
            assert len(item.incident.alerts) <= 8
            assert item.incident.total_event_count <= 12


def test_scrambling_scenario_ids_does_not_change_clusters_or_scores() -> None:
    assets, identities, alerts = generate_dataset(seed=42)
    baseline = run_pipeline(alerts=alerts, assets=assets, identities=identities)
    scrambled = []
    for idx, alert in enumerate(alerts):
        copy = dict(alert)
        copy["scenario_id"] = f"scrambled-{idx}"
        scrambled.append(copy)
    mutated = run_pipeline(alerts=scrambled, assets=assets, identities=identities)
    assert fingerprint(baseline) == fingerprint(mutated)


def test_attribution_and_explanations_are_traceable() -> None:
    result = _pipeline()
    top = result.risk_ranked[0]
    assert abs(positive_attribution_sum(top.risk) - 100.0) < 0.05
    card = result.cards[0]
    assert card.incident_id == top.incident.incident_id
    assert card.executive_summary
    assert card.narrative
    assert card.containment
    assert card.explanation_source == "deterministic"
    assert card.llm_enhanced is False
    assert set(card.alert_ids) == set(top.incident.alert_ids)


def test_llm_enhancement_cannot_mutate_scores_or_entities() -> None:
    result = _pipeline()
    original = result.cards[0]
    unchanged = enhance_with_llm(original)
    assert unchanged.risk_score == original.risk_score
    assert unchanged.alert_ids == original.alert_ids
    assert unchanged.tactics == original.tactics
    assert unchanged.risk.drivers == original.risk.drivers
    cards = explain_incidents(result.risk_ranked, use_llm=False)
    assert [c.risk_score for c in cards] == [i.risk.risk_score for i in result.risk_ranked]


def test_contrastive_text_never_compares_an_incident_to_itself() -> None:
    result = _pipeline()
    scanner = next(
        card
        for card in result.cards
        if card.risk_rank == result.metrics.noisy_false_priority_risk_rank
    )
    crown = next(
        card
        for card in result.cards
        if card.risk_rank == result.metrics.quiet_crown_jewel_risk_rank
    )
    assert scanner.contrastive
    assert crown.incident_id in (scanner.contrastive or "")
    assert scanner.incident_id != crown.incident_id
    assert "ranks below" in (scanner.contrastive or "")
    assert crown.contrastive
    assert scanner.incident_id in (crown.contrastive or "")
    assert "outranks" in (crown.contrastive or "")


def test_malformed_rows_do_not_fail_the_pipeline() -> None:
    assets, identities, alerts = generate_dataset(seed=42)
    broken = list(alerts)
    broken.insert(0, {"id": "BAD", "time": "not-a-time"})
    result = run_pipeline(alerts=broken, assets=assets, identities=identities)
    assert result.metrics.dropped_alert_count >= 1
    assert result.metrics.ransomware_staging_risk_rank == 1
    assert result.metrics.quiet_crown_jewel_risk_rank == 2
