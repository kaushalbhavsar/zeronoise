"""End-to-end acceptance: the demo must invert a false SIEM priority."""

from __future__ import annotations

from data.generate_synthetic_data import generate_dataset
from engine.explainer import enhance_with_llm, explain_incidents
from engine.pipeline import fingerprint, run_pipeline
from engine.risk_scorer import positive_attribution_sum


def _pipeline():
    assets, identities, alerts = generate_dataset(seed=42)
    return run_pipeline(alerts=alerts, assets=assets, identities=identities, use_llm=False)


def test_seed_42_dataset_is_large_enough_to_show_fatigue() -> None:
    assets, identities, alerts = generate_dataset(seed=42)
    assert len(assets) >= 8
    assert len(identities) >= 5
    assert len(alerts) >= 350
    assert sum(1 for a in alerts if a["scenario_id"] == "true_breach") < 20
    assert sum(1 for a in alerts if a["scenario_id"] == "noisy_scanner") >= 200


def test_pipeline_is_deterministic_for_fixed_seed() -> None:
    left = _pipeline()
    right = _pipeline()
    assert fingerprint(left) == fingerprint(right)
    assert [c.incident_id for c in left.cards] == [c.incident_id for c in right.cards]
    assert [c.risk_score for c in left.cards] == [c.risk_score for c in right.cards]


def test_true_breach_is_top_risk_and_not_top_legacy() -> None:
    result = _pipeline()
    m = result.metrics
    assert m.true_breach_risk_rank == 1
    assert m.noisy_scanner_legacy_rank == 1
    assert m.true_breach_legacy_rank is not None and m.true_breach_legacy_rank > 1
    assert m.noisy_scanner_risk_rank is not None and m.noisy_scanner_risk_rank > 1
    assert m.ranking_inverted is True


def test_fatigue_reduction_exceeds_eighty_percent() -> None:
    result = _pipeline()
    assert result.metrics.fatigue_reduction_pct >= 80.0
    assert result.metrics.incident_count < result.metrics.raw_alert_count / 5
    assert result.metrics.deduplicated_alert_count < result.metrics.raw_alert_count / 2


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
    # Force the optional path with LLM disabled in config; the helper must
    # still refuse to invent state when the flag is off or the API is absent.
    unchanged = enhance_with_llm(original)
    assert unchanged.risk_score == original.risk_score
    assert unchanged.alert_ids == original.alert_ids
    assert unchanged.tactics == original.tactics
    assert unchanged.risk.drivers == original.risk.drivers

    cards = explain_incidents(result.risk_ranked, use_llm=False)
    assert [c.risk_score for c in cards] == [i.risk.risk_score for i in result.risk_ranked]
    assert cards[0].alert_ids == original.alert_ids
    assert cards[0].risk.drivers == original.risk.drivers
