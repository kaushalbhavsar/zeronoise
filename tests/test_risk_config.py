from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from engine.risk_config import (
    RiskParameters,
    config_fingerprint,
    default_risk_parameters,
    load_risk_config,
    priority_from_score,
    set_active_risk_config,
)
from engine.risk_scorer import (
    normalize_risk,
    raw_risk,
    score_incident,
    score_progression,
)
from tests.test_risk_scoring import _breach_incident, _scanner_incident


def test_defaults_match_prototype() -> None:
    cfg = RiskParameters()
    assert cfg.model_version == "ZN-RISK-1.0"
    assert cfg.severity_weights.low == 2
    assert cfg.severity_weights.medium == 5
    assert cfg.severity_weights.high == 10
    assert cfg.severity_weights.critical == 15
    assert cfg.tactic_progression_weight == 0.35
    assert cfg.sensor_corroboration_weight == 0.20
    assert cfg.completion_weight == 0.50
    assert cfg.false_positive_dampening == 0.70
    assert cfg.duplicate_volume_weight == 0.10
    assert cfg.asset_context_weight == 0.65
    assert cfg.identity_context_weight == 0.35
    assert cfg.fidelity_cap == 35.0
    assert cfg.normalization_scale == 45.0
    assert cfg.p0_threshold == 85
    assert cfg.p1_threshold == 70
    assert cfg.p2_threshold == 50
    assert cfg.p3_threshold == 30
    assert cfg.calibration.source == "expert_defined"
    assert cfg.calibration.ndcg_at_5 is None


def test_yaml_matches_builtin_defaults() -> None:
    loaded = load_risk_config(Path("config/risk-model.yaml"))
    builtin = default_risk_parameters()
    assert loaded.fingerprint() == builtin.fingerprint()
    assert loaded.model_version == "ZN-RISK-1.0"


def test_invalid_context_weights_rejected() -> None:
    with pytest.raises(ValidationError, match="asset_context_weight"):
        RiskParameters(asset_context_weight=0.8, identity_context_weight=0.4)


def test_invalid_thresholds_rejected() -> None:
    with pytest.raises(ValidationError, match="Priority thresholds"):
        RiskParameters(p0_threshold=70, p1_threshold=85)


def test_invalid_normalization_scale_rejected() -> None:
    with pytest.raises(ValidationError):
        RiskParameters(normalization_scale=0)


def test_invalid_fp_dampening_rejected() -> None:
    with pytest.raises(ValidationError):
        RiskParameters(false_positive_dampening=1.5)


def test_sensor_weight_may_not_exceed_tactic_weight() -> None:
    with pytest.raises(ValidationError, match="sensor_corroboration_weight"):
        RiskParameters(tactic_progression_weight=0.10, sensor_corroboration_weight=0.40)


def test_score_reproducible_with_same_config() -> None:
    cfg = RiskParameters()
    first = score_incident(_breach_incident(), cfg)
    second = score_incident(_breach_incident(), cfg)
    assert first.risk.raw_weighted_score == second.risk.raw_weighted_score
    assert first.risk.risk_score == second.risk.risk_score
    assert priority_from_score(first.risk.risk_score, cfg) == priority_from_score(
        second.risk.risk_score, cfg
    )
    assert first.risk_config_hash == second.risk_config_hash == cfg.fingerprint()
    assert first.risk_model_version == "ZN-RISK-1.0"


def test_completion_weight_moves_exfil_score_only() -> None:
    base = RiskParameters()
    boosted = base.model_copy(update={"completion_weight": 0.90})
    breach = _breach_incident()
    scanner = _scanner_incident()
    assert "Exfiltration" in breach.unique_tactics
    assert "Impact" not in scanner.unique_tactics
    assert "Exfiltration" not in scanner.unique_tactics
    breach_base = score_incident(breach, base)
    breach_hot = score_incident(breach, boosted)
    scanner_base = score_incident(scanner, base)
    scanner_hot = score_incident(scanner, boosted)
    assert breach_hot.risk.risk_score > breach_base.risk.risk_score
    k_base, _ = score_progression(breach, base)
    k_hot, _ = score_progression(breach, boosted)
    assert k_hot > k_base
    assert scanner_hot.risk.risk_score == scanner_base.risk.risk_score


def test_version_and_hash_travel_with_score() -> None:
    scored = score_incident(_breach_incident())
    assert scored.risk_model_version == "ZN-RISK-1.0"
    assert scored.risk_model_name == "ZeroNoise Risk Model"
    assert len(scored.risk_config_hash) == 64
    assert scored.risk.config_hash == scored.risk_config_hash
    assert scored.risk.model_version == "ZN-RISK-1.0"


def test_fingerprint_ignores_calibration_metrics() -> None:
    left = RiskParameters()
    right = left.model_copy(
        update={
            "calibration": left.calibration.model_copy(
                update={"incident_count": 1842, "ndcg_at_5": 0.91}
            )
        }
    )
    assert left.fingerprint() == right.fingerprint()
    changed = left.model_copy(update={"completion_weight": 0.51})
    assert changed.fingerprint() != left.fingerprint()


def test_priority_bands_use_config() -> None:
    cfg = RiskParameters()
    assert priority_from_score(88, cfg) == "P0"
    assert priority_from_score(80, cfg) == "P1"
    assert priority_from_score(51, cfg) == "P2"
    assert priority_from_score(30, cfg) == "P3"
    assert priority_from_score(12, cfg) == "P4"


def test_missing_file_uses_defaults(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yaml"
    loaded = load_risk_config(missing)
    assert loaded.model_version == "ZN-RISK-1.0"
    assert loaded.fingerprint() == default_risk_parameters().fingerprint()


def test_corrupt_file_fails_fast(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("asset_context_weight: 0.8\nidentity_context_weight: 0.4\n")
    with pytest.raises(ValueError, match="Invalid risk configuration"):
        load_risk_config(path)


def test_normalize_uses_config_scale() -> None:
    cfg = RiskParameters(normalization_scale=45.0)
    assert normalize_risk(0, cfg) == 0.0
    assert 0 < normalize_risk(raw_risk(10, 2, 1), cfg) < 100


# keep a local alias so an accidental unused import is obvious if fingerprint helper moves
def test_public_fingerprint_helper_matches_model() -> None:
    cfg = RiskParameters()
    assert config_fingerprint(cfg) == cfg.fingerprint()


def test_config_is_frozen() -> None:
    cfg = RiskParameters()
    with pytest.raises(ValidationError):
        cfg.completion_weight = 0.9  # type: ignore[misc]


def test_unknown_keys_rejected() -> None:
    with pytest.raises(ValidationError):
        RiskParameters.model_validate({"alpha": 0.35})


def test_negative_additive_weight_rejected() -> None:
    with pytest.raises(ValidationError):
        RiskParameters(tactic_progression_weight=-0.1)


def test_yaml_integer_criticality_keys_apply(tmp_path: Path) -> None:
    path = tmp_path / "crit.yaml"
    path.write_text(
        Path("config/risk-model.yaml").read_text(encoding="utf-8").replace(
            "  5: 2.0", "  5: 1.7"
        ),
        encoding="utf-8",
    )
    loaded = load_risk_config(path)
    assert loaded.criticality_weight(5) == 1.7
    assert loaded.fingerprint() != default_risk_parameters().fingerprint()
    set_active_risk_config(default_risk_parameters())


def test_seed_42_prototype_scores_and_metadata() -> None:
    from data.generate_synthetic_data import generate_dataset
    from engine.pipeline import run_pipeline

    assets, identities, alerts = generate_dataset(seed=42)
    result = run_pipeline(alerts=alerts, assets=assets, identities=identities)
    ransom = next(
        item
        for item in result.risk_ranked
        if any(a.scenario_id == "ransomware_staging" for a in item.incident.alerts)
    )
    crown = next(
        item
        for item in result.risk_ranked
        if any(a.scenario_id == "quiet_crown_jewel" for a in item.incident.alerts)
    )
    noisy = next(
        item
        for item in result.risk_ranked
        if any(a.scenario_id == "noisy_false_priority" for a in item.incident.alerts)
    )
    assert ransom.risk_rank == 1
    assert crown.risk_rank == 2
    assert noisy.risk_rank is not None and noisy.risk_rank > 2
    assert abs(ransom.risk.risk_score - 88.3461) < 1e-3
    assert abs(crown.risk.risk_score - 80.8194) < 1e-3
    assert all(item.risk_model_version == "ZN-RISK-1.0" for item in result.incidents)
    assert all(len(item.risk_config_hash) == 64 for item in result.incidents)
    assert {item.risk_config_hash for item in result.incidents} == {
        default_risk_parameters().fingerprint()
    }
