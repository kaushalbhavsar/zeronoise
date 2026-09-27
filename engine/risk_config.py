"""Versioned, validated risk-model parameters.

Risk model logic (how B, K, and C combine) lives in risk_scorer.py.
These parameters define how strongly each factor influences the score.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

LOGGER = logging.getLogger("zeronoise.risk")

ATTRIBUTION_FACTORS: tuple[str, ...] = (
    "Alert Fidelity",
    "Kill-Chain Progression",
    "Blast Radius",
    "FP/Noise Suppression",
)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "risk-model.yaml"
_WEIGHT_TOLERANCE = 1e-6

_ACTIVE: RiskParameters | None = None


class SeverityWeights(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    low: float = Field(default=2.0, ge=0, description="Weight for vendor Low severity.")
    medium: float = Field(default=5.0, ge=0, description="Weight for vendor Medium severity.")
    high: float = Field(default=10.0, ge=0, description="Weight for vendor High severity.")
    critical: float = Field(default=15.0, ge=0, description="Weight for vendor Critical severity.")

    def for_label(self, label: str) -> float:
        return getattr(self, label.lower())


class EnvironmentWeights(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    sandbox: float = Field(default=0.4, ge=0, description="Multiplier for sandbox / lab hosts.")
    dev: float = Field(default=0.7, ge=0, description="Multiplier for development hosts.")
    staging: float = Field(default=1.0, ge=0, description="Multiplier for staging hosts.")
    prod: float = Field(default=1.4, ge=0, description="Multiplier for production hosts.")

    def for_label(self, label: str) -> float:
        return getattr(self, label)


class DataSensitivityWeights(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    public: float = Field(default=0.5, ge=0, description="Multiplier for public data.")
    internal: float = Field(default=0.9, ge=0, description="Multiplier for internal data.")
    confidential: float = Field(default=1.4, ge=0, description="Multiplier for confidential data.")
    crown_jewel_pii_pci: float = Field(
        default=2.0, ge=0, description="Multiplier for crown-jewel / PII / PCI data."
    )

    def for_label(self, label: str) -> float:
        return getattr(self, label)


class PrivilegeWeights(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    standard_user: float = Field(default=0.5, ge=0, description="Multiplier for a standard user.")
    service_account: float = Field(default=1.0, ge=0, description="Multiplier for a service account.")
    tier_1_cloud_admin: float = Field(
        default=1.4, ge=0, description="Multiplier for a tier-1 cloud admin."
    )
    tier_0_domain_admin: float = Field(
        default=1.8, ge=0, description="Multiplier for a tier-0 / domain admin."
    )

    def for_label(self, label: str) -> float:
        return getattr(self, label)


class BusinessCriticalityWeights(BaseModel):
    """Explicit CMDB criticality mapping. Easier to calibrate than a linear formula."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)
    level_1: float = Field(default=0.4, ge=0, alias="1", description="CMDB criticality 1.")
    level_2: float = Field(default=0.8, ge=0, alias="2", description="CMDB criticality 2.")
    level_3: float = Field(default=1.2, ge=0, alias="3", description="CMDB criticality 3.")
    level_4: float = Field(default=1.6, ge=0, alias="4", description="CMDB criticality 4.")
    level_5: float = Field(default=2.0, ge=0, alias="5", description="CMDB criticality 5.")

    @model_validator(mode="before")
    @classmethod
    def _stringify_level_keys(cls, data: object) -> object:
        if isinstance(data, dict):
            return {str(key): value for key, value in data.items()}
        return data

    def for_level(self, level: int) -> float:
        return getattr(self, f"level_{level}")


class CalibrationMetadata(BaseModel):
    """Provenance only. Never invent NDCG or recall figures."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    source: Literal[
        "expert_defined",
        "synthetic_calibration",
        "historical_incidents",
        "shadow_mode",
    ] = "expert_defined"
    calibration_date: date | None = None
    incident_count: int | None = None
    ndcg_at_5: float | None = None
    ndcg_at_10: float | None = None
    critical_recall_at_10: float | None = None


class RiskParameters(BaseModel):
    """Tunable coefficients for ZN-RISK. Frozen after validation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_name: str = Field(default="ZeroNoise Risk Model", description="Human-readable model name.")
    model_version: str = Field(
        default="ZN-RISK-1.0",
        description="Version stamp stored with every score (logic version, not a weight).",
    )

    severity_weights: SeverityWeights = Field(default_factory=SeverityWeights)
    environment_weights: EnvironmentWeights = Field(default_factory=EnvironmentWeights)
    data_sensitivity_weights: DataSensitivityWeights = Field(
        default_factory=DataSensitivityWeights
    )
    privilege_weights: PrivilegeWeights = Field(default_factory=PrivilegeWeights)
    business_criticality_weights: BusinessCriticalityWeights = Field(
        default_factory=BusinessCriticalityWeights
    )

    tactic_progression_weight: float = Field(
        default=0.35,
        ge=0,
        description="How much each extra ATT&CK stage raises K. Higher: multi-stage attacks rise faster.",
    )
    sensor_corroboration_weight: float = Field(
        default=0.20,
        ge=0,
        description="How much each extra sensor raises K. Higher: cross-sensor incidents rise faster.",
    )
    completion_weight: float = Field(
        default=0.50,
        ge=0,
        description="Bonus on K when Exfiltration or Impact is observed.",
    )
    false_positive_dampening: float = Field(
        default=0.70,
        ge=0,
        le=1,
        description="How strongly a high FPR reduces per-alert fidelity.",
    )
    duplicate_volume_weight: float = Field(
        default=0.10,
        ge=0,
        description="Log-volume coefficient. Higher: repeated detections matter more.",
    )
    asset_context_weight: float = Field(
        default=0.65,
        ge=0,
        le=1,
        description="Share of C from the highest-risk asset.",
    )
    identity_context_weight: float = Field(
        default=0.35,
        ge=0,
        le=1,
        description="Share of C from the highest-risk identity.",
    )
    asset_environment_blend: float = Field(
        default=0.35,
        ge=0,
        le=1,
        description="Share of asset_risk from environment. Must sum with the other asset blends to 1.0.",
    )
    asset_data_blend: float = Field(
        default=0.35,
        ge=0,
        le=1,
        description="Share of asset_risk from data sensitivity.",
    )
    asset_criticality_blend: float = Field(
        default=0.30,
        ge=0,
        le=1,
        description="Share of asset_risk from CMDB business criticality.",
    )
    asset_score_min: float = Field(
        default=0.4, ge=0, description="Lower clip for computed asset_risk."
    )
    asset_score_max: float = Field(
        default=2.0, gt=0, description="Upper clip for computed asset_risk."
    )
    fidelity_cap: float = Field(
        default=35.0,
        gt=0,
        description="Maximum accumulated B. Higher: more distinct detections can add before saturation.",
    )
    normalization_scale: float = Field(
        default=45.0,
        gt=0,
        description="Saturating-map scale. Higher: scores rise more slowly toward 100.",
    )
    p0_threshold: float = Field(
        default=85.0, ge=0, le=100, description="Inclusive lower bound for P0. Must be > P1."
    )
    p1_threshold: float = Field(
        default=70.0, ge=0, le=100, description="Inclusive lower bound for P1. Must be > P2."
    )
    p2_threshold: float = Field(
        default=50.0, ge=0, le=100, description="Inclusive lower bound for P2. Must be > P3."
    )
    p3_threshold: float = Field(
        default=30.0,
        ge=0,
        le=100,
        description="Inclusive lower bound for P3. Below this is P4. ZN-RISK-1.0 keeps a P4 band.",
    )
    correlation_window_hours: float = Field(
        default=4.0, gt=0, description="Maximum time gap for joining related alerts."
    )
    dedup_window_minutes: float = Field(
        default=15.0, gt=0, description="Rolling window that collapses duplicate detections."
    )
    progression_base: float = Field(
        default=1.0, ge=0, description="Baseline K before tactic/sensor/completion bonuses."
    )
    completion_tactics: tuple[str, ...] = Field(
        default=("Exfiltration", "Impact"),
        description="ATT&CK tactics that set the completion flag on K.",
    )
    neutral_impact: float = Field(
        default=0.90, ge=0, description="asset_risk used when a host is not in CMDB."
    )
    neutral_privilege: float = Field(
        default=0.70, ge=0, description="P_priv used when a claimed user is missing from IAM."
    )
    unobserved_privilege: float = Field(
        default=0.50, ge=0, description="P_priv used when no user was observed."
    )
    fidelity_baseline: float = Field(
        default=2.0, ge=0, description="Ablation baseline for B (not a scoring coefficient)."
    )
    progression_baseline: float = Field(
        default=1.0, ge=0, description="Ablation baseline for K."
    )
    blast_baseline: float = Field(
        default=1.0, ge=0, description="Ablation baseline for C."
    )
    calibration: CalibrationMetadata = Field(default_factory=CalibrationMetadata)

    @model_validator(mode="after")
    def validate_weights(self) -> "RiskParameters":
        context = self.asset_context_weight + self.identity_context_weight
        if abs(context - 1.0) > _WEIGHT_TOLERANCE:
            raise ValueError(
                "asset_context_weight + identity_context_weight must equal 1.0 "
                f"(got {context:.6f})"
            )
        blend = (
            self.asset_environment_blend
            + self.asset_data_blend
            + self.asset_criticality_blend
        )
        if abs(blend - 1.0) > _WEIGHT_TOLERANCE:
            raise ValueError(
                "asset environment/data/criticality blends must equal 1.0 "
                f"(got {blend:.6f})"
            )
        if not (
            self.p0_threshold
            > self.p1_threshold
            > self.p2_threshold
            > self.p3_threshold
        ):
            raise ValueError(
                "Priority thresholds must satisfy P0 > P1 > P2 > P3 "
                f"(got {self.p0_threshold}, {self.p1_threshold}, "
                f"{self.p2_threshold}, {self.p3_threshold})"
            )
        if self.sensor_corroboration_weight > self.tactic_progression_weight:
            raise ValueError(
                "sensor_corroboration_weight must not exceed tactic_progression_weight "
                "in ZN-RISK-1.0 (progression should not matter less than adding a sensor)"
            )
        if self.asset_score_max < self.asset_score_min:
            raise ValueError("asset_score_max must be >= asset_score_min")
        return self

    def severity_weight(self, label: str) -> float:
        return self.severity_weights.for_label(label)

    def environment_weight(self, label: str) -> float:
        return self.environment_weights.for_label(label)

    def data_weight(self, label: str) -> float:
        return self.data_sensitivity_weights.for_label(label)

    def privilege_weight(self, label: str) -> float:
        return self.privilege_weights.for_label(label)

    def criticality_weight(self, level: int) -> float:
        return self.business_criticality_weights.for_level(level)

    def severity_table(self) -> dict[str, float]:
        return {
            "Low": self.severity_weights.low,
            "Medium": self.severity_weights.medium,
            "High": self.severity_weights.high,
            "Critical": self.severity_weights.critical,
        }

    def environment_table(self) -> dict[str, float]:
        return self.environment_weights.model_dump()

    def data_table(self) -> dict[str, float]:
        return self.data_sensitivity_weights.model_dump()

    def privilege_table(self) -> dict[str, float]:
        return self.privilege_weights.model_dump()

    def criticality_table(self) -> dict[int, float]:
        return {index: self.criticality_weight(index) for index in range(1, 6)}

    def correlation_window_minutes(self) -> float:
        return self.correlation_window_hours * 60.0

    def formula_text(self) -> str:
        return (
            f"risk_score = 100 × (1 − exp(−RawRisk / {self.normalization_scale})), "
            f"RawRisk = B × K × C, "
            f"C = {self.asset_context_weight}×asset_risk + {self.identity_context_weight}×P_priv, "
            f"B = min(Σ fidelity_a over unique (rule, tactic), {self.fidelity_cap}), "
            f"K = {self.progression_base} + {self.tactic_progression_weight}×max(0,m-1) + "
            f"{self.sensor_corroboration_weight}×max(0,s-1) + "
            f"{self.completion_weight}×completion"
        )

    def fingerprint(self) -> str:
        payload = self.model_dump(mode="json", exclude={"calibration"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def short_hash(self) -> str:
        return self.fingerprint()[:12]


def config_fingerprint(config: RiskParameters) -> str:
    return config.fingerprint()


@lru_cache(maxsize=1)
def default_risk_parameters() -> RiskParameters:
    return RiskParameters()


def priority_from_score(score: float, config: RiskParameters | None = None) -> str:
    cfg = config or get_active_risk_config()
    if score >= cfg.p0_threshold:
        return "P0"
    if score >= cfg.p1_threshold:
        return "P1"
    if score >= cfg.p2_threshold:
        return "P2"
    if score >= cfg.p3_threshold:
        return "P3"
    return "P4"


def set_active_risk_config(config: RiskParameters) -> None:
    global _ACTIVE
    _ACTIVE = config


def get_active_risk_config() -> RiskParameters:
    return _ACTIVE if _ACTIVE is not None else default_risk_parameters()


def load_risk_config(path: str | Path = DEFAULT_CONFIG_PATH) -> RiskParameters:
    """Load YAML once, validate, and fail fast on a corrupt file."""
    config_path = Path(path)
    if not config_path.exists():
        LOGGER.warning(
            "Risk configuration file not found. Using built-in ZN-RISK-1.0 defaults. path=%s",
            config_path,
        )
        config = default_risk_parameters()
        _log_initialized(config, source="built-in defaults")
        set_active_risk_config(config)
        return config
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required to load config/risk-model.yaml. Install PyYAML."
        ) from exc
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to parse risk configuration {config_path}: {exc}") from exc
    if raw is None:
        raise ValueError(f"Risk configuration {config_path} is empty.")
    if not isinstance(raw, dict):
        raise ValueError(f"Risk configuration {config_path} must be a mapping.")
    try:
        config = RiskParameters.model_validate(raw)
    except Exception as exc:
        raise ValueError(f"Invalid risk configuration {config_path}: {exc}") from exc
    _log_initialized(config, source=str(config_path))
    set_active_risk_config(config)
    return config


def _log_initialized(config: RiskParameters, *, source: str) -> None:
    LOGGER.info(
        "ZeroNoise Risk Engine initialized model=%s config=%s hash=%s calibration=%s",
        config.model_version,
        source,
        config.short_hash(),
        config.calibration.source,
    )


PARAMETER_IMPACT = (
    ("tactic_progression_weight", "Multi-stage incidents rank higher"),
    ("sensor_corroboration_weight", "Cross-sensor incidents rank higher"),
    ("completion_weight", "Exfiltration/Impact incidents rank higher"),
    ("false_positive_dampening", "High-FP rules contribute less"),
    ("duplicate_volume_weight", "Repeated detections matter more"),
    ("asset_context_weight", "Business asset value matters more"),
    ("identity_context_weight", "Privileged accounts matter more"),
    ("normalization_scale", "Scores rise more slowly toward 100"),
    ("fidelity_cap", "More detection evidence can accumulate before saturation"),
)
