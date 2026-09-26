"""Pydantic v2 schemas for alerts, context stores, incidents, and cards."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["Low", "Medium", "High", "Critical"]
SourceProduct = Literal["EDR", "IAM", "NDR", "WAF", "DLP", "SIEM"]
MitreTactic = Literal[
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]
Environment = Literal["prod", "staging", "dev", "sandbox"]
DataSensitivity = Literal[
    "crown_jewel_pii_pci",
    "confidential",
    "internal",
    "public",
]
PrivilegeTier = Literal[
    "tier_0_domain_admin",
    "tier_1_cloud_admin",
    "service_account",
    "standard_user",
]


class AlertEntities(BaseModel):
    user_id: str | None = None
    host_id: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    process_hash: str | None = None


class Asset(BaseModel):
    host_id: str
    hostname: str
    ip_address: str
    environment: Environment
    data_sensitivity: DataSensitivity
    business_criticality: int = Field(ge=1, le=5)


class Identity(BaseModel):
    user_id: str
    department: str
    privilege_tier: PrivilegeTier


class EnrichedAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    source_product: SourceProduct
    rule_name: str
    severity_raw: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)
    mitre_tactic: MitreTactic
    mitre_technique: str
    entities: AlertEntities
    event_count: int = 1
    scenario_id: str | None = None
    original_alert_id: str | None = None
    member_alert_ids: list[str] = Field(default_factory=list)
    asset: Asset | None = None
    dest_asset: Asset | None = None
    identity: Identity | None = None
    context_gaps: list[str] = Field(default_factory=list)


class RawAlert(BaseModel):
    """Vendor-shaped input that the normalizer maps into EnrichedAlert."""

    alert_id: str | None = None
    id: str | None = None
    timestamp: datetime | str | None = None
    time: datetime | str | None = None
    source_product: str | None = None
    product: str | None = None
    vendor: str | None = None
    rule_name: str | None = None
    signature: str | None = None
    severity_raw: str | int | float | None = None
    severity: str | int | float | None = None
    sev: str | int | float | None = None
    confidence: float | int | None = None
    false_positive_rate: float | int | None = None
    fp_rate: float | int | None = None
    mitre_tactic: str | None = None
    tactic: str | None = None
    mitre_technique: str | None = None
    technique: str | None = None
    entities: AlertEntities | dict | None = None
    user_id: str | None = None
    host_id: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    process_hash: str | None = None
    event_count: int = 1
    scenario_id: str | None = None


class RiskDriver(BaseModel):
    name: str
    score: float
    weight: float
    contribution: float
    contribution_pct: float
    evidence: list[str] = Field(default_factory=list)


class RiskBreakdown(BaseModel):
    risk_score: float
    raw_weighted_score: float
    noise_score: float
    noise_discount: float
    drivers: list[RiskDriver]
    formula: str


class CandidateIncident(BaseModel):
    incident_id: str
    alert_ids: list[str]
    alerts: list[EnrichedAlert]
    first_seen: datetime
    last_seen: datetime
    unique_tactics: list[str]
    unique_techniques: list[str]
    unique_products: list[str]
    unique_users: list[str]
    unique_hosts: list[str]
    total_event_count: int
    max_severity: Severity


class ScoredIncident(BaseModel):
    incident: CandidateIncident
    risk: RiskBreakdown
    legacy_score: float
    title: str


class IncidentCard(BaseModel):
    incident_id: str
    title: str
    risk_score: float
    legacy_score: float
    risk_rank: int | None = None
    legacy_rank: int | None = None
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    raw_event_count: int
    max_severity: Severity
    tactics: list[str]
    products: list[str]
    users: list[str]
    hosts: list[str]
    assets: list[Asset]
    identities: list[Identity]
    executive_summary: str
    narrative: str
    containment: list[str]
    contrastive: str | None = None
    risk: RiskBreakdown
    alert_ids: list[str]
    llm_enhanced: bool = False
    explanation_source: Literal["deterministic", "llm"] = "deterministic"


class PipelineMetrics(BaseModel):
    raw_alert_count: int
    enriched_alert_count: int
    deduplicated_alert_count: int
    incident_count: int
    alerts_collapsed_by_dedup: int
    fatigue_reduction_pct: float
    volume_compression_pct: float
    quiet_crown_jewel_risk_rank: int | None = None
    quiet_crown_jewel_legacy_rank: int | None = None
    ransomware_staging_risk_rank: int | None = None
    ransomware_staging_legacy_rank: int | None = None
    noisy_false_priority_risk_rank: int | None = None
    noisy_false_priority_legacy_rank: int | None = None
    dropped_alert_count: int = 0
    missing_context_alert_count: int = 0
    ranking_inverted: bool = False


class PipelineResult(BaseModel):
    alerts_raw: int
    normalize_errors: list[str] = Field(default_factory=list)
    alerts_deduped: list[EnrichedAlert]
    incidents: list[ScoredIncident]
    cards: list[IncidentCard]
    risk_ranked: list[ScoredIncident]
    legacy_ranked: list[ScoredIncident]
    metrics: PipelineMetrics
