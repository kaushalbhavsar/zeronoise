"""Deterministic configuration for the SOC triage engine.

Changing these values changes scoring and correlation. The LLM flag
must never be read by the normalizer, correlator, or risk scorer.
"""

from __future__ import annotations

from pathlib import Path

RANDOM_SEED = 42

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"

CMDB_PATH = DATA_DIR / "cmdb_assets.json"
IAM_PATH = DATA_DIR / "iam_users.json"
ALERTS_PATH = DATA_DIR / "sample_alerts.jsonl"

from engine.risk_config import ATTRIBUTION_FACTORS, default_risk_parameters

# Compatibility aliases. Tunable values live in config/risk-model.yaml.
_RP = default_risk_parameters()

# Dedup: same rule + same primary entities inside this window collapse.
DEDUP_WINDOW_MINUTES = int(_RP.dedup_window_minutes)

# Correlation: two alerts may join only if they are within this window
# and share a meaningful relationship.
CORRELATION_WINDOW_MINUTES = int(_RP.correlation_window_minutes())

# Connected components larger than this are inspected and possibly split.
MAX_COMPONENT_NODES = 25

# A source IP that fans out to this many distinct hosts is treated as a
# scanner and cannot weld those hosts into one compromise by IP alone.
SCANNER_FANOUT_HOSTS = 8

# Drop these edge strengths when splitting a mega-component.
STRONG_EDGE_THRESHOLD = 0.80

# Temporal split gap used after a mega-component survives strong-edge filtering.
TEMPORAL_SPLIT_GAP_MINUTES = 90

# Naive SIEM score: sum of these weights over every raw alert (no dedup).
SEVERITY_WEIGHTS: dict[str, float] = _RP.severity_table()

# Generic destinations that must never join otherwise-unrelated alerts.
GENERIC_IPS = frozenset(
    {
        "0.0.0.0",
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "255.255.255.255",
    }
)

# Tokens that mark high-frequency infrastructure. Joins that only share
# these hosts are low-confidence and get dropped from mega-components.
INFRA_HOST_TOKENS: tuple[str, ...] = (
    "dns",
    "proxy",
    "nat",
    "lb-",
    "-lb",
    "loadbal",
    "load-bal",
    "jump",
    "dhcp",
    "scanner",
    "nessus",
    "qualys",
    "vpn-gw",
    "firewall",
    "waf-vip",
)

# Scoring coefficients are defined in engine/risk_config.py and
# config/risk-model.yaml. These names remain for older imports.
FIDELITY_CAP = _RP.fidelity_cap
FIDELITY_FPR_COEFF = _RP.false_positive_dampening
FIDELITY_VOLUME_COEFF = _RP.duplicate_volume_weight
PROGRESSION_BASE = _RP.progression_base
PROGRESSION_TACTIC_COEFF = _RP.tactic_progression_weight
PROGRESSION_SENSOR_COEFF = _RP.sensor_corroboration_weight
PROGRESSION_COMPLETION_BONUS = _RP.completion_weight
COMPLETION_TACTICS: frozenset[str] = frozenset(_RP.completion_tactics)
ENVIRONMENT_WEIGHT: dict[str, float] = _RP.environment_table()
DATA_WEIGHT: dict[str, float] = _RP.data_table()
CRITICALITY_WEIGHT: dict[int, float] = _RP.criticality_table()
ASSET_ENV_BLEND = _RP.asset_environment_blend
ASSET_DATA_BLEND = _RP.asset_data_blend
ASSET_CRIT_BLEND = _RP.asset_criticality_blend
ASSET_SCORE_MIN = _RP.asset_score_min
ASSET_SCORE_MAX = _RP.asset_score_max
PRIVILEGE_WEIGHT: dict[str, float] = _RP.privilege_table()
BLAST_ASSET_WEIGHT = _RP.asset_context_weight
BLAST_IDENTITY_WEIGHT = _RP.identity_context_weight
NEUTRAL_IMPACT = _RP.neutral_impact
NEUTRAL_PRIVILEGE = _RP.neutral_privilege
UNOBSERVED_PRIVILEGE = _RP.unobserved_privilege
FIDELITY_BASELINE = _RP.fidelity_baseline
PROGRESSION_BASELINE = _RP.progression_baseline
BLAST_BASELINE = _RP.blast_baseline
RISK_SCALE = _RP.normalization_scale
ENV_SCORE = ENVIRONMENT_WEIGHT
SENSITIVITY_SCORE = DATA_WEIGHT
PRIVILEGE_SCORE = PRIVILEGE_WEIGHT

# Optional explanation-only LLM. The engine is fully offline unless a
# provider and API key are present in the environment.
#   LLM_PROVIDER=openai  OPENAI_API_KEY=...
#   LLM_PROVIDER=gemini  GEMINI_API_KEY=...
LLM_ENABLED = False
LLM_PROVIDER = ""
LLM_MODEL = "gpt-4o-mini"
LLM_GEMINI_MODEL = "gemini-2.0-flash"
LLM_BASE_URL = ""  # empty = official OpenAI-compatible default
LLM_TIMEOUT_SECONDS = 20

KILL_CHAIN: tuple[str, ...] = (
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
)

SEVERITY_RANK: dict[str, int] = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

