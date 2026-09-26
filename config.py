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

# Dedup: same rule + same primary entities inside this window collapse.
DEDUP_WINDOW_MINUTES = 15

# Correlation: shared resolved entities within this window form an incident.
CORRELATION_WINDOW_MINUTES = 120

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

# Additive risk weights. Must sum to 1.0 so attribution is a partition
# of the pre-noise score.
RISK_WEIGHTS: dict[str, float] = {
    "business_impact": 0.28,
    "identity_privilege": 0.14,
    "attack_progression": 0.26,
    "signal_quality": 0.16,
    "blast_radius": 0.10,
    "severity_residual": 0.06,
}

# Maximum fraction of the raw weighted score that bursty, high-FPR
# incidents can lose. Noise never increases rank.
NOISE_DISCOUNT_CAP = 0.45

# Optional explanation-only LLM. Disabled by default; the engine is
# fully offline. When enabled the model may rewrite prose but cannot
# change scores, ranking, entities, alert IDs, or attribution.
LLM_ENABLED = False
LLM_MODEL = "gpt-4o-mini"
LLM_BASE_URL = ""  # empty = official OpenAI-compatible default

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

ENV_SCORE: dict[str, float] = {
    "prod": 1.00,
    "staging": 0.45,
    "dev": 0.25,
    "sandbox": 0.08,
}

SENSITIVITY_SCORE: dict[str, float] = {
    "crown_jewel_pii_pci": 1.00,
    "confidential": 0.70,
    "internal": 0.35,
    "public": 0.10,
}

# Unknown CMDB/IAM context is not treated as crown-jewel or as zero.
NEUTRAL_IMPACT = 0.35
NEUTRAL_PRIVILEGE = 0.35

PRIVILEGE_SCORE: dict[str, float] = {
    "tier_0_domain_admin": 1.00,
    "tier_1_cloud_admin": 0.85,
    "service_account": 0.70,
    "standard_user": 0.35,
}

LATE_STAGE_SCORE: dict[str, float] = {
    "Impact": 1.00,
    "Exfiltration": 1.00,
    "Collection": 0.75,
    "Lateral Movement": 0.70,
    "Credential Access": 0.55,
    "Privilege Escalation": 0.50,
    "Persistence": 0.40,
    "Discovery": 0.25,
    "Execution": 0.20,
    "Initial Access": 0.15,
}
