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

# Correlation: two alerts may join only if they are within this window
# and share a meaningful relationship.
CORRELATION_WINDOW_MINUTES = 4 * 60

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
SEVERITY_WEIGHTS: dict[str, int] = {
    "Low": 2,
    "Medium": 5,
    "High": 10,
    "Critical": 15,
}

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

# Base threat fidelity B. Repeated copies of the same (rule, tactic)
# do not add another term; volume only enters through log1p.
FIDELITY_CAP = 35.0
FIDELITY_FPR_COEFF = 0.70
FIDELITY_VOLUME_COEFF = 0.10

# Kill-chain progression K.
PROGRESSION_BASE = 1.0
PROGRESSION_TACTIC_COEFF = 0.35
PROGRESSION_SENSOR_COEFF = 0.20
PROGRESSION_COMPLETION_BONUS = 0.50
COMPLETION_TACTICS: frozenset[str] = frozenset({"Exfiltration", "Impact"})

# Asset impact tables. Highest-risk touched asset wins.
ENVIRONMENT_WEIGHT: dict[str, float] = {
    "sandbox": 0.4,
    "dev": 0.7,
    "staging": 1.0,
    "prod": 1.4,
}
DATA_WEIGHT: dict[str, float] = {
    "public": 0.5,
    "internal": 0.9,
    "confidential": 1.4,
    "crown_jewel_pii_pci": 2.0,
}
CRITICALITY_WEIGHT: dict[int, float] = {
    1: 0.4,
    2: 0.8,
    3: 1.2,
    4: 1.6,
    5: 2.0,
}
ASSET_ENV_BLEND = 0.35
ASSET_DATA_BLEND = 0.35
ASSET_CRIT_BLEND = 0.30
ASSET_SCORE_MIN = 0.4
ASSET_SCORE_MAX = 2.0

# Identity impact. Highest-risk involved identity wins (P_priv).
PRIVILEGE_WEIGHT: dict[str, float] = {
    "standard_user": 0.5,
    "service_account": 1.0,
    "tier_1_cloud_admin": 1.4,
    "tier_0_domain_admin": 1.8,
}

# Unknown CMDB/IAM context is not treated as crown-jewel or as zero.
NEUTRAL_IMPACT = 0.90
NEUTRAL_PRIVILEGE = 0.70
# No observed identity: floor so the B×K×I product does not collapse to 0.
UNOBSERVED_PRIVILEGE = 0.50

# Maximum fraction of the pre-noise product that bursty, high-FPR
# incidents can lose. Noise never increases rank.
NOISE_DISCOUNT_CAP = 0.45

# Aliases used by the explainer when picking the highest-sensitivity asset.
ENV_SCORE = ENVIRONMENT_WEIGHT
SENSITIVITY_SCORE = DATA_WEIGHT
PRIVILEGE_SCORE = PRIVILEGE_WEIGHT

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

