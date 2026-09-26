# ZeroNoise

AI-driven, risk-based SOC incident triage engine.

The prototype shows why a SOC should stop ranking work by vendor severity and raw alert volume. A noisy scanner can emit hundreds of Critical events against a sandbox. A real breach can emit a handful of Medium events that walk the kill chain on a crown-jewel system. Context, correlation, attack progression, and business impact have to outweigh volume.

The core is deterministic and works fully offline. An LLM, if you turn it on, may only rewrite prose.

## What it proves

On the seeded demo dataset (`RANDOM_SEED = 42`, ~300 alerts over 24 hours):

| Queue | Rank 1 | Rank 2 | Sandbox scanner (120 Critical) |
| --- | --- | --- | --- |
| Legacy SIEM (severity × volume) | Scanner on `dev-sandbox-04` (1800) | Ransomware staging | **#1** |
| Risk-based incidents | 6-stage Impact on `wrk-corp-14` (88.3) | Crown-jewel exfil via `usr_admin_root` (80.8) | **#3** (30.9) |

Those ranks come from `RawRisk = B × K × C`, not from `scenario_id`. The scanner is suppressed by a short kill chain, sandbox/public/crit-1 context, and FPR 0.85. The 4-Medium crown-jewel incident still outranks it; the 6-stage High ransomware chain has higher fidelity B, so it leads the risk queue.

Alert fatigue drops because hundreds of raw alerts collapse into a short incident queue, and the item at the top is the one that actually matters.

## Architecture

```text
synthetic JSONL ─┐
CMDB assets     ─┼─► normalizer / enrich ─► dedup ─► correlate
IAM identities  ─┘                                      │
                                                        ▼
                                              risk score + attribution
                                                        │
                                              deterministic explainer
                                                        │
                                         Streamlit SOC queue + contrast
```

`scenario_id` is written on synthetic alerts so the demo can be graded. The correlator and risk scorer never read it.

## Repository

```text
data/generate_synthetic_data.py   Seeded CMDB, IAM, and alert stream
engine/schemas.py                 Pydantic v2 models
engine/normalizer.py              Vendor-field mapping, CMDB/IAM enrich, dedup
engine/correlator.py              Entity + time union-find (no scenario_id)
engine/risk_scorer.py             B × K × I risk + traceable attribution
engine/explainer.py               Deterministic cards; optional LLM prose
engine/pipeline.py                End-to-end run + fatigue metrics
app.py                            Interactive SOC queue
tests/                            Dedup, correlation, scoring, acceptance
```

## Quick start

Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python data/generate_synthetic_data.py
python -m engine.pipeline
pytest -q
streamlit run app.py
```

`streamlit run app.py` opens the SOC console: a filterable incident queue, case ownership/status, and an investigation workbench (timeline, ATT&CK, risk drivers, containment, evidence). Queue order can be switched between risk and SIEM volume.

## Risk formula

The score is computed on **deduplicated, correlated incidents**, never on raw SIEM rows:

```text
fidelity_a = severity_weight × confidence × (1 - 0.7 × FPR)
             × (1 + 0.10 × log1p(event_count - 1))

B = min(Σ fidelity_a over unique (rule_name, mitre_tactic), 35)

K = 1 + 0.35×max(0, m-1) + 0.20×max(0, s-1)
    + 0.50×int(Exfiltration ∈ tactics or Impact ∈ tactics)

asset_score = 0.35×env + 0.35×data + 0.30×criticality   (≈ 0.4–2.0)
P_priv      = highest involved privilege weight
I           = asset_score × P_priv

risk = min(100, B × K × I × (1 - 0.45 × noise))
```

| Factor | What it measures |
| --- | --- |
| Threat fidelity **B** | Vendor severity × confidence × (1 − 0.7×FPR), unique (rule, tactic) only, log volume |
| Kill-chain **K** | Distinct ATT&CK tactics, distinct sensors, Exfiltration/Impact completion |
| Asset impact | Highest-risk touched asset (`sandbox` 0.4 … `prod` 1.4; `public` 0.5 … `crown_jewel_pii_pci` 2.0) |
| Identity **P_priv** | Highest-risk identity (`standard_user` 0.5 … `tier_0_domain_admin` 1.8) |
| Noise discount | cap 0.45; bursty, high-FPR, single-stage piles (scanners) |

Volume has strongly diminishing returns. 120 identical Critical alerts are not 120 attack stages.

Given the same dataset and `config.py`, ranking, scores, and attribution percentages are identical every run.

## LLM contract

Disabled by default (`LLM_ENABLED = False`). When enabled, the model may rewrite the executive summary, narrative, and containment text. It must not change risk scores, invent entities or alert IDs, alter ranking, add unsupported ATT&CK stages, or override attribution.

## Mandatory scenarios

| ID | Story | Alerts | Expected rank |
| --- | --- | --- | --- |
| A `quiet_crown_jewel` | VPN → PowerShell creds → SSH pivot → 2.4 GB exfil on `prd-billing-db-01` | 4 Medium / ~90 min | Risk **#2**, legacy buried |
| B `ransomware_staging` | Phish → exec → LSASS → discovery → SMB scan → shadow-copy delete on `wrk-corp-14` | 6 Medium/High | Risk **#1** |
| C `noisy_false_priority` | CVE-2024-21762 WAF/IDS flood on `dev-sandbox-04` | 120 Critical | Legacy **#1**, risk **#3** |
| Background | Failed logins, vuln scans, isolated malware, admin scripts, WAF probes, brute-force bursts | 170 | Must not weld into a giant incident |

The normalizer parses JSONL, canonicalizes timestamps and IPs, resolves host IP ↔ host ID, enriches from CMDB/IAM, and keeps going when a row is malformed or an asset/user is unknown (neutral context weights).

## Design constraints

- Dedup key: rule + user + host + src IP + dest IP inside a **rolling 15-minute** window. Survivors carry `event_count`, `original_alert_ids`, `first_seen`, `last_seen`.
- Correlation: NetworkX `MultiGraph`. Edges are `SHARED_HOST`, `SHARED_IDENTITY`, `SHARED_ATTACKER_IP`, `DESTINATION_PIVOT`, `HOST_IP_PIVOT`, `PROCESS_HASH`, each with `time_delta_minutes` and `correlation_strength`.
- Two alerts join only if they are within **4 hours** and have at least one meaningful relationship.
- DNS/proxy/NAT/LB/jump/DHCP/scanner infrastructure and high-fanout attacker IPs cannot weld unrelated hosts. Components over 25 nodes are split on strong edges, then time gaps.
- Volume has strongly diminishing returns (`1 + 0.10 × log1p(n − 1)`). 120 identical alerts are not 120 attack stages.
- Naive SIEM score: `Σ SEVERITY_WEIGHTS[raw_alert]` with Low=2, Medium=5, High=10, Critical=15. **No dedup.** `naive_siem_rank` is that descending order.

## Tests

```bash
pytest tests/test_deduplication.py tests/test_correlation.py tests/test_risk_scoring.py tests/test_acceptance.py -q
```

Acceptance checks the seed-42 ranking that the formula produces (B then A on risk, C on legacy), measurable fatigue reduction, isolated background noise, determinism, unused `scenario_id`, and that a malformed row does not fail the pipeline.
