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
                                         Streamlit SOC workspaces
```

`scenario_id` is written on synthetic alerts so the demo can be graded. The correlator and risk scorer never read it.

## Repository

```text
data/generate_synthetic_data.py   Seeded CMDB, IAM, and alert stream
engine/schemas.py                 Pydantic v2 models
engine/normalizer.py              Vendor-field mapping, CMDB/IAM enrich, dedup
engine/correlator.py              Entity + time union-find (no scenario_id)
engine/risk_scorer.py             B × K × C risk + ablation attribution
engine/explainer.py               Deterministic cards; optional OpenAI/Gemini prose
engine/pipeline.py                load→…→score→rank→explain
engine/presentation.py            Badges, rank delta, correlation sentences
console/                          Security overview, incident queue, detection intelligence
app.py                            Streamlit navigation entrypoint
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

`streamlit run app.py` opens three workspaces over the same cached snapshot: **Security overview**, **Incident queue**, and **Detection intelligence**. The snapshot is labeled as historical / demo data (offline JSONL + CMDB/IAM), not a live SIEM feed. Overview is the executive landing page: open exposure, P0–P1 cases, affected assets, ownership, and response progress. The queue is the analyst workbench — two high-priority cards, then a working table (Priority · Incident · Affected service/asset · Status · Owner · Age · Risk). Opening a case or selecting a row replaces the queue with a decision brief and investigation tabs; **← Back to queue** keeps filters and selection. Detection intelligence compares AI vs legacy ranks, explains significant moves, and reports `N% fewer items to review` when 300 raw alerts become 111 incidents. That figure is volume compression, not measured time saved or fatigue. Case state (owner, status, notes, checklist) is session-local. Reset lives under **Demo / admin**.

## Risk formula

The score is computed on **deduplicated, correlated incidents**, never on raw SIEM rows:

```text
fidelity_a = severity_weight × confidence × (1 - 0.7 × FPR)
             × (1 + 0.10 × log1p(event_count - 1))

B = min(Σ fidelity_a over unique (rule_name, mitre_tactic), 35)

K = 1 + 0.35×max(0, m-1) + 0.20×max(0, s-1)
    + 0.50×int(Exfiltration ∈ tactics or Impact ∈ tactics)

asset_risk = 0.35×env + 0.35×data + 0.30×criticality   (≈ 0.4–2.0)
P_priv     = highest involved privilege weight
C          = 0.65×asset_risk + 0.35×P_priv     (configurable)

RawRisk    = B × K × C
risk_score = 100 × (1 − exp(−RawRisk / 45))
```

`RISK_SCALE = 45` was chosen on the seed-42 dataset so multi-stage incidents saturate into the 70–90 band and isolated noise stays in the single digits. RawRisk is not shown on the analyst card. Scores are not assigned per `scenario_id`.

Attribution is **counterfactual ablation**, not an independent split of B, K, and C. Each factor is replaced with its baseline (B → 2.0, K → 1.0, C → 1.0, FPR → 0) and the score drop (or FP-suppression lift) is renormalized to integer percents that sum to 100.

| Factor | What it measures |
| --- | --- |
| Alert Fidelity **B** | Severity × confidence × (1 − 0.7×FPR), unique (rule, tactic) only, log volume |
| Kill-chain **K** | Distinct ATT&CK tactics, distinct sensors, Exfiltration/Impact completion |
| Blast radius **C** | Highest-risk asset (0.65) and highest-risk identity (0.35) |
| FP/Noise suppression | How much the score rises if every alert is recomputed with FPR = 0 |

Volume has strongly diminishing returns. 120 identical Critical alerts are not 120 attack stages.

Given the same dataset and `config.py`, ranking, scores, and attribution percentages are identical every run.

## Explainability

Every card answers six questions from incident facts only:

| Question | Field |
| --- | --- |
| What happened? | `executive_summary` |
| Why is it ranked here? | `why_prioritized` (ablation percents) |
| Why does this incident rank higher? | `contrastive_explanation` |
| Why might this be real rather than noise? | `why_not_false_positive` |
| How did the attack evolve? | `attack_timeline` |
| What should the SOC do now? | `recommended_actions` |

Each timeline line is chronological and cites a real alert ID, for example `09:12  [ALRT-A-001] Initial Access — Anomalous VPN login for usr_svc_deploy on prd-app-02`. The explainer never invents alert IDs, hosts, users, techniques, IPs, or timestamps. False-positive wording stays uncertain (`unlikely to be isolated noise`), never `definitely malicious`.

Opening a case expands the analyst file:

Executive Summary · Risk Breakdown · Affected Assets · Affected Identities · MITRE Tactics · MITRE Techniques · Attack Timeline · Correlation Evidence · Raw Alert References · Recommended Actions

Recommended actions are generated from the incident's own users, hosts, sensors, and tactics — for example `Disable or rotate usr_admin_root credentials` or `Isolate prd-app-02 from the network` — never “involved hosts” when an entity ID is known.

## LLM contract

Offline by default. Optional providers are selected by environment variables:

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=...

# or
LLM_PROVIDER=gemini
GEMINI_API_KEY=...
```

The model receives only a structured incident payload (IDs, timestamps, entities, CMDB/IAM, ATT&CK, edges, score, attribution, naive rank, AI rank). It must not invent facts, change `risk_score` / ranks, or rewrite attribution percents. Every returned timeline step is checked for a real `[alert_id]`. If no key is set or the call fails, the deterministic Python card is used unchanged.

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
