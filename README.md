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

`streamlit run app.py` opens three workspaces over the same cached snapshot: **Security overview**, **Incident queue**, and **Detection intelligence**. The snapshot is labeled as historical / demo data (offline JSONL + CMDB/IAM), not a live SIEM feed. Overview is the executive landing page: open exposure, P0–P1 cases, affected assets, ownership, and response progress. The queue is a dense operational board — compact horizontal strips (priority · risk · ZeroNoise rank/Δ · incident · asset · ATT&CK stage · age · sensors · alert compression · status · owner) so analysts can scan 10–15 incidents without scrolling. Ranking mode toggles ZeroNoise vs Legacy SIEM on the same row design. Clicking a strip opens the investigation workspace; **← Back to queue** keeps filters. **Export** on the case downloads a decision-first Markdown or PDF incident report (brief first, formulas and raw detections in the appendix). Detection intelligence compares AI vs legacy ranks, explains significant moves, and reports `N% fewer items to review` when 300 raw alerts become 111 incidents. That figure is volume compression, not measured time saved or fatigue. Case state (owner, status, notes, checklist) is session-local; session activity is recorded only after a change is saved. Share a case with `?case=<incident_id>`. **Presentation mode** masks identifiers for screen sharing and is not access control. Reset lives under **Demo / admin**.

For live demo contrast against a basic open-source-style SIEM queue (severity × volume, no context), run:

```bash
python legacy_siem/app.py
```

Then open `http://127.0.0.1:8502/` beside ZeroNoise. Same `data/sample_alerts.jsonl` feed; the noisy WAF sandbox group ranks first.


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

The coefficients above are the **ZN-RISK-1.0** defaults. They live in `config/risk-model.yaml`, not in `risk_scorer.py`. `normalization_scale = 45` was chosen on the seed-42 dataset so multi-stage incidents saturate into the 70–90 band and isolated noise stays in the single digits. RawRisk is not shown on the analyst card. Scores are not assigned per `scenario_id`.

Attribution is **counterfactual ablation**, not an independent split of B, K, and C. Each factor is replaced with its baseline (B → 2.0, K → 1.0, C → 1.0, FPR → 0) and the score drop (or FP-suppression lift) is renormalized to integer percents that sum to 100.

| Factor | What it measures |
| --- | --- |
| Alert Fidelity **B** | Severity × confidence × (1 − 0.7×FPR), unique (rule, tactic) only, log volume |
| Kill-chain **K** | Distinct ATT&CK tactics, distinct sensors, Exfiltration/Impact completion |
| Blast radius **C** | Highest-risk asset (0.65) and highest-risk identity (0.35) |
| FP/Noise suppression | How much the score rises if every alert is recomputed with FPR = 0 |

Volume has strongly diminishing returns. 120 identical Critical alerts are not 120 attack stages.

Given the same dataset and the same risk-model file, ranking, scores, and attribution percentages are identical every run.

## Risk Model Configuration

**ZN-RISK-1.0 uses expert-defined prototype parameters. They have not yet been calibrated against production SOC outcomes.**

| Concern | Where it lives |
| --- | --- |
| Risk model **logic** (how B, K, and C combine) | `engine/risk_scorer.py` |
| Risk model **parameters** (how strongly each factor counts) | `config/risk-model.yaml` + `engine/risk_config.py` |

Changing `0.35` to `0.42` requires only a new configuration file. Changing the shape of `K = …` requires a new risk-model implementation/version.

Default file: `config/risk-model.yaml`. Load once at pipeline start with `load_risk_config()`. If the file is missing, ZeroNoise uses built-in `RiskParameters()` defaults and logs that fact. If the file exists but is invalid, load fails fast.

Create a new version by copying the file:

```text
config/risk-model.yaml
config/risk-model-v1.1.yaml
config/risk-model-experimental.yaml
```

Then pass that path into `load_risk_config()` / `run_pipeline(risk_config=...)`. The scorer accepts any valid `RiskParameters` object.

Every scored incident stores `risk_model_version` and a SHA-256 `risk_config_hash` of the canonical parameter set (calibration metrics are excluded). The export appendix prints both so a historical score can be reproduced even if the active file later changes.

Validation rejects: context weights that do not sum to 1.0, priority bands that are not strictly descending (`P0 > P1 > P2 > P3`), a zero/negative normalization scale, FP dampening outside `[0, 1]`, unknown keys, negative additive multipliers, and a sensor weight that exceeds the tactic-progression weight.

### Parameter meaning

| Parameter | What it controls |
| --- | --- |
| `tactic_progression_weight` | How much each extra ATT&CK stage raises K. Higher: multi-stage attacks rise faster. Lower: progression matters less. |
| `sensor_corroboration_weight` | How much each extra sensor raises K. Higher: cross-sensor incidents rise faster. |
| `completion_weight` | Bonus on K when Exfiltration or Impact is observed. |
| `false_positive_dampening` | How strongly a high FPR reduces per-alert fidelity. Higher: noisy rules contribute less. |
| `duplicate_volume_weight` | Log-volume coefficient (`1 + w × log1p(n − 1)`). Higher: repeated detections matter more. |
| `asset_context_weight` | Share of C from the highest-risk asset. Must sum with identity share to 1.0. |
| `identity_context_weight` | Share of C from the highest-risk identity. |
| `normalization_scale` | Saturating-map scale. Higher: scores rise more slowly toward 100. |
| `fidelity_cap` | Maximum accumulated B. Higher: more distinct detections can add before saturation. |
| `severity_weights` | Vendor Low / Medium / High / Critical → fidelity points. |
| `environment_weights` | sandbox / dev / staging / prod asset multipliers. |
| `data_sensitivity_weights` | public → crown-jewel / PII / PCI asset multipliers. |
| `privilege_weights` | standard user → tier-0 admin identity multipliers. |
| `business_criticality_weights` | Explicit CMDB 1–5 mapping (not a generated linear formula). |
| `p0_threshold` … `p3_threshold` | Inclusive score bands. Below P3 is P4. |
| `correlation_window_hours` | Maximum time gap for joining related alerts. |
| `dedup_window_minutes` | Rolling window that collapses duplicate detections. |

### Parameter impact

| Parameter | Increasing it causes |
| --- | --- |
| `tactic_progression_weight` | Multi-stage incidents rank higher |
| `sensor_corroboration_weight` | Cross-sensor incidents rank higher |
| `completion_weight` | Exfiltration/Impact incidents rank higher |
| `false_positive_dampening` | High-FP rules contribute less |
| `duplicate_volume_weight` | Repeated detections matter more |
| `asset_context_weight` | Business asset value matters more |
| `identity_context_weight` | Privileged accounts matter more |
| `normalization_scale` | Scores rise more slowly toward 100 |
| `fidelity_cap` | More detection evidence can accumulate before saturation |

### Provenance and reproducibility

`calibration.source` is `expert_defined` until a measured calibration exists. Do not invent NDCG or recall figures. The Demo / admin panel shows the active version, config hash, and coefficients, labeled as prototype parameters.

Every score stores `risk_model_version` and `risk_config_hash` (SHA-256 of the canonical JSON, excluding `calibration`). Historical incidents keep the hash they were scored with even if the active file later changes. Future calibration should produce a new YAML file and pass that `RiskParameters` object into the same scorer.

## Explainability

Every card answers six questions from incident facts only:

| Question | Field |
| --- | --- |
| What happened? | `executive_summary` |
| Why is it ranked here? | `why_prioritized` (ablation percents) |
| Why this ranks high | `contrastive_explanation` |
| Why this may be a real attack | `why_not_false_positive` |
| How did the attack evolve? | `attack_timeline` |
| What should the SOC do now? | `recommended_actions` |

Each timeline line is chronological and cites a real alert ID, for example `09:12  [ALRT-A-001] Initial Access — Anomalous VPN login for usr_svc_deploy on prd-app-02`. The explainer never invents alert IDs, hosts, users, techniques, IPs, or timestamps. False-positive wording stays uncertain (`unlikely to be a single false alert`), never `definitely malicious`.

Opening a case expands the analyst file:

Executive Summary · Why this ranks high · Affected Assets · Affected Identities · MITRE Tactics · MITRE Techniques · Attack Timeline · Why these alerts are connected · Raw Alert References · Recommended Actions

Recommended actions are generated from the incident's own users, hosts, sensors, and tactics — for example `Disable usr_admin_root and rotate its credentials` or `Isolate prd-app-02 from the network` — never “involved hosts” when an entity ID is known. User-facing explanations must score at least 70 on the Flesch Reading Ease scale.

## LLM contract

Offline by default. Optional providers are selected by environment variables:

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=...

# or
LLM_PROVIDER=gemini
GEMINI_API_KEY=...
```

The model receives only a structured incident payload (IDs, timestamps, entities, CMDB/IAM, ATT&CK, edges, score, attribution, naive rank, AI rank). It must not invent facts, change `risk_score` / ranks, or rewrite attribution percents. Every returned timeline step is checked for a real `[alert_id]`. Each prose field must also pass Flesch Reading Ease >= 70 after identifiers are ignored for scoring. Failed or hard-to-read LLM text falls back to the deterministic card. If no key is set or the call fails, that same Python card is used unchanged.

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
