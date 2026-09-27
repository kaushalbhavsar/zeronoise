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

Those ranks come from `RawRisk = B × K × C` under **ZN-RISK-1.0**, not from `scenario_id`. The scanner is suppressed by a short kill chain, sandbox/public/crit-1 context, and FPR 0.85. The 4-Medium crown-jewel incident still outranks it; the 6-stage High ransomware chain has higher fidelity B, so it leads the risk queue.

Alert fatigue drops because hundreds of raw alerts collapse into a short incident queue, and the item at the top is the one that actually matters.

## Architecture

```text
synthetic JSONL ─┐
CMDB assets     ─┼─► normalizer / enrich ─► dedup ─► correlate
IAM identities  ─┘                                      │
                                                        ▼
                                         load risk-model.yaml once
                                                        │
                                              risk score + attribution
                                                        │
                                              deterministic explainer
                                                        │
                                         Streamlit SOC workspaces
```

`scenario_id` is written on synthetic alerts so the demo can be graded. The correlator and risk scorer never read it.

Risk **logic** (how B, K, and C combine) lives in `engine/risk_scorer.py`. Risk **parameters** (how strongly each factor counts) live in `config/risk-model.yaml`. Changing `0.35` to `0.42` is a new configuration file. Changing the shape of `K = …` is a new risk-model implementation.

## Repository

```text
config/risk-model.yaml            ZN-RISK-1.0 expert-defined coefficients
engine/risk_config.py             Frozen Pydantic model, loader, fingerprint
engine/risk_scorer.py             B × K × C logic; consumes RiskParameters
engine/schemas.py                 Pydantic v2 models (includes model version + hash)
engine/normalizer.py              Vendor-field mapping, CMDB/IAM enrich, dedup
engine/correlator.py              Entity + time graph (no scenario_id)
engine/explainer.py               Deterministic cards; optional OpenAI/Gemini prose
engine/incident_report.py         Decision-first Markdown / PDF export
engine/pipeline.py                load→…→score→rank→explain (config loaded once)
engine/presentation.py            Badges, rank delta, correlation sentences
data/generate_synthetic_data.py   Seeded CMDB, IAM, and alert stream
console/                          Security overview, incident queue, detection intelligence
legacy_siem/                      Severity × volume contrast queue
app.py                            Streamlit navigation entrypoint
tests/                            Dedup, correlation, scoring, config, acceptance
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

`streamlit run app.py` opens three workspaces over the same cached snapshot: **Security overview**, **Incident queue**, and **Detection intelligence**. The snapshot is labeled as historical / demo data (offline JSONL + CMDB/IAM), not a live SIEM feed. Overview is the executive landing page: open exposure, P0–P1 cases, affected assets, ownership, and response progress. The queue is a dense operational board — compact horizontal strips (priority · risk · ZeroNoise rank/Δ · incident · asset · ATT&CK stage · age · sensors · alert compression · status · owner) so analysts can scan 10–15 incidents without scrolling. Ranking mode toggles ZeroNoise vs Legacy SIEM on the same row design. Clicking a strip opens the investigation workspace; **← Back to queue** keeps filters. **Export** on the case downloads a decision-first Markdown or PDF incident report (brief first, formulas and raw detections in the appendix). Detection intelligence compares AI vs legacy ranks, explains significant moves, and reports `N% fewer items to review` when 300 raw alerts become 111 incidents. That figure is volume compression, not measured time saved or fatigue. Case state (owner, status, notes, checklist) is session-local; session activity is recorded only after a change is saved. Share a case with `?case=<incident_id>`. **Presentation mode** masks identifiers for screen sharing and is not access control. Reset and the active risk-model table live under **Demo / admin**.

For live demo contrast against a basic open-source-style SIEM queue (severity × volume, no context), run:

```bash
python legacy_siem/app.py
```

Then open `http://127.0.0.1:8502/` beside ZeroNoise. Same `data/sample_alerts.jsonl` feed; the noisy WAF sandbox group ranks first.

## Risk formula

The score is computed on **deduplicated, correlated incidents**, never on raw SIEM rows. Coefficients come from the active `RiskParameters` object (default file: `config/risk-model.yaml`):

```text
fidelity_a = severity_weight
           × confidence
           × (1 − false_positive_dampening × FPR)
           × (1 + duplicate_volume_weight × log1p(event_count − 1))

B = min(Σ fidelity_a over unique (rule_name, mitre_tactic), fidelity_cap)

K = progression_base
  + tactic_progression_weight × max(0, m − 1)
  + sensor_corroboration_weight × max(0, s − 1)
  + completion_weight × completion_flag

asset_risk = env_blend×env + data_blend×data + crit_blend×criticality
             clipped to [asset_score_min, asset_score_max]
P_priv     = highest involved privilege weight
C          = asset_context_weight × asset_risk
           + identity_context_weight × P_priv

RawRisk    = B × K × C
risk_score = 100 × (1 − exp(−RawRisk / normalization_scale))
```

`completion_flag` is 1 when Exfiltration or Impact is observed. ZN-RISK-1.0 uses `log1p(n − 1)` for volume, not `ln(n)`.

ZN-RISK-1.0 defaults (also the built-in `RiskParameters()` fallback):

| Parameter | Default |
| --- | --- |
| `false_positive_dampening` | 0.70 |
| `duplicate_volume_weight` | 0.10 |
| `fidelity_cap` | 35 |
| `tactic_progression_weight` | 0.35 |
| `sensor_corroboration_weight` | 0.20 |
| `completion_weight` | 0.50 |
| `asset_context_weight` | 0.65 |
| `identity_context_weight` | 0.35 |
| `normalization_scale` | 45 |
| `p0` / `p1` / `p2` / `p3` thresholds | 85 / 70 / 50 / 30 |

`normalization_scale = 45` was chosen on the seed-42 dataset so multi-stage incidents saturate into the 70–90 band and isolated noise stays in the single digits. RawRisk is not shown on the analyst card. Scores are not assigned per `scenario_id`.

Attribution is **counterfactual ablation**, not an independent split of B, K, and C. Each factor is replaced with its baseline (B → `fidelity_baseline`, K → `progression_baseline`, C → `blast_baseline`, FPR → 0) and the score drop (or FP-suppression lift) is renormalized to integer percents that sum to 100.

| Factor | What it measures |
| --- | --- |
| Alert Fidelity **B** | Severity × confidence × FP dampening, unique (rule, tactic) only, log volume |
| Kill-chain **K** | Distinct ATT&CK tactics, distinct sensors, Exfiltration/Impact completion |
| Blast radius **C** | Highest-risk asset and highest-risk identity |
| FP/Noise suppression | How much the score rises if every alert is recomputed with FPR = 0 |

Volume has strongly diminishing returns. 120 identical Critical alerts are not 120 attack stages.

Given the same dataset and the same risk-model file, ranking, scores, attribution percentages, and the configuration hash are identical every run.

## Risk Model Configuration

**ZN-RISK-1.0 uses expert-defined prototype parameters. They have not yet been calibrated against production SOC outcomes. They are not machine-learned.**

| Concern | Where it lives |
| --- | --- |
| Risk model **logic** (how B, K, and C combine) | `engine/risk_scorer.py` |
| Risk model **parameters** (how strongly each factor counts) | `config/risk-model.yaml` + `engine/risk_config.py` |

### Loading

`run_pipeline()` calls `load_risk_config()` **once** at the start of a run and passes the same frozen `RiskParameters` into every `score_incident` call. YAML is not re-parsed per incident.

| Situation | Behavior |
| --- | --- |
| `config/risk-model.yaml` exists and is valid | Load, validate, log version + hash, score with that object |
| File is missing | Use built-in `RiskParameters()` (ZN-RISK-1.0 defaults) and log that an external file was not loaded |
| File exists but is invalid | Fail fast with a validation error. No silent fallback |

```python
from engine.risk_config import load_risk_config
from engine.pipeline import run_pipeline

cfg = load_risk_config("config/risk-model.yaml")
result = run_pipeline(risk_config=cfg)
```

Startup logs look like:

```text
ZeroNoise Risk Engine initialized
Model: ZN-RISK-1.0
Config: config/risk-model.yaml
Config hash: 145d80b4415e
Calibration source: expert_defined
```

The risk configuration contains no API keys or credentials.

### Creating a new model version

Copy the file; do not edit scoring code to change a weight.

```text
config/risk-model.yaml
config/risk-model-v1.1.yaml
config/risk-model-experimental.yaml
```

Change `model_version` (for example `ZN-RISK-1.1`) and the coefficients you want to try. Then:

```python
cfg = load_risk_config("config/risk-model-v1.1.yaml")
run_pipeline(risk_config=cfg)
```

The scorer accepts any valid `RiskParameters` object. Future calibration should only need to produce a new file.

### Validation

`RiskParameters` is frozen (`ConfigDict(frozen=True)`) and rejects:

- `asset_context_weight + identity_context_weight` not equal to 1.0 (± 1e-6)
- asset environment / data / criticality blends that do not sum to 1.0
- priority bands that are not strictly descending (`P0 > P1 > P2 > P3`)
- `sensor_corroboration_weight > tactic_progression_weight` (progression must not matter less than adding a sensor)
- `normalization_scale` or `fidelity_cap` ≤ 0
- `false_positive_dampening` outside `[0, 1]`
- negative additive multipliers
- unknown keys

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

### Fingerprint, provenance, and reproducibility

Every scored incident stores:

- `risk_model_name` — for example `ZeroNoise Risk Model`
- `risk_model_version` — for example `ZN-RISK-1.0`
- `risk_config_hash` — SHA-256 of the canonical JSON parameter set

The hash excludes `calibration` (provenance only). Historical incidents keep the version and hash they were scored with even if the active file later changes. The export technical appendix prints:

```text
Risk model: ZN-RISK-1.0
Configuration hash: 145d80b4415e
Normalization scale: 45
Fidelity cap: 35
```

`calibration.source` is `expert_defined` until a measured calibration exists. Optional fields (`ndcg_at_5`, `critical_recall_at_10`, …) stay `null` unless they have been measured. Do not invent those figures.

The Demo / admin panel shows the active version, short hash, and coefficients, labeled as prototype parameters.

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

- Dedup key: rule + user + host + src IP + dest IP inside the configured rolling window (`dedup_window_minutes`, default **15**). Survivors carry `event_count`, `original_alert_ids`, `first_seen`, `last_seen`.
- Correlation: NetworkX `MultiGraph`. Edges are `SHARED_HOST`, `SHARED_IDENTITY`, `SHARED_ATTACKER_IP`, `DESTINATION_PIVOT`, `HOST_IP_PIVOT`, `PROCESS_HASH`, each with `time_delta_minutes` and `correlation_strength`.
- Two alerts join only if they are within the configured correlation window (`correlation_window_hours`, default **4**) and have at least one meaningful relationship.
- DNS/proxy/NAT/LB/jump/DHCP/scanner infrastructure and high-fanout attacker IPs cannot weld unrelated hosts. Components over 25 nodes are split on strong edges, then time gaps.
- Volume has strongly diminishing returns (`1 + duplicate_volume_weight × log1p(n − 1)`). 120 identical alerts are not 120 attack stages.
- Naive SIEM score: `Σ severity_weights[raw_alert]` with ZN-RISK-1.0 Low=2, Medium=5, High=10, Critical=15. **No dedup.** `naive_siem_rank` is that descending order.

## Tests

```bash
pytest -q
```

Or the core engine subset:

```bash
pytest tests/test_deduplication.py tests/test_correlation.py tests/test_risk_scoring.py tests/test_risk_config.py tests/test_acceptance.py -q
```

Acceptance checks the seed-42 ranking that ZN-RISK-1.0 produces (B then A on risk, C on legacy), measurable fatigue reduction, isolated background noise, determinism, unused `scenario_id`, and that a malformed row does not fail the pipeline. Config tests check default values, YAML fingerprint equality, invalid weight/threshold rejection, score reproducibility, version + hash on every incident, and that changing `completion_weight` moves only Exfiltration/Impact cases.

## Future work

### Live SIEM feed

ZeroNoise does not have a live SIEM connector. It is a **batch engine**: you hand it a window of alerts plus CMDB and IAM, and it returns a ranked incident snapshot. A live feed is future work: a thin adapter in front of `run_pipeline()`, not a change to scoring logic.

`run_pipeline()` already accepts in-memory rows. A connector does not have to write JSONL first.

```python
from engine.pipeline import run_pipeline
from engine.risk_config import load_risk_config

result = run_pipeline(
    alerts=mapped_alerts,          # list[dict] from the SIEM
    assets=cmdb_rows,              # list[dict] from the CMDB
    identities=iam_rows,           # list[dict] from IAM
    risk_config=load_risk_config(),
)
```

The Streamlit console today only reads `data/sample_alerts.jsonl` + `data/cmdb_assets.json` + `data/iam_users.json` and caches one snapshot. It is labeled “not a live SIEM feed” on purpose. A live deployment should call the engine on a timer and serve `result.risk_ranked`. If Streamlit stays in the path, replace the file load in `console/state.py` and invalidate `@st.cache_data`.

#### Alert contract

Map each SIEM event to the fields the normalizer already accepts:

| Feed field | ZeroNoise field | Notes |
| --- | --- | --- |
| Alert ID | `id` | Unique. Duplicates collapse on rule + user + host + IPs. |
| Time | `time` | ISO-8601. Correlation uses `correlation_window_hours` (default 4). |
| Product | `vendor` | Aliases exist: CrowdStrike→EDR, Okta→IAM, Splunk/QRadar/Suricata→SIEM. |
| Rule | `signature` | Used as `rule_name`. |
| Severity | `sev` | Low / Medium / High / Critical (or 1–5). |
| ATT&CK tactic | `tactic` | Required. Unknown tactics drop that row; the batch continues. |
| ATT&CK technique | `technique` | Required, e.g. `T1003.001`. |
| User | `user_id` | Must match IAM `user_id` for privilege scoring. |
| Host | `host_id` | Must match CMDB `host_id` / hostname / IP. |
| IPs | `src_ip`, `dest_ip` | Used for correlation and CMDB IP lookup. |
| Confidence | `confidence` | 0–1. Missing → 0.5. |
| Rule FPR | `fp_rate` | 0–1. Missing → 0.35. This is the main noise lever. |

Do **not** send `scenario_id` on production events. That field is only for grading the demo. The scorer never reads it. Unknown users and hosts are kept and scored with **neutral** impact/privilege.

#### Context stores

Risk ranking is wrong without current CMDB and IAM:

```json
{"host_id": "prd-billing-db-01", "hostname": "...", "ip_address": "10.20.4.10",
 "environment": "prod", "data_sensitivity": "crown_jewel_pii_pci",
 "business_criticality": 5}
```

```json
{"user_id": "jmartinez", "department": "Finance", "privilege_tier": "standard_user"}
```

`environment` must be `prod` / `staging` / `dev` / `sandbox`.  
`data_sensitivity` must be `public` / `internal` / `confidential` / `crown_jewel_pii_pci`.  
`privilege_tier` must be `standard_user` / `service_account` / `tier_1_cloud_admin` / `tier_0_domain_admin`.

Refresh these on the same cadence as the alert window.

#### Suggested live loop

ZeroNoise re-scores the **whole window** each run. It is not incremental.

1. Export or subscribe to SIEM alerts (saved search, watcher, webhook, Kafka, …).
2. Map each event to the contract above.
3. Keep a lookback of at least `correlation_window_hours` (default 4) plus slack.
4. Call `run_pipeline(alerts=..., assets=..., identities=...)`.
5. Serve `result.risk_ranked` to analysts.
6. Repeat every 1–5 minutes.

```python
from datetime import datetime, timedelta, timezone
from engine.pipeline import run_pipeline

def triage_window(siem_client, cmdb, iam, lookback_hours=6):
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    raw = siem_client.search(since=since)
    alerts = [map_siem_event(event) for event in raw]
    return run_pipeline(alerts=alerts, assets=cmdb, identities=iam)
```

`map_siem_event` is the only product-specific code. The scorer, correlator, and risk YAML stay unchanged.

What a live adapter must supply that many SIEMs omit:

- **`fp_rate` per rule.** If every rule is 0.1, noisy WAF floods will not be damped.
- **ATT&CK tactic/technique.** Attach it in the adapter if the SIEM has no mapping.
- **Stable entity IDs.** The user/host string on the alert must match IAM/CMDB.

Not in scope until a connector exists: Splunk/Elastic/Sentinel adapters, a webhook server, a Kafka consumer, or an incremental “score this one new alert” API. A new alert only changes rank after the next full window run.
