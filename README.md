# ZeroNoise

AI-driven, risk-based SOC incident triage engine.

The prototype shows why a SOC should stop ranking work by vendor severity and raw alert volume. A noisy scanner can emit hundreds of Critical events against a sandbox. A real breach can emit a handful of Medium events that walk the kill chain on a crown-jewel system. Context, correlation, attack progression, and business impact have to outweigh volume.

The core is deterministic and works fully offline. An LLM, if you turn it on, may only rewrite prose.

## What it proves

On the seeded demo dataset (`RANDOM_SEED = 42`):

| Queue | Rank 1 | Rank of the true breach |
| --- | --- | --- |
| Legacy SIEM (severity × volume) | Noisy sandbox scanner | Buried |
| Risk-based incidents | Stealthy crown-jewel breach | **#1** |

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
engine/risk_scorer.py             Weighted risk + traceable attribution
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

The Streamlit app compares the two queues, opens an incident card with driver attribution, and reports fatigue reduction.

## Risk formula

Six bounded drivers, weights that sum to 1.0, then a noise discount that can only reduce the score:

```text
raw  = Σ w_i * s_i
risk = 100 * raw * (1 - 0.45 * noise)

contribution_pct_i = 100 * (w_i * s_i) / raw
```

| Driver | Weight | What it measures |
| --- | --- | --- |
| Business impact | 0.28 | Environment, data sensitivity, criticality |
| Identity privilege | 0.14 | IAM tier (domain admin … standard user) |
| Attack progression | 0.26 | Unique ATT&CK tactics, late-stage presence, kill-chain span, sensors |
| Signal quality | 0.16 | `confidence × (1 − FPR)`, plus corroboration |
| Blast radius | 0.10 | Distinct hosts and identities |
| Severity residual | 0.06 | Vendor severity is kept, but cannot dominate |
| Noise discount | cap 0.45 | Bursty, high-FPR, single-stage piles (scanners) |

Given the same dataset and `config.py`, ranking, scores, and attribution percentages are identical every run.

## LLM contract

Disabled by default (`LLM_ENABLED = False`). When enabled, the model may rewrite the executive summary, narrative, and containment text. It must not change risk scores, invent entities or alert IDs, alter ranking, add unsupported ATT&CK stages, or override attribution.

## Design constraints

- Dedup key: rule + user + host + src IP + dest IP inside a 15-minute window.
- Correlation: shared resolved entity (user, host, process hash, non-generic IP) inside 120 minutes. Transitive.
- Generic resolvers such as `8.8.8.8` never join incidents.
- Legacy SIEM score: `1000 × max_severity + 10 × alerts + events`.

## Tests

```bash
pytest tests/test_deduplication.py tests/test_correlation.py tests/test_risk_scoring.py tests/test_acceptance.py -q
```

Acceptance checks the ranking inversion, ≥80% fatigue reduction, determinism under seed 42, and that scrambling `scenario_id` does not change clusters or scores.
