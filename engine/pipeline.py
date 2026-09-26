"""End-to-end deterministic triage pipeline."""

from __future__ import annotations

import json
from pathlib import Path

from config import ALERTS_PATH, CMDB_PATH, IAM_PATH
from engine.correlator import correlate_alerts
from engine.explainer import explain_incidents
from engine.normalizer import deduplicate_alerts, normalize_and_enrich_report, parse_jsonl
from engine.risk_scorer import score_incidents
from engine.schemas import (
    Asset,
    EnrichedAlert,
    Identity,
    PipelineMetrics,
    PipelineResult,
    ScoredIncident,
)


def load_json(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    return parse_jsonl(path)


def _scenario_ids(alerts: list[EnrichedAlert]) -> set[str]:
    return {alert.scenario_id for alert in alerts if alert.scenario_id}


def _find_by_scenario(
    scored: list[ScoredIncident], scenario: str
) -> ScoredIncident | None:
    for item in scored:
        if scenario in _scenario_ids(item.incident.alerts):
            return item
    return None


def compute_metrics(
    raw_count: int,
    enriched_count: int,
    deduped: list[EnrichedAlert],
    risk_ranked: list[ScoredIncident],
    legacy_ranked: list[ScoredIncident],
) -> PipelineMetrics:
    incident_count = len(risk_ranked)
    collapsed = max(0, enriched_count - len(deduped))
    fatigue = 0.0
    if raw_count:
        fatigue = 100.0 * (1.0 - incident_count / raw_count)
    compression = 0.0
    if raw_count:
        compression = 100.0 * (1.0 - len(deduped) / raw_count)

    def rank_of(scored_list: list[ScoredIncident], scenario: str) -> int | None:
        for idx, item in enumerate(scored_list, start=1):
            if scenario in _scenario_ids(item.incident.alerts):
                return idx
        return None

    breach_risk = rank_of(risk_ranked, "quiet_crown_jewel")
    breach_legacy = rank_of(legacy_ranked, "quiet_crown_jewel")
    ransom_risk = rank_of(risk_ranked, "ransomware_staging")
    ransom_legacy = rank_of(legacy_ranked, "ransomware_staging")
    scan_risk = rank_of(risk_ranked, "noisy_false_priority")
    scan_legacy = rank_of(legacy_ranked, "noisy_false_priority")
    inverted = bool(
        breach_risk
        and scan_risk
        and breach_legacy
        and scan_legacy
        and breach_risk < scan_risk
        and scan_legacy < breach_legacy
    )
    missing_context = sum(1 for alert in deduped if alert.context_gaps)
    return PipelineMetrics(
        raw_alert_count=raw_count,
        enriched_alert_count=enriched_count,
        deduplicated_alert_count=len(deduped),
        incident_count=incident_count,
        alerts_collapsed_by_dedup=collapsed,
        fatigue_reduction_pct=round(fatigue, 2),
        volume_compression_pct=round(compression, 2),
        quiet_crown_jewel_risk_rank=breach_risk,
        quiet_crown_jewel_legacy_rank=breach_legacy,
        ransomware_staging_risk_rank=ransom_risk,
        ransomware_staging_legacy_rank=ransom_legacy,
        noisy_false_priority_risk_rank=scan_risk,
        noisy_false_priority_legacy_rank=scan_legacy,
        missing_context_alert_count=missing_context,
        ranking_inverted=inverted,
    )


def run_pipeline(
    alerts: list[dict] | None = None,
    assets: list[dict] | list[Asset] | None = None,
    identities: list[dict] | list[Identity] | None = None,
    *,
    alerts_path: Path = ALERTS_PATH,
    cmdb_path: Path = CMDB_PATH,
    iam_path: Path = IAM_PATH,
    use_llm: bool = False,
) -> PipelineResult:
    parse_errors: list[str] = []
    if alerts is not None:
        raw_alerts = list(alerts)
    else:
        raw_alerts, parse_errors = load_jsonl(alerts_path)
    raw_assets = assets if assets is not None else load_json(cmdb_path)
    raw_identities = identities if identities is not None else load_json(iam_path)

    enriched, normalize_errors = normalize_and_enrich_report(
        raw_alerts, raw_assets, raw_identities
    )
    all_errors = parse_errors + normalize_errors
    deduped = deduplicate_alerts(enriched)
    incidents = correlate_alerts(deduped)
    scored = score_incidents(incidents)

    risk_ranked = sorted(
        scored, key=lambda item: (-item.risk.risk_score, item.incident.incident_id)
    )
    legacy_ranked = sorted(
        scored, key=lambda item: (-item.legacy_score, item.incident.incident_id)
    )
    risk_ranks = {
        item.incident.incident_id: idx for idx, item in enumerate(risk_ranked, start=1)
    }
    legacy_ranks = {
        item.incident.incident_id: idx for idx, item in enumerate(legacy_ranked, start=1)
    }

    scanner = _find_by_scenario(scored, "noisy_false_priority")
    breach = _find_by_scenario(scored, "quiet_crown_jewel")
    cards = explain_incidents(
        risk_ranked,
        risk_ranks=risk_ranks,
        legacy_ranks=legacy_ranks,
        contrast_target=scanner,
        contrast_fallback=breach,
        use_llm=use_llm,
    )
    metrics = compute_metrics(
        raw_count=len(raw_alerts) + len(parse_errors),
        enriched_count=len(enriched),
        deduped=deduped,
        risk_ranked=risk_ranked,
        legacy_ranked=legacy_ranked,
    )
    metrics.dropped_alert_count = len(all_errors)
    return PipelineResult(
        alerts_raw=len(raw_alerts) + len(parse_errors),
        normalize_errors=all_errors,
        alerts_deduped=deduped,
        incidents=scored,
        cards=cards,
        risk_ranked=risk_ranked,
        legacy_ranked=legacy_ranked,
        metrics=metrics,
    )


def fingerprint(result: PipelineResult) -> str:
    """Stable digest of ranking + scores for determinism tests."""
    rows = [
        f"{item.incident.incident_id}:{item.risk.risk_score:.4f}:{item.legacy_score:.3f}"
        for item in result.risk_ranked
    ]
    return "|".join(rows)


if __name__ == "__main__":
    result = run_pipeline()
    m = result.metrics
    print("SOC triage pipeline")
    print(f"  raw alerts          : {m.raw_alert_count}")
    print(f"  after dedup         : {m.deduplicated_alert_count}")
    print(f"  incidents           : {m.incident_count}")
    print(f"  fatigue reduction   : {m.fatigue_reduction_pct:.1f}%")
    print(f"  ranking inverted    : {m.ranking_inverted}")
    print("  risk queue (top 5)")
    for idx, item in enumerate(result.risk_ranked[:5], start=1):
        print(
            f"    {idx}. {item.risk.risk_score:6.1f}  {item.incident.incident_id}  {item.title}"
        )
    print("  naive SIEM queue (top 5)")
    for idx, item in enumerate(result.legacy_ranked[:5], start=1):
        print(
            f"    {idx}. naive={item.legacy_score:8.1f}  rank={item.naive_siem_rank}  "
            f"{item.incident.incident_id}  {item.title}"
        )
