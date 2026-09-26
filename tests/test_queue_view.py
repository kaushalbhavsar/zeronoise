"""Tests for the dense incident queue view model and board helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from console.common import visible_incidents
from console.state import OPEN_STATUSES, PRIORITIES
from engine.pipeline import run_pipeline
from engine.presentation import rank_delta, rank_delta_label
from engine.queue_view import (
    build_queue_row,
    compact_age,
    compact_rank_delta,
    compression_label,
    default_sort_key,
    display_asset,
    display_owner,
    format_rank_cell,
    latest_attack_stage,
    queue_title,
    rank_tooltip,
    row_aria_label,
    sort_queue_rows,
)
from engine.risk_scorer import score_incident, score_incidents
from tests.test_risk_scoring import _breach_incident, _scanner_incident
from config import ALERTS_PATH, CMDB_PATH, IAM_PATH


def test_rank_delta_convention() -> None:
    """legacy #27 + ZeroNoise #1 → ↑26; legacy #1 + ZeroNoise #14 → ↓13."""
    assert rank_delta(1, 27) == 26
    assert compact_rank_delta(26) == "↑26"
    assert rank_delta(14, 1) == -13
    assert compact_rank_delta(-13) == "↓13"
    assert compact_rank_delta(0) == "—"
    assert compact_rank_delta(None) == "—"
    assert rank_delta_label(26) == "↑ 26 positions"


def test_format_rank_cell_modes() -> None:
    assert format_rank_cell(mode="zeronoise", zeronoise_rank=1, legacy_rank=27, delta=26) == "#1 ↑26"
    assert format_rank_cell(mode="legacy", zeronoise_rank=1, legacy_rank=27, delta=26) == "#27"
    assert "ZeroNoise rank #1" in rank_tooltip(1, 27)
    assert "Legacy SIEM rank #27" in rank_tooltip(1, 27)


def test_compression_label() -> None:
    assert compression_label(120, 2) == "120 → 2"
    assert compression_label(6, 6) == "6 → 6"


def test_missing_owner_and_asset() -> None:
    assert display_owner(None) == "Unassigned"
    assert display_owner("") == "Unassigned"
    assert display_owner("Maya") == "Maya"
    assert display_asset(None) == "—"
    assert display_asset("wrk-corp-14") == "wrk-corp-14"


def test_compact_age() -> None:
    now = datetime(2026, 3, 18, 14, 0, tzinfo=timezone.utc)
    assert compact_age(now - timedelta(minutes=18), now) == "18m"
    assert compact_age(now - timedelta(hours=2), now) == "2h"
    assert compact_age(now - timedelta(hours=50), now) == "2d"


def test_queue_title_and_stage_from_facts() -> None:
    breach = score_incident(_breach_incident())
    scanner = score_incident(_scanner_incident())
    assert queue_title(breach) == "Crown-jewel exfiltration"
    assert queue_title(scanner) == "WAF exploit burst"
    short, full = latest_attack_stage(breach)
    assert short == "EXFIL"
    assert full == "Exfiltration"


def test_build_queue_row_matches_incident_data() -> None:
    ranked = score_incidents([_scanner_incident(), _breach_incident()])
    now = ranked[0].incident.last_seen + timedelta(minutes=12)
    breach = next(item for item in ranked if item.risk_rank == 1)
    row = build_queue_row(breach, now, status="Investigating", owner=None)
    assert row.priority in {"P0", "P1", "P2"}
    assert row.risk_score == breach.risk.risk_score
    assert row.zeronoise_rank == breach.risk_rank
    assert row.legacy_rank == breach.naive_siem_rank
    assert row.rank_delta == rank_delta(breach.risk_rank, breach.naive_siem_rank)
    assert row.raw_alert_count == breach.incident.total_event_count
    assert row.deduplicated_event_count == len(breach.incident.alerts)
    assert row.owner == "Unassigned"
    assert row.primary_asset is not None
    assert "IAM" in row.sensors or "EDR" in row.sensors
    assert row.latest_attack_stage == "EXFIL"
    assert "role=\"row\"" not in row.title  # plain text title
    aria = row_aria_label(row, mode="zeronoise")
    assert row.priority in aria
    assert row.title in aria


def test_default_sort_follows_ranking_mode() -> None:
    assert default_sort_key("zeronoise") == "zeronoise_rank"
    assert default_sort_key("legacy") == "legacy_rank"


def test_sort_queue_zeronoise_and_legacy() -> None:
    ranked = score_incidents([_scanner_incident(), _breach_incident()])
    now = ranked[0].incident.last_seen + timedelta(minutes=12)
    rows = [
        build_queue_row(item, now, status="New", owner="Unassigned")
        for item in ranked
    ]
    by_zn = sort_queue_rows(rows, "zeronoise_rank", ascending=True)
    assert [r.zeronoise_rank for r in by_zn] == sorted(r.zeronoise_rank for r in by_zn if r.zeronoise_rank)
    by_leg = sort_queue_rows(rows, "legacy_rank", ascending=True)
    assert by_leg[0].legacy_rank == 1
    # Scanner is legacy #1 but ZeroNoise deprioritizes it.
    scanner_row = next(r for r in rows if r.legacy_rank == 1)
    assert scanner_row.zeronoise_rank == 2
    assert scanner_row.rank_delta is not None and scanner_row.rank_delta < 0


def test_pipeline_board_rows_show_waf_drop_and_serious_rise() -> None:
    result = run_pipeline(str(ALERTS_PATH), str(CMDB_PATH), str(IAM_PATH), use_llm=False)
    now = max(item.incident.last_seen for item in result.risk_ranked) + timedelta(minutes=12)
    rows = [
        build_queue_row(item, now, status="New", owner="Unassigned")
        for item in result.risk_ranked
    ]
    assert len(rows) >= 10
    top = rows[0]
    assert top.zeronoise_rank == 1
    assert top.latest_attack_stage == "IMPACT"
    assert "Ransomware" in top.title or top.risk_score >= 80
    noisy = next(
        row
        for row, item in zip(rows, result.risk_ranked)
        if any(a.scenario_id == "noisy_false_priority" for a in item.incident.alerts)
    )
    assert noisy.legacy_rank == 1
    assert noisy.zeronoise_rank is not None and noisy.zeronoise_rank > 2
    assert noisy.rank_delta is not None and noisy.rank_delta < 0
    assert noisy.raw_alert_count == 120
    assert compression_label(noisy.raw_alert_count, noisy.deduplicated_event_count).startswith("120 →")


def test_visible_incidents_default_zeronoise_order(monkeypatch) -> None:
    result = run_pipeline(str(ALERTS_PATH), str(CMDB_PATH), str(IAM_PATH), use_llm=False)

    class _FakeSession(dict):
        def __getattr__(self, name):
            try:
                return self[name]
            except KeyError as exc:
                raise AttributeError(name) from exc

        def __setattr__(self, name, value):
            self[name] = value

    fake = _FakeSession()
    fake.cases = {
        item.incident.incident_id: {"status": "New", "assignee": "Unassigned", "notes": "", "done": [], "history": []}
        for item in result.risk_ranked
    }
    monkeypatch.setattr("console.common.case", lambda incident_id: fake.cases[incident_id])
    monkeypatch.setattr("console.state.case", lambda incident_id: fake.cases[incident_id])

    visible = visible_incidents(
        result,
        "ZeroNoise Risk-Based",
        "",
        list(PRIORITIES),
        list(OPEN_STATUSES),
        [],
        False,
        True,
    )
    assert [item.risk_rank for item in visible[:5]] == [1, 2, 3, 4, 5]

    legacy = visible_incidents(
        result,
        "Legacy SIEM",
        "",
        list(PRIORITIES),
        list(OPEN_STATUSES),
        [],
        False,
        True,
    )
    assert legacy[0].naive_siem_rank == 1
    assert legacy[0].incident.incident_id != visible[0].incident.incident_id
