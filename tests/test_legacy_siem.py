"""Smoke tests for the legacy SIEM foil queue."""

from __future__ import annotations

from pathlib import Path

from config import ALERTS_PATH
from legacy_siem.app import aggregate, filter_rows, load_alerts


def test_legacy_queue_puts_noisy_waf_first() -> None:
    alerts = load_alerts(ALERTS_PATH)
    rows = aggregate(alerts)
    assert rows
    top = rows[0]
    assert top["severity"] == "Critical"
    assert top["host"] == "dev-sandbox-04"
    assert top["count"] >= 40
    assert "WAF" in top["rule"] or top["product"] in {"WAF", "IDS"}
    assert top["score"] == 15 * top["count"]


def test_filter_severity() -> None:
    rows = aggregate(load_alerts(ALERTS_PATH))
    critical = filter_rows(rows, q="", sev="Critical")
    assert critical
    assert all(r["severity"] == "Critical" for r in critical)
    sandbox = filter_rows(rows, q="dev-sandbox-04", sev="All")
    assert any(r["host"] == "dev-sandbox-04" for r in sandbox)


def test_waf_extract_also_parses() -> None:
    path = Path("data/waf_noisy_sandbox.jsonl")
    alerts = load_alerts(path)
    assert len(alerts) == 120
    rows = aggregate(alerts)
    assert rows[0]["count"] >= 40
