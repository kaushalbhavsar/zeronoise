from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.normalizer import (
    deduplicate_alerts,
    normalize_and_enrich,
    normalize_and_enrich_report,
    normalize_ip,
    parse_jsonl,
)
from engine.schemas import AlertEntities, EnrichedAlert


def _alert(
    alert_id: str,
    minutes: int,
    rule: str = "WAF SQLi signature match",
    host: str = "host-sandbox-web-07",
    src: str = "198.51.100.66",
    dest: str = "10.90.1.77",
    event_count: int = 1,
) -> EnrichedAlert:
    return EnrichedAlert(
        alert_id=alert_id,
        timestamp=datetime(2026, 3, 18, 13, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes),
        source_product="WAF",
        rule_name=rule,
        severity_raw="Critical",
        confidence=0.9,
        false_positive_rate=0.7,
        mitre_tactic="Initial Access",
        mitre_technique="T1190",
        entities=AlertEntities(host_id=host, src_ip=src, dest_ip=dest),
        event_count=event_count,
        member_alert_ids=[alert_id],
    )


def test_burst_of_identical_alerts_collapses_and_sums_events() -> None:
    alerts = [_alert(f"A{i}", minutes=i) for i in range(10)]
    collapsed = deduplicate_alerts(alerts, window_minutes=15)
    assert len(collapsed) == 1
    assert collapsed[0].event_count == 10
    assert set(collapsed[0].member_alert_ids) == {f"A{i}" for i in range(10)}


def test_alerts_outside_window_stay_separate() -> None:
    alerts = [_alert("A0", 0), _alert("A1", 20)]
    collapsed = deduplicate_alerts(alerts, window_minutes=15)
    assert len(collapsed) == 2


def test_different_rules_do_not_merge() -> None:
    alerts = [
        _alert("A0", 0, rule="SQLi"),
        _alert("A1", 1, rule="XSS"),
    ]
    collapsed = deduplicate_alerts(alerts, window_minutes=15)
    assert len(collapsed) == 2


def test_vendor_payload_normalizes_then_dedups() -> None:
    raw = [
        {
            "id": f"RAW-{i}",
            "time": f"2026-03-18T13:0{i}:00+00:00",
            "vendor": "F5",
            "signature": "WAF XSS probe blocked",
            "sev": "Critical",
            "confidence": 0.9,
            "fp_rate": 0.7,
            "tactic": "Initial Access",
            "technique": "T1190",
            "host_id": "host-sandbox-web-07",
            "src_ip": "198.51.100.66",
            "dest_ip": "10.90.1.77",
        }
        for i in range(5)
    ]
    assets = [
        {
            "host_id": "host-sandbox-web-07",
            "hostname": "sandbox-web-07",
            "ip_address": "10.90.1.77",
            "environment": "sandbox",
            "data_sensitivity": "public",
            "business_criticality": 1,
        }
    ]
    enriched = normalize_and_enrich(raw, assets, [])
    collapsed = deduplicate_alerts(enriched)
    assert len(collapsed) == 1
    assert collapsed[0].source_product == "WAF"
    assert collapsed[0].event_count == 5


def test_normalize_ip_strips_and_canonicalizes() -> None:
    assert normalize_ip(" 193.32.162.88 ") == "193.32.162.88"
    assert normalize_ip("10.20.8.22/32") == "10.20.8.22"


def test_unknown_identity_does_not_drop_the_alert() -> None:
    raw = [
        {
            "id": "UNK-1",
            "time": "2026-03-18T02:10:00+00:00",
            "vendor": "Okta",
            "signature": "Anomalous VPN login from unusual ASN",
            "sev": "Medium",
            "confidence": 0.7,
            "fp_rate": 0.2,
            "tactic": "Initial Access",
            "technique": "T1078",
            "user_id": "usr_unknown_contractor",
            "src_ip": " 203.0.113.9 ",
        }
    ]
    enriched, errors = normalize_and_enrich_report(raw, [], [])
    assert errors == []
    assert len(enriched) == 1
    assert enriched[0].alert_id == "UNK-1"
    assert enriched[0].original_alert_id == "UNK-1"
    assert enriched[0].entities.src_ip == "203.0.113.9"
    assert any(gap.startswith("unknown_user:") for gap in enriched[0].context_gaps)


def test_parse_jsonl_skips_malformed_lines() -> None:
    rows, errors = parse_jsonl(["{bad", '{"id": "A", "ok": true}', ""])
    assert len(rows) == 1
    assert rows[0]["id"] == "A"
    assert errors
