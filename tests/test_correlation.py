from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.correlator import correlate_alerts, entity_keys
from engine.schemas import AlertEntities, Asset, EnrichedAlert


T0 = datetime(2026, 3, 18, 13, 0, tzinfo=timezone.utc)


def _alert(
    alert_id: str,
    minutes: int,
    *,
    user: str | None = None,
    host: str | None = None,
    src: str | None = None,
    dest: str | None = None,
    tactic: str = "Discovery",
    product: str = "EDR",
    scenario: str | None = "demo",
) -> EnrichedAlert:
    asset = None
    if host:
        asset = Asset(
            host_id=host,
            hostname=f"{host}.internal",
            ip_address=src or "10.0.0.1",
            environment="prod",
            data_sensitivity="internal",
            business_criticality=3,
        )
    return EnrichedAlert(
        alert_id=alert_id,
        timestamp=T0 + timedelta(minutes=minutes),
        source_product=product,  # type: ignore[arg-type]
        rule_name=f"rule-{alert_id}",
        severity_raw="Medium",
        confidence=0.7,
        false_positive_rate=0.2,
        mitre_tactic=tactic,  # type: ignore[arg-type]
        mitre_technique=f"T-{alert_id}",
        entities=AlertEntities(user_id=user, host_id=host, src_ip=src, dest_ip=dest),
        scenario_id=scenario,
        asset=asset,
        member_alert_ids=[alert_id],
    )


def test_shared_user_within_window_forms_one_incident() -> None:
    alerts = [
        _alert("A1", 0, user="u-maria-chen", host="host-ws-maria", tactic="Initial Access"),
        _alert("A2", 30, user="u-maria-chen", host="host-fin-web-01", tactic="Lateral Movement"),
        _alert("A3", 50, user="u-maria-chen", host="host-pci-db-01", tactic="Exfiltration"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert set(incidents[0].alert_ids) == {"A1", "A2", "A3"}
    assert incidents[0].unique_tactics == [
        "Initial Access",
        "Lateral Movement",
        "Exfiltration",
    ]


def test_unrelated_entities_do_not_join() -> None:
    alerts = [
        _alert("A1", 0, user="u-maria-chen", host="host-ws-maria"),
        _alert("B1", 2, user="u-other", host="host-sandbox-web-07"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2


def test_generic_dns_ip_is_not_a_join_key() -> None:
    alerts = [
        _alert("A1", 0, user="u-a", dest="8.8.8.8"),
        _alert("B1", 1, user="u-b", dest="8.8.8.8"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2
    assert "ip:8.8.8.8" not in entity_keys(alerts[0])


def test_scenario_id_is_ignored_for_correlation() -> None:
    related = [
        _alert("A1", 0, user="u-maria-chen", host="host-ws-maria", scenario="true_breach"),
        _alert("A2", 10, user="u-maria-chen", host="host-fin-web-01", scenario="true_breach"),
    ]
    scrambled = [
        related[0].model_copy(update={"scenario_id": "noisy_scanner"}),
        related[1].model_copy(update={"scenario_id": "isolated_noise"}),
    ]
    left = {tuple(inc.alert_ids) for inc in correlate_alerts(related)}
    right = {tuple(inc.alert_ids) for inc in correlate_alerts(scrambled)}
    assert left == right


def test_outside_temporal_window_does_not_merge() -> None:
    alerts = [
        _alert("A1", 0, user="u-maria-chen"),
        _alert("A2", 400, user="u-maria-chen"),
    ]
    incidents = correlate_alerts(alerts, window_minutes=120)
    assert len(incidents) == 2
