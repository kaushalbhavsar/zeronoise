from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.correlator import (
    build_correlation_graph,
    correlate_alerts,
    entity_keys,
)
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
    process_hash: str | None = None,
    tactic: str = "Discovery",
    product: str = "EDR",
    scenario: str | None = "demo",
    ip: str | None = None,
) -> EnrichedAlert:
    asset = None
    if host:
        asset = Asset(
            host_id=host,
            hostname=f"{host}.internal",
            ip_address=ip or src or dest or "10.0.0.1",
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
        entities=AlertEntities(
            user_id=user,
            host_id=host,
            src_ip=src,
            dest_ip=dest,
            process_hash=process_hash,
        ),
        scenario_id=scenario,
        asset=asset,
        original_alert_ids=[alert_id],
        member_alert_ids=[alert_id],
    )


def test_shared_user_within_window_forms_one_incident() -> None:
    alerts = [
        _alert("A1", 0, user="usr_svc_deploy", host="prd-app-02", tactic="Initial Access"),
        _alert("A2", 30, user="usr_svc_deploy", host="prd-app-02", tactic="Credential Access"),
        _alert("A3", 50, user="usr_admin_root", host="prd-billing-db-01", tactic="Exfiltration"),
    ]
    # A3 shares no user/host with A1/A2 unless we add a pivot.
    alerts[2] = _alert(
        "A3",
        50,
        user="usr_admin_root",
        host="prd-billing-db-01",
        dest="10.0.0.1",
        tactic="Exfiltration",
        ip="10.20.4.10",
    )
    # Re-link via destination pivot: A2 dest == A3 src, plus shared identity chain via host pivot.
    alerts = [
        _alert("A1", 0, user="usr_svc_deploy", host="prd-app-02", tactic="Initial Access"),
        _alert("A2", 30, user="usr_svc_deploy", host="prd-app-02", tactic="Lateral Movement"),
        _alert("A3", 50, user="usr_svc_deploy", host="prd-billing-db-01", tactic="Exfiltration"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert set(incidents[0].alert_ids) == {"A1", "A2", "A3"}
    types = {edge.relationship_type for edge in incidents[0].edges}
    assert "SHARED_IDENTITY" in types
    assert incidents[0].edges
    assert all(hasattr(edge, "correlation_strength") for edge in incidents[0].edges)


def test_destination_and_host_ip_pivot() -> None:
    app = Asset(
        host_id="prd-app-02",
        hostname="prd-app-02.prod.internal",
        ip_address="10.20.8.22",
        environment="prod",
        data_sensitivity="confidential",
        business_criticality=4,
    )
    billing = Asset(
        host_id="prd-billing-db-01",
        hostname="prd-billing-db-01.prod.internal",
        ip_address="10.20.4.10",
        environment="prod",
        data_sensitivity="crown_jewel_pii_pci",
        business_criticality=5,
    )
    a = _alert("P1", 0, host="prd-app-02", src="10.20.8.22", dest="10.20.4.10")
    a = a.model_copy(update={"asset": app, "dest_asset": billing})
    b = _alert("P2", 12, host="prd-billing-db-01", src="10.20.4.10")
    b = b.model_copy(update={"asset": billing})
    incidents = correlate_alerts([a, b])
    assert len(incidents) == 1
    types = {edge.relationship_type for edge in incidents[0].edges}
    assert "DESTINATION_PIVOT" in types or "HOST_IP_PIVOT" in types


def test_unrelated_entities_do_not_join() -> None:
    alerts = [
        _alert("A1", 0, user="usr_svc_deploy", host="prd-app-02"),
        _alert("B1", 2, user="usr_other", host="dev-sandbox-04"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2


def test_generic_dns_ip_is_not_a_join_key() -> None:
    alerts = [
        _alert("A1", 0, user="usr-a", dest="8.8.8.8"),
        _alert("B1", 1, user="usr-b", dest="8.8.8.8"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2
    assert "ip:8.8.8.8" not in entity_keys(alerts[0])


def test_scanner_ip_does_not_weld_unrelated_hosts() -> None:
    alerts = [
        _alert(
            f"S{i}",
            i,
            host=f"wrk-target-{i:02d}",
            src="198.51.100.66",
            dest=f"10.90.1.{i}",
            ip=f"10.90.1.{i}",
        )
        for i in range(12)
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 12


def test_jump_host_alone_is_low_confidence() -> None:
    graph = build_correlation_graph(
        [
            _alert("J1", 0, host="prd-jump-01", user="usr-a"),
            _alert("J2", 5, host="prd-jump-01", user="usr-b"),
        ]
    )
    data = list(graph.edges(data=True))
    assert data
    assert all(edge[2]["correlation_strength"] <= 0.40 for edge in data)


def test_scenario_id_is_ignored_for_correlation() -> None:
    related = [
        _alert("A1", 0, user="usr_svc_deploy", host="prd-app-02", scenario="quiet_crown_jewel"),
        _alert("A2", 10, user="usr_svc_deploy", host="prd-app-02", scenario="quiet_crown_jewel"),
    ]
    scrambled = [
        related[0].model_copy(update={"scenario_id": "noisy_false_priority"}),
        related[1].model_copy(update={"scenario_id": "background_noise"}),
    ]
    left = {tuple(inc.alert_ids) for inc in correlate_alerts(related)}
    right = {tuple(inc.alert_ids) for inc in correlate_alerts(scrambled)}
    assert left == right


def test_outside_four_hour_window_does_not_merge() -> None:
    alerts = [
        _alert("A1", 0, user="usr_svc_deploy"),
        _alert("A2", 400, user="usr_svc_deploy"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2
