from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.correlator import correlate_alerts
from engine.risk_scorer import (
    diminishing_volume,
    fidelity_a,
    naive_siem_score,
    positive_attribution_sum,
    score_business_impact,
    score_incident,
    score_incidents,
    score_privilege,
    score_progression,
    score_threat_fidelity,
)
from engine.schemas import AlertEntities, Asset, EnrichedAlert, Identity


T0 = datetime(2026, 3, 18, 13, 0, tzinfo=timezone.utc)

CROWN = Asset(
    host_id="host-pci-db-01",
    hostname="pci-db-01.prod.internal",
    ip_address="10.20.4.12",
    environment="prod",
    data_sensitivity="crown_jewel_pii_pci",
    business_criticality=5,
)
SANDBOX = Asset(
    host_id="host-sandbox-web-07",
    hostname="sandbox-web-07.sandbox.internal",
    ip_address="10.90.1.77",
    environment="sandbox",
    data_sensitivity="public",
    business_criticality=1,
)
FINANCE_USER = Identity(
    user_id="u-maria-chen",
    department="Finance",
    privilege_tier="standard_user",
)


def _alert(**kwargs) -> EnrichedAlert:
    defaults = dict(
        timestamp=T0,
        source_product="EDR",
        rule_name="demo",
        severity_raw="Medium",
        confidence=0.7,
        false_positive_rate=0.2,
        mitre_tactic="Discovery",
        mitre_technique="T1087",
        entities=AlertEntities(),
        event_count=1,
        member_alert_ids=[],
    )
    defaults.update(kwargs)
    if not defaults["member_alert_ids"]:
        defaults["member_alert_ids"] = [defaults["alert_id"]]
    return EnrichedAlert(**defaults)


def _breach_incident():
    chain = [
        ("Initial Access", "IAM", "T1078"),
        ("Credential Access", "EDR", "T1003.001"),
        ("Lateral Movement", "NDR", "T1021"),
        ("Collection", "DLP", "T1213"),
        ("Exfiltration", "NDR", "T1041"),
    ]
    alerts = []
    for i, (tactic, product, technique) in enumerate(chain):
        alerts.append(
            _alert(
                alert_id=f"B{i}",
                timestamp=T0 + timedelta(minutes=15 * i),
                source_product=product,
                rule_name=f"breach-{i}",
                severity_raw="Medium",
                confidence=0.75,
                false_positive_rate=0.16,
                mitre_tactic=tactic,
                mitre_technique=technique,
                entities=AlertEntities(
                    user_id="u-maria-chen",
                    host_id="host-pci-db-01",
                    dest_ip="10.20.4.12",
                ),
                asset=CROWN,
                dest_asset=CROWN,
                identity=FINANCE_USER,
            )
        )
    return correlate_alerts(alerts)[0]


def _scanner_incident():
    alerts = [
        _alert(
            alert_id="S0",
            source_product="WAF",
            rule_name="WAF SQLi signature match",
            severity_raw="Critical",
            confidence=0.93,
            false_positive_rate=0.78,
            mitre_tactic="Initial Access",
            mitre_technique="T1190",
            entities=AlertEntities(host_id="host-sandbox-web-07", dest_ip="10.90.1.77"),
            asset=SANDBOX,
            dest_asset=SANDBOX,
            event_count=280,
        )
    ]
    return correlate_alerts(alerts)[0]


def test_volume_has_strongly_diminishing_returns() -> None:
    assert diminishing_volume(1) == 1.0
    assert diminishing_volume(120) < 2.0
    assert diminishing_volume(120) < 120 / 10


def test_fidelity_a_matches_spec() -> None:
    score = fidelity_a(
        severity_raw="Medium",
        confidence=0.80,
        false_positive_rate=0.20,
        event_count=1,
    )
    assert score == 5 * 0.80 * (1 - 0.7 * 0.20) * 1.0


def test_fidelity_uses_unique_rule_tactic_pairs() -> None:
    shared = AlertEntities(host_id="host-sandbox-web-07")
    incident = correlate_alerts(
        [
            _alert(
                alert_id="D0",
                rule_name="same-rule",
                mitre_tactic="Discovery",
                event_count=4,
                entities=shared,
                asset=SANDBOX,
            ),
            _alert(
                alert_id="D1",
                timestamp=T0,
                rule_name="same-rule",
                mitre_tactic="Discovery",
                event_count=4,
                entities=shared,
                asset=SANDBOX,
            ),
        ]
    )[0]
    b, _ = score_threat_fidelity(incident)
    combined = fidelity_a(
        severity_raw="Medium",
        confidence=0.7,
        false_positive_rate=0.2,
        event_count=8,
    )
    assert abs(b - combined) < 1e-9
    assert b < 2 * fidelity_a(
        severity_raw="Medium",
        confidence=0.7,
        false_positive_rate=0.2,
        event_count=4,
    )


def test_fidelity_is_capped_at_35() -> None:
    alerts = [
        _alert(
            alert_id=f"C{i}",
            timestamp=T0,
            rule_name=f"rule-{i}",
            severity_raw="Critical",
            confidence=1.0,
            false_positive_rate=0.0,
            mitre_tactic="Impact" if i % 2 else "Exfiltration",
            mitre_technique=f"T{i}",
            entities=AlertEntities(host_id="host-pci-db-01", user_id="u-maria-chen"),
            asset=CROWN,
            identity=FINANCE_USER,
        )
        for i in range(8)
    ]
    incident = correlate_alerts(alerts)[0]
    b, evidence = score_threat_fidelity(incident)
    assert b == 35.0
    assert any("capped" in line for line in evidence)


def test_kill_chain_progression_formula() -> None:
    k, _ = score_progression(_breach_incident())
    # 5 tactics, 4 sensors, Exfiltration present
    assert k == 1.0 + 0.35 * 4 + 0.20 * 3 + 0.50
    scanner_k, _ = score_progression(_scanner_incident())
    assert scanner_k == 1.0


def test_asset_and_identity_use_spec_tables() -> None:
    breach = _breach_incident()
    asset, _ = score_business_impact(breach)
    # prod 1.4, crown jewel 2.0, crit 5 → 2.0
    expected = 0.35 * 1.4 + 0.35 * 2.0 + 0.30 * 2.0
    assert abs(asset - expected) < 1e-9
    scanner_asset, _ = score_business_impact(_scanner_incident())
    assert 0.4 <= scanner_asset <= 0.5
    priv, _ = score_privilege(breach)
    assert priv == 0.5
    no_id, _ = score_privilege(_scanner_incident())
    assert no_id == 0.5


def test_naive_siem_score_sums_raw_severity_weights() -> None:
    breach = _breach_incident()
    scanner = _scanner_incident()
    assert naive_siem_score(breach) == 5 * len(breach.alerts)
    assert naive_siem_score(scanner) == 15 * 280
    scored = score_incidents([scanner, breach])
    assert scored[0].incident.alerts[0].alert_id.startswith("B")
    scanner_scored = next(item for item in scored if item.incident.alerts[0].alert_id.startswith("S"))
    assert scanner_scored.naive_siem_rank == 1
    assert scanner_scored.legacy_score > score_incident(breach).legacy_score


def test_crown_jewel_breach_outranks_critical_sandbox_scanner() -> None:
    breach = score_incident(_breach_incident())
    scanner = score_incident(_scanner_incident())
    assert breach.risk.risk_score > scanner.risk.risk_score
    assert scanner.legacy_score > breach.legacy_score


def test_positive_attribution_is_a_partition() -> None:
    scored = score_incident(_breach_incident())
    total = positive_attribution_sum(scored.risk)
    assert abs(total - 100.0) < 0.05


def test_scoring_is_deterministic() -> None:
    first = score_incident(_breach_incident())
    second = score_incident(_breach_incident())
    assert first.risk.risk_score == second.risk.risk_score
    assert [d.contribution_pct for d in first.risk.drivers] == [
        d.contribution_pct for d in second.risk.drivers
    ]


def test_scenario_id_does_not_change_score() -> None:
    incident = _breach_incident()
    mutated = incident.model_copy(
        update={
            "alerts": [
                alert.model_copy(update={"scenario_id": "noisy_scanner"})
                for alert in incident.alerts
            ]
        }
    )
    assert score_incident(incident).risk.risk_score == score_incident(mutated).risk.risk_score


def test_score_incidents_orders_by_risk_desc() -> None:
    ranked = score_incidents([_scanner_incident(), _breach_incident()])
    assert ranked[0].risk.risk_score >= ranked[1].risk.risk_score
    assert ranked[0].incident.alerts[0].alert_id.startswith("B")
