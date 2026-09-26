from __future__ import annotations

from engine.explainer import (
    apply_llm_prose,
    attack_timeline,
    build_card,
    deterministic_containment,
    enhance_with_llm,
    llm_incident_payload,
    timeline_cites_real_ids,
    why_not_false_positive,
)
from tests.test_risk_scoring import _breach_incident, _scanner_incident
from engine.risk_scorer import score_incident


def test_timeline_cites_real_alert_ids() -> None:
    scored = score_incident(_breach_incident())
    lines = attack_timeline(scored)
    known = set(scored.incident.alert_ids)
    assert lines
    assert timeline_cites_real_ids(lines, known)
    for alert_id in known:
        assert any(f"[{alert_id}]" in line for line in lines)
    for line in lines:
        assert " — " in line
        assert line[0].isdigit()
        assert "[" in line and "]" in line


def test_timeline_never_invents_entities() -> None:
    scored = score_incident(_breach_incident())
    card = build_card(scored, risk_rank=1, legacy_rank=4)
    known_users = set(card.users)
    known_hosts = set(card.hosts)
    blob = " ".join(card.attack_timeline)
    for user in known_users:
        assert user in blob
    assert "usr_not_in_incident" not in blob
    assert "10.9.9.9" not in blob
    for host in known_hosts:
        assert host in blob or any(asset.hostname in blob for asset in card.assets)


def test_recommended_actions_cite_entities_not_generic_hosts() -> None:
    breach = score_incident(_breach_incident())
    actions = deterministic_containment(breach)
    blob = " ".join(actions)
    assert actions
    assert "u-maria-chen" in blob
    assert "host-pci-db-01" in blob
    assert "involved hosts" not in blob
    assert "involved accounts" not in blob
    assert any("Disable or rotate u-maria-chen credentials." == row for row in actions)
    assert any("Isolate host-pci-db-01 from the network." == row for row in actions)
    assert any("Restrict outbound connectivity from host-pci-db-01." == row for row in actions)
    assert any("Preserve EDR telemetry before remediation." == row for row in actions)
    assert any(
        "Review authentication activity associated with u-maria-chen." == row
        for row in actions
    )


def test_scanner_actions_stay_in_sandbox_and_name_the_rule() -> None:
    scanner = score_incident(_scanner_incident())
    actions = deterministic_containment(scanner)
    blob = " ".join(actions)
    assert "host-sandbox-web-07" in blob
    assert "sandbox VLAN" in blob
    assert "WAF SQLi signature match" in blob
    assert "involved hosts" not in blob
    assert "usr_admin_root" not in blob


def test_why_not_false_positive_uses_deterministic_signals() -> None:
    breach = why_not_false_positive(score_incident(_breach_incident()))
    assert "unlikely to be isolated noise" in breach
    assert "definitely malicious" not in breach.lower()
    assert "credential" in breach.lower() or "Credential" in breach
    scanner = why_not_false_positive(score_incident(_scanner_incident()))
    assert "definitely" not in scanner.lower()
    assert "isolated noise" in scanner


def test_llm_payload_is_incident_scoped() -> None:
    scored = score_incident(_breach_incident())
    card = build_card(scored, risk_rank=2, legacy_rank=7)
    payload = llm_incident_payload(card)
    assert payload["incident_id"] == card.incident_id
    assert payload["alert_ids"] == list(card.alert_ids)
    assert payload["naive_siem_rank"] == 7
    assert payload["ai_rank"] == 2
    assert payload["risk_score"] == card.risk_score
    assert {row["factor"] for row in payload["risk_attribution"]} == {
        driver.factor for driver in card.why_prioritized
    }
    assert [row["alert_id"] for row in payload["alerts"]] == list(card.alert_ids)
    assert "background_noise" not in str(payload)
    assert "unrelated" not in str(payload)


def test_enhance_with_llm_falls_back_without_keys(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    scored = score_incident(_breach_incident())
    card = build_card(scored, risk_rank=1, legacy_rank=4)
    enhanced = enhance_with_llm(card)
    assert enhanced.explanation_source == "deterministic"
    assert enhanced.llm_enhanced is False
    assert enhanced.risk_score == card.risk_score
    assert enhanced.attack_timeline == card.attack_timeline


def test_llm_prose_is_rejected_when_it_invents_ids() -> None:
    scored = score_incident(_breach_incident())
    card = build_card(scored, risk_rank=1, legacy_rank=4)
    invented = apply_llm_prose(
        card,
        {
            "executive_summary": "Host evil-box-99 was pwned by usr_nobody.",
            "attack_timeline": ["[ALT-99999] 09:12 UTC — imaginary VPN login."],
            "why_not_false_positive": "Definitely malicious.",
            "recommended_actions": ["Isolate 8.8.8.8 immediately."],
            "contrastive_explanation": "Because I said so.",
        },
    )
    assert invented.attack_timeline == card.attack_timeline
    assert "[ALT-99999]" not in "".join(invented.attack_timeline)
    assert invented.risk_score == card.risk_score
    assert invented.why_prioritized == card.why_prioritized
    assert invented.explanation_source == "deterministic"


def test_llm_prose_keeps_valid_cited_timeline() -> None:
    scored = score_incident(_breach_incident())
    card = build_card(scored, risk_rank=1, legacy_rank=4)
    first_id = card.alert_ids[0]
    accepted = apply_llm_prose(
        card,
        {
            "executive_summary": card.executive_summary,
            "attack_timeline": [f"[{first_id}] 13:00 UTC — {card.tactics[0]} observed."],
            "why_not_false_positive": "This is unlikely to be isolated noise given the supplied tactics.",
            "recommended_actions": card.recommended_actions,
            "contrastive_explanation": card.contrastive_explanation,
        },
    )
    assert accepted.explanation_source == "llm"
    assert accepted.llm_enhanced is True
    assert accepted.attack_timeline[0].startswith(f"[{first_id}]")
    assert accepted.risk_score == card.risk_score
    assert accepted.priority_rank == 1
    assert accepted.naive_siem_rank == 4
