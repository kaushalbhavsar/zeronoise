from engine.explainer import LLM_SYSTEM_PROMPT, build_card
from engine.pipeline import run_pipeline
from engine.presentation import evidence_summary, urgency_sentence, why_this_matters
from engine.readability import (
    MIN_FLESCH,
    clean_for_readability,
    enforce_readability,
    flesch_reading_ease,
    is_readable,
)
from engine.risk_scorer import score_incident
from tests.test_risk_scoring import _breach_incident, _scanner_incident


def test_placeholders_do_not_change_published_text() -> None:
    raw = "usr_admin_root copied 2.4 GB from prd-billing-db-01 to 45.133.1.54 using T1048."
    cleaned = clean_for_readability(raw)
    assert "USERID" in cleaned
    assert "HOSTID" in cleaned
    assert "IPADDR" in cleaned
    assert "MITREID" in cleaned
    assert raw == "usr_admin_root copied 2.4 GB from prd-billing-db-01 to 45.133.1.54 using T1048."


def test_plain_sample_meets_threshold() -> None:
    text = (
        "A service account may have been compromised. "
        "The attacker moved from an application server to the billing database. "
        "The database stores sensitive customer data."
    )
    assert flesch_reading_ease(text) >= MIN_FLESCH


def test_hard_sample_is_rejected_then_rewritten() -> None:
    hard = (
        "The elevated prioritization is attributable to increased contextual "
        "blast-radius characteristics associated with a highly sensitive production data asset."
    )
    assert flesch_reading_ease(hard) < MIN_FLESCH
    fallback = (
        "A service account may have been compromised. "
        "The attacker moved from an application server to the billing database."
    )
    out = enforce_readability(hard, fallback)
    assert is_readable(out)


def test_card_fields_pass_independently() -> None:
    result = run_pipeline(use_llm=False)
    for card in result.cards:
        assert is_readable(card.executive_summary), card.incident_id
        if card.contrastive_explanation:
            assert is_readable(card.contrastive_explanation), card.incident_id
        assert is_readable(card.why_not_false_positive), card.incident_id
        for action in card.recommended_actions:
            assert is_readable(action), action
        for line in card.attack_timeline:
            assert is_readable(line), line
        for driver in card.why_prioritized:
            if driver.evidence:
                assert is_readable(driver.evidence), driver.factor


def test_presentation_fields_pass() -> None:
    for item in (score_incident(_breach_incident()), score_incident(_scanner_incident())):
        assert is_readable(why_this_matters(item))
        assert is_readable(urgency_sentence(item))
        assert is_readable(evidence_summary(item))


def test_llm_prompt_requires_plain_english() -> None:
    assert "Flesch Reading Ease score of at least 70" in LLM_SYSTEM_PROMPT
    assert "plain English" in LLM_SYSTEM_PROMPT
    card = build_card(score_incident(_breach_incident()), risk_rank=1, legacy_rank=4)
    assert card.explanation_source == "deterministic"
