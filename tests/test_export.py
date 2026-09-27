from datetime import timedelta
import re

from config import ALERTS_PATH, CMDB_PATH, IAM_PATH
from console.export import case_markdown, case_pdf, export_filenames
from engine.incident_report import (
    SECTION_ORDER,
    analyst_prose_fields,
    build_incident_report,
    display_title,
)
from engine.pipeline import run_pipeline
from engine.readability import is_readable
from engine.schemas import ScoredIncident
from tests.test_risk_scoring import _breach_incident, _scanner_incident
from engine.risk_scorer import score_incident


def _result():
    return run_pipeline(str(ALERTS_PATH), str(CMDB_PATH), str(IAM_PATH), use_llm=False)


def _now(result):
    return max(scored.incident.last_seen for scored in result.risk_ranked) + timedelta(minutes=12)


def _card(result, item):
    return next(card for card in result.cards if card.incident_id == item.incident.incident_id)


def _crown(result=None):
    result = result or _result()
    item = next(
        scored
        for scored in result.risk_ranked
        if "usr_admin_root" in scored.incident.unique_users
    )
    return item, _card(result, item), _now(result), result


def _ransomware(result=None):
    result = result or _result()
    item = result.risk_ranked[0]
    return item, _card(result, item), _now(result), result


def _record(**overrides) -> dict:
    base = {
        "status": "New",
        "assignee": "Unassigned",
        "notes": "",
        "done": [],
        "close_reason": "",
        "history": [],
    }
    base.update(overrides)
    return base


def test_report_sections_appear_in_decision_first_order() -> None:
    item, card, now, result = _ransomware()
    text = case_markdown(item, card, _record(), now, peers=result.risk_ranked)
    positions = [text.find(f"## {name}" if name != "Technical appendix" else "# Technical appendix") for name in SECTION_ORDER]
    assert all(pos >= 0 for pos in positions), positions
    assert positions == sorted(positions)


def test_alert_citations_belong_to_the_incident() -> None:
    item, card, now, result = _ransomware()
    text = case_markdown(item, card, _record(), now, peers=result.risk_ranked)
    known = set(item.incident.alert_ids)
    cited = set(re.findall(r"\[(ALRT-[A-Za-z0-9-]+)\]", text))
    assert cited
    assert cited <= known


def test_risk_driver_values_match_engine_and_sum_to_100() -> None:
    item, card, now, _ = _ransomware()
    report = build_incident_report(item, card, _record(), now)
    engine = {driver.factor: driver.contribution_pct for driver in (card.why_prioritized or item.risk.drivers)}
    rendered = {driver.factor: driver.contribution_pct for driver in report.risk_drivers}
    assert sum(rendered.values()) == 100
    for factor, pct in rendered.items():
        assert engine.get(factor, engine.get("FP/Noise Suppression" if "Noise" in factor else factor)) == pct or pct in engine.values()
    assert [driver.contribution_pct for driver in report.risk_drivers] == [
        driver.contribution_pct for driver in (card.why_prioritized or item.risk.drivers)
    ]


def test_standard_user_is_never_called_privileged() -> None:
    item = score_incident(_breach_incident())
    card = _synthetic_card(item)
    now = item.incident.last_seen
    text = case_markdown(item, card, _record(), now)
    assert "u-maria-chen" in text
    assert "Privileged identity" not in text
    assert "privileged" not in text.lower()


def test_unknown_destination_is_omitted_not_invented() -> None:
    scanner = score_incident(_scanner_incident())
    card = _synthetic_card(scanner)
    text = case_markdown(scanner, card, _record(), scanner.incident.last_seen)
    assert "Destination: —" not in text
    assert "| **Destination** | `—`" not in text


def test_tables_escape_pipe_characters() -> None:
    item, card, now, _ = _ransomware()
    if card.recommended_actions:
        card.recommended_actions[0] = "Review rule `a|b` before close."
    text = case_markdown(item, card, _record(), now)
    assert "a\\|b" in text or "a|b" not in "".join(
        line for line in text.splitlines() if line.startswith("|")
    )


def test_analyst_facing_prose_meets_flesch_threshold() -> None:
    item, card, now, result = _ransomware()
    report = build_incident_report(item, card, _record(), now, peers=result.risk_ranked)
    for field in analyst_prose_fields(report):
        assert is_readable(field), field


def test_export_uses_zeronoise_branding() -> None:
    item, card, now, _ = _ransomware()
    text = case_markdown(item, card, _record(), now)
    assert "ZeroNoise" in text
    assert "Pragyan" not in text
    assert "ai_rank" not in text
    assert "ZeroNoise rank" in text


def test_case_markdown_matches_workspace_context() -> None:
    item, card, now, result = _crown()
    record = _record(
        status="Investigating",
        assignee="You",
        notes="handoff: confirm dest volume",
        history=[
            {
                "at": "2026-09-26 12:00:00Z",
                "actor": "You",
                "field": "status",
                "old": "New",
                "new": "Investigating",
            }
        ],
    )
    text = case_markdown(item, card, record, now, peers=result.risk_ranked)
    assert "Crown-jewel exfil" in text or "exfil" in text.lower()
    assert item.title in text
    assert item.incident.incident_id in text
    assert "usr_admin_root" in text
    assert "prd-billing-db-01" in text
    assert "## Decision brief" in text
    assert "## B. Raw detections" in text
    assert "## Evidence linking" in text
    assert "handoff: confirm dest volume" in text
    assert "Status: New → Investigating" in text
    assert "not a confidence" in text.lower() or "not a confidence percentage" in text
    assert "History is not invented" not in text
    assert "# Technical appendix" in text
    assert "```text" in text
    assert "risk_score = 100 × (1 − exp(−RawRisk / 45))" in text
    assert "RawRisk    = B × K × C" in text
    assert item.risk.formula not in text
    first_formula = text.find("## A. Risk calculation")
    first_rank = text.find("Why ZeroNoise ranked this")
    assert 0 <= first_rank < first_formula
    assert "| **RawRisk** |" in text
    assert "| **B** |" in text
    assert "Risk model: ZN-RISK-1.0" in text
    assert "Configuration hash:" in text
    assert item.risk_config_hash[:12] in text
    assert "Normalization scale: 45" in text
    assert "Fidelity cap: 35" in text


def test_case_markdown_does_not_invent_history() -> None:
    item, card, now, _ = _crown()
    text = case_markdown(item, card, _record(), now)
    assert "No case changes in this session. History is not invented." in text
    assert "No notes have been saved in this session." in text


def test_masked_export_hides_identifiers() -> None:
    item, card, now, _ = _crown()
    text = case_markdown(item, card, _record(), now, mask=True)
    assert "usr_admin_root" not in text
    assert "usr_••••" in text
    names = export_filenames(item, mask=True)
    assert names["md"].endswith(".md")
    assert names["pdf"].endswith(".pdf")
    assert item.incident.incident_id not in names["md"]


def test_pdf_contains_case_title() -> None:
    item, card, now, _ = _crown()
    markdown = case_markdown(item, card, _record(), now)
    pdf = case_pdf(markdown)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf
    assert item.title.split()[0].encode("latin-1", "replace") in pdf
    assert b"Decision brief" in pdf
    assert b"Raw detections" in pdf


def test_ransomware_report_is_readable_decision_first() -> None:
    item, card, now, result = _ransomware()
    assert "Impact" in item.incident.unique_tactics
    text = case_markdown(item, card, _record(status="Escalated", assignee="You"), now, peers=result.risk_ranked)
    assert display_title(item).startswith("Ransomware staging")
    assert text.splitlines()[0] == f"# {display_title(item)}"
    assert "Immediate action" in text
    assert "What happened" in text
    assert "Why it matters" in text
    assert "RawRisk    = B × K × C" in text
    assert "RawRisk = B × K × C =" not in text
    assert text.find("## Decision brief") < text.find("# Technical appendix")
    assert text.find("## Decision brief") < text.find("## A. Risk calculation")
    assert "definitely malicious" not in text.lower()


def _synthetic_card(item: ScoredIncident):
    from engine.explainer import build_card

    return build_card(item)
