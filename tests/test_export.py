from datetime import timedelta

from config import ALERTS_PATH, CMDB_PATH, IAM_PATH
from console.export import case_markdown, case_pdf, export_filenames
from engine.pipeline import run_pipeline


def _crown():
    result = run_pipeline(str(ALERTS_PATH), str(CMDB_PATH), str(IAM_PATH), use_llm=False)
    item = next(
        scored
        for scored in result.risk_ranked
        if "usr_admin_root" in scored.incident.unique_users
    )
    card = next(card for card in result.cards if card.incident_id == item.incident.incident_id)
    now = max(scored.incident.last_seen for scored in result.risk_ranked) + timedelta(minutes=12)
    return item, card, now


def test_case_markdown_matches_workspace_context() -> None:
    item, card, now = _crown()
    record = {
        "status": "Investigating",
        "assignee": "You",
        "notes": "handoff: confirm dest volume",
        "done": [],
        "close_reason": "",
        "history": [
            {
                "at": "2026-09-26 12:00:00Z",
                "actor": "You",
                "field": "status",
                "old": "New",
                "new": "Investigating",
            }
        ],
    }
    text = case_markdown(item, card, record, now, mask=False)
    assert item.title in text
    assert item.incident.incident_id in text
    assert "usr_admin_root" in text
    assert "prd-billing-db-01" in text
    assert "Initial identity:" in text
    assert "Privileged identity:" in text
    assert "Source host:" in text
    assert "Affected destination:" in text
    assert "Decision brief" in text
    assert "Detections" in text
    assert "How the events are linked" in text
    assert "handoff: confirm dest volume" in text
    assert "You · status: New -> Investigating" in text
    assert "not a confidence" in text.lower() or "not a confidence percentage" in text
    assert "History is not invented" not in text


def test_case_markdown_does_not_invent_history() -> None:
    item, card, now = _crown()
    record = {
        "status": "New",
        "assignee": "Unassigned",
        "notes": "",
        "done": [],
        "close_reason": "",
        "history": [],
    }
    text = case_markdown(item, card, record, now, mask=False)
    assert "No case changes in this session. History is not invented." in text
    assert "No notes have been saved in this session." in text


def test_masked_export_hides_identifiers() -> None:
    item, card, now = _crown()
    record = {
        "status": "New",
        "assignee": "Unassigned",
        "notes": "",
        "done": [],
        "close_reason": "",
        "history": [],
    }
    text = case_markdown(item, card, record, now, mask=True)
    assert "usr_admin_root" not in text
    assert "usr_••••" in text
    names = export_filenames(item, mask=True)
    assert names["md"].endswith(".md")
    assert names["pdf"].endswith(".pdf")
    assert item.incident.incident_id not in names["md"]


def test_pdf_contains_case_title() -> None:
    item, card, now = _crown()
    record = {
        "status": "New",
        "assignee": "Unassigned",
        "notes": "",
        "done": [],
        "close_reason": "",
        "history": [],
    }
    markdown = case_markdown(item, card, record, now, mask=False)
    pdf = case_pdf(markdown)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf
    assert item.title.split()[0].encode("latin-1", "replace") in pdf
    assert b"Decision brief" in pdf
    assert b"Detections" in pdf
