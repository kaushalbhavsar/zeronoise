from pathlib import Path

from streamlit.testing.v1 import AppTest

from engine.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]


def _app() -> AppTest:
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    at.run()
    assert not at.exception
    return at


def _queue(at: AppTest | None = None) -> AppTest:
    at = at or _app()
    at.switch_page("console/pages/queue.py").run()
    assert not at.exception
    return at


def _intel() -> AppTest:
    at = _app()
    at.switch_page("console/pages/intelligence.py").run()
    assert not at.exception
    return at


def test_overview_is_default_workspace() -> None:
    at = _app()
    titles = [item.value for item in at.title]
    markdown = " ".join(str(item.value) for item in at.markdown)
    assert any("Security overview" in str(value) for value in titles + [markdown])
    assert "Highest-priority incidents" in markdown
    assert "zn-heading" in markdown
    assert "fewer items to review" in markdown.lower() or any(
        "fewer items to review" in str(item.value).lower() for item in at.caption
    )


def test_queue_mode_does_not_raise() -> None:
    at = _queue()
    assert any("Open case" in button.label for button in at.button)
    assert not any("Back to queue" in button.label for button in at.button)
    blob = " ".join(str(item.value) for item in at.markdown)
    assert "Take next" in blob
    assert "Working queue" in blob
    assert "zn-heading" in blob


def test_opening_case_replaces_queue_with_workspace() -> None:
    at = _queue()
    case_id = run_pipeline().risk_ranked[0].incident.incident_id
    at.session_state.active_case_id = case_id
    at.run()
    assert not at.exception
    labels = [button.label for button in at.button]
    assert any("Back to queue" in label for label in labels)
    assert "Open case" not in labels
    downloads = [item.label for item in at.download_button]
    assert "Download Markdown" in downloads
    assert "Download PDF" in downloads
    assert [tab.label for tab in at.tabs] == [
        "Overview",
        "Timeline",
        "ATT&CK",
        "Risk",
        "Response",
        "Evidence",
    ]
    assert len(at.get("plotly_chart")) >= 1
    blob = " ".join(str(item.value) for item in at.markdown)
    blob += " ".join(str(item.value) for item in at.caption)
    assert "What happened?" in blob
    assert "Decision brief" in blob
    assert "Initial identity" in blob
    assert "Chronology" in blob
    assert "ATT&CK path" in blob
    assert "Why this ranks high" in blob
    assert "Recommended work" in blob
    assert "Detections" in blob
    assert "Session activity" in blob
    assert "zn-heading" in blob
    assert "zn-kind" in blob
    assert "Why this ranks high" in blob or any(
        "Why this ranks high" in str(item.value) for item in at.markdown
    )
    assert "Destructive" not in blob
    assert "Why the legacy SIEM got this wrong" not in blob
    assert "Privilege Escalation" in blob
    assert "Lateral Movement" in blob


def test_back_to_queue_preserves_filters() -> None:
    at = _queue()
    at.session_state.queue_search = "wrk-corp"
    case_id = run_pipeline().risk_ranked[0].incident.incident_id
    at.session_state.active_case_id = case_id
    at.run()
    back = next(button for button in at.button if "Back to queue" in button.label)
    back.click().run()
    assert not at.exception
    assert at.session_state.active_case_id is None
    assert at.session_state.queue_search == "wrk-corp"
    assert any("Open case" in button.label for button in at.button)


def test_open_case_helper_sets_active_id() -> None:
    at = _queue()
    first = next(button for button in at.button if button.label == "Open case")
    first.click().run()
    assert not at.exception
    assert at.session_state.active_case_id
    assert any("Back to queue" in button.label for button in at.button)


def test_notes_and_checklist_persist_across_rerun() -> None:
    at = _queue()
    case_id = run_pipeline().risk_ranked[0].incident.incident_id
    at.session_state.active_case_id = case_id
    at.run()
    notes = at.text_area(key=f"notes-{case_id}")
    notes.set_value("handoff: isolate after backup confirm").run()
    saver = next(button for button in at.button if button.label == "Save notes")
    saver.click().run()
    assert at.session_state.cases[case_id]["notes"] == "handoff: isolate after backup confirm"
    boxes = [box for box in at.checkbox if box.key and str(box.key).startswith(f"act-{case_id}-")]
    assert boxes
    boxes[0].check().run()
    assert at.session_state.cases[case_id]["done"]
    at.run()
    assert at.session_state.cases[case_id]["notes"] == "handoff: isolate after backup confirm"
    assert at.session_state.cases[case_id]["done"]


def test_false_positive_close_requires_reason() -> None:
    at = _queue()
    case_id = run_pipeline().risk_ranked[0].incident.incident_id
    at.session_state.active_case_id = case_id
    at.run()
    labels = [button.label for button in at.button]
    assert "Close as false positive" in labels
    assert "Destructive" not in " ".join(str(item.value) for item in at.markdown)
    closer = next(button for button in at.button if button.label == "Close as false positive")
    closer.click().run()
    assert at.session_state.cases[case_id]["status"] == "New"
    at.text_area(key=f"fp-reason-{case_id}").set_value("duplicate of sanctioned backup job").run()
    closer = next(button for button in at.button if button.label == "Close as false positive")
    closer.click().run()
    assert at.session_state.cases[case_id]["status"] == "Closed — false positive"


def test_deep_link_opens_named_case() -> None:
    case_id = run_pipeline().risk_ranked[0].incident.incident_id
    at = _app()
    at.query_params["case"] = case_id
    at.switch_page("console/pages/queue.py").run()
    assert not at.exception
    assert at.session_state.active_case_id == case_id
    assert any("Back to queue" in button.label for button in at.button)


def test_investigate_records_session_history() -> None:
    at = _queue()
    case_id = run_pipeline().risk_ranked[0].incident.incident_id
    at.session_state.active_case_id = case_id
    at.run()
    next(button for button in at.button if button.label == "Investigate").click().run()
    history = at.session_state.cases[case_id]["history"]
    assert history
    assert history[0]["actor"] == "You"
    assert history[0]["field"] in {"status", "owner"}
    assert at.session_state.cases[case_id]["status"] == "Investigating"


def test_intelligence_uses_volume_not_fatigue_copy() -> None:
    at = _intel()
    blob = " ".join(str(item.value) for item in list(at.markdown) + list(at.caption) + list(at.title))
    assert "fewer items to review" in blob.lower()
    assert "alert fatigue reduction" not in blob.lower()
    assert "Why the legacy SIEM got this wrong" not in blob
    assert "AI rank vs legacy rank" in blob
    assert "Significant rank changes" in blob
    assert "zn-heading" in blob
