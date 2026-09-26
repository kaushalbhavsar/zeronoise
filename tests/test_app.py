from pathlib import Path

from streamlit.testing.v1 import AppTest

from engine.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]


def _app() -> AppTest:
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    at.run()
    assert not at.exception
    return at


def test_queue_mode_does_not_raise() -> None:
    at = _app()
    assert any("Open case" in button.label for button in at.button)
    assert not any("Back to queue" in button.label for button in at.button)


def test_opening_case_replaces_queue_with_workspace() -> None:
    at = _app()
    case_id = run_pipeline().risk_ranked[0].incident.incident_id
    at.session_state.active_case_id = case_id
    at.run()
    assert not at.exception
    labels = [button.label for button in at.button]
    assert any("Back to queue" in label for label in labels)
    assert "Open case" not in labels
    assert [tab.label for tab in at.tabs] == [
        "Overview",
        "Timeline",
        "ATT&CK",
        "Risk",
        "Response",
        "Evidence",
    ]
    assert len(at.get("plotly_chart")) >= 1


def test_back_to_queue_preserves_filters() -> None:
    at = _app()
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
    at = _app()
    first = next(button for button in at.button if button.label == "Open case")
    first.click().run()
    assert not at.exception
    assert at.session_state.active_case_id
    assert any("Back to queue" in button.label for button in at.button)
