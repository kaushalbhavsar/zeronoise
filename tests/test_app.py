from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


def test_console_does_not_raise_duplicate_plotly_id() -> None:
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    at.run()
    assert not at.exception
    assert len(at.get("plotly_chart")) >= 1
