from engine.presentation import METRIC_DEFINITIONS
from console.common import apply_preset, filter_summary, priority
from console.state import OPEN_STATUSES, PRIORITIES


def test_priority_bands() -> None:
    assert priority(88) == "P0"
    assert priority(80) == "P1"
    assert priority(51) == "P2"
    assert priority(30) == "P3"
    assert priority(12) == "P4"


def test_filter_presets() -> None:
    assert apply_preset("My cases")["mine"] is True
    assert apply_preset("Unassigned critical")["unassigned_critical"] is True
    assert apply_preset("Production")["production_only"] is True
    assert apply_preset("All open")["mine"] is False


def test_filter_summary_is_compact() -> None:
    text = filter_summary(
        12,
        111,
        list(PRIORITIES),
        list(OPEN_STATUSES),
        [],
        "Production",
    )
    assert "Showing 12 of 111" in text
    assert "Production" in text
    assert "all priorities" in text


def test_metric_definitions_state_scope_and_window() -> None:
    for key in ("open", "matching", "p0_p1", "raw"):
        text = METRIC_DEFINITIONS[key]
        assert "Window" in text or "window" in text
        assert "Calculation" in text or "Calculation" in text
    assert "not the current queue filter" in METRIC_DEFINITIONS["open"]
    assert "Current queue filters only" in METRIC_DEFINITIONS["matching"]
