"""Deterministic SOC incident triage engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine.pipeline import PipelineResult, run_pipeline

__all__ = ["PipelineResult", "run_pipeline"]


def __getattr__(name: str):
    if name in {"PipelineResult", "run_pipeline"}:
        from engine.pipeline import PipelineResult, run_pipeline

        return PipelineResult if name == "PipelineResult" else run_pipeline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
