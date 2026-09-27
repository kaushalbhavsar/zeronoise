#!/usr/bin/env python3
"""Generate a hackathon/demo PowerPoint from README.md content."""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "ZeroNoise_README_Deck.pptx"

# Dark SOC palette (not purple-on-white)
BG = RGBColor(0x0A, 0x12, 0x20)
PANEL = RGBColor(0x12, 0x1A, 0x2A)
ACCENT = RGBColor(0x3B, 0x82, 0xF6)
TEXT = RGBColor(0xE8, 0xEE, 0xF7)
MUTED = RGBColor(0x93, 0xA4, 0xBB)
DANGER = RGBColor(0xFF, 0x8A, 0x8A)
OK = RGBColor(0x8E, 0xE0, 0xA8)
WARN = RGBColor(0xF3, 0xD2, 0x7A)


def _set_slide_bg(slide, color: RGBColor) -> None:
    fill = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5)
    )
    fill.fill.solid()
    fill.fill.fore_color.rgb = color
    fill.line.fill.background()
    # Send to back
    spTree = slide.shapes._spTree
    sp = fill._element
    spTree.remove(sp)
    spTree.insert(2, sp)


def _add_text(
    slide,
    left,
    top,
    width,
    height,
    text: str,
    *,
    size: int = 18,
    bold: bool = False,
    color: RGBColor = TEXT,
    align=PP_ALIGN.LEFT,
) -> None:
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    run.font.name = "Calibri"


def _bullets(
    slide,
    left,
    top,
    width,
    height,
    items: list[str],
    *,
    size: int = 16,
    color: RGBColor = TEXT,
) -> None:
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = PP_ALIGN.LEFT
        p.level = 0
        p.space_after = Pt(8)
        run = p.add_run()
        run.text = f"•  {item}"
        run.font.size = Pt(size)
        run.font.color.rgb = color
        run.font.name = "Calibri"


def _kicker(slide, text: str) -> None:
    _add_text(
        slide,
        Inches(0.7),
        Inches(0.35),
        Inches(12),
        Inches(0.35),
        text.upper(),
        size=12,
        bold=True,
        color=MUTED,
    )


def _title(slide, text: str, top: float = 0.7) -> None:
    _add_text(
        slide,
        Inches(0.7),
        Inches(top),
        Inches(12),
        Inches(0.7),
        text,
        size=32,
        bold=True,
        color=TEXT,
    )


def _card(slide, left, top, width, height, color: RGBColor = PANEL) -> None:
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()
    shape.adjustments[0] = 0.08


def build() -> Path:
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]

    # 1 Title
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _add_text(s, Inches(0.7), Inches(2.0), Inches(12), Inches(0.4), "ZERONOISE", size=14, bold=True, color=ACCENT)
    _add_text(s, Inches(0.7), Inches(2.5), Inches(12), Inches(1.2), "AI-driven, risk-based\nSOC incident triage", size=40, bold=True, color=TEXT)
    _add_text(
        s,
        Inches(0.7),
        Inches(5.0),
        Inches(11),
        Inches(1.0),
        "Stop ranking work by vendor severity and raw alert volume.\nContext, correlation, attack progression, and business impact outweigh noise.",
        size=18,
        color=MUTED,
    )
    _add_text(s, Inches(0.7), Inches(6.7), Inches(11), Inches(0.35), "From README · Demo deck · Offline / deterministic core", size=12, color=MUTED)

    # 2 Problem
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "The problem")
    _title(s, "Severity × volume gets triage wrong")
    _card(s, Inches(0.7), Inches(1.8), Inches(5.7), Inches(4.2))
    _add_text(s, Inches(1.0), Inches(2.1), Inches(5.2), Inches(0.4), "Noisy scanner", size=20, bold=True, color=DANGER)
    _bullets(
        s,
        Inches(1.0),
        Inches(2.7),
        Inches(5.2),
        Inches(3.0),
        [
            "Hundreds of Critical WAF/IDS alerts",
            "Sandbox host, public data, crit-1",
            "High false-positive rule (FPR 0.85)",
            "Looks urgent in a legacy SIEM queue",
        ],
        size=16,
    )
    _card(s, Inches(6.9), Inches(1.8), Inches(5.7), Inches(4.2))
    _add_text(s, Inches(7.2), Inches(2.1), Inches(5.2), Inches(0.4), "Quiet real breach", size=20, bold=True, color=OK)
    _bullets(
        s,
        Inches(7.2),
        Inches(2.7),
        Inches(5.2),
        Inches(3.0),
        [
            "A handful of Medium alerts",
            "Walks the ATT&CK kill chain",
            "Hits crown-jewel / production assets",
            "Buried under Critical volume",
        ],
        size=16,
    )

    # 3 Proof table
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "What it proves · seed 42 · ~300 alerts / 24h")
    _title(s, "Same alerts. Different triage.")
    headers = ["Queue", "Rank 1", "Rank 2", "WAF sandbox (120 Critical)"]
    rows = [
        ["Legacy SIEM\n(severity × volume)", "Scanner on\ndev-sandbox-04", "Ransomware staging", "#1"],
        ["ZeroNoise\n(risk-based)", "6-stage Impact on\nwrk-corp-14 (88.3)", "Crown-jewel exfil\n(80.8)", "#3 (30.9)"],
    ]
    col_w = [2.8, 3.4, 3.4, 2.8]
    x0, y0 = 0.7, 1.9
    # header row
    x = x0
    for i, h in enumerate(headers):
        _card(s, Inches(x), Inches(y0), Inches(col_w[i] - 0.1), Inches(0.7), RGBColor(0x16, 0x20, 0x33))
        _add_text(s, Inches(x + 0.15), Inches(y0 + 0.18), Inches(col_w[i] - 0.3), Inches(0.45), h, size=13, bold=True, color=MUTED)
        x += col_w[i]
    for r_i, row in enumerate(rows):
        x = x0
        y = y0 + 0.85 + r_i * 1.55
        for i, cell in enumerate(row):
            color = PANEL
            tc = TEXT
            if i == 3 and r_i == 0:
                tc = DANGER
            if i == 3 and r_i == 1:
                tc = OK
            _card(s, Inches(x), Inches(y), Inches(col_w[i] - 0.1), Inches(1.4), color)
            _add_text(s, Inches(x + 0.15), Inches(y + 0.25), Inches(col_w[i] - 0.3), Inches(1.0), cell, size=14, bold=(i == 0 or i == 3), color=tc)
            x += col_w[i]
    _add_text(
        s,
        Inches(0.7),
        Inches(6.5),
        Inches(12),
        Inches(0.5),
        "Ranks come from RawRisk = B × K × C (ZN-RISK-1.0) — not scenario_id.",
        size=14,
        color=MUTED,
    )

    # 4 Product idea
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "Product idea")
    _title(s, "Raw alerts are noisy. Incidents are the work.")
    _bullets(
        s,
        Inches(0.7),
        Inches(1.9),
        Inches(12),
        Inches(4.5),
        [
            "Deduplicate and correlate alerts into analyst-relevant incidents",
            "Score by fidelity (B), kill-chain progression (K), and blast radius (C)",
            "Surface rank movement vs legacy SIEM (↑ / ↓)",
            "Show alert compression (e.g. 120 → 3) without implying low risk",
            "Explain every rank from incident facts only",
        ],
        size=20,
    )

    # 5 Architecture
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "Architecture")
    _title(s, "Deterministic offline pipeline")
    steps = [
        ("Ingest", "JSONL alerts\n+ CMDB + IAM"),
        ("Normalize", "Enrich &\ndeduplicate"),
        ("Correlate", "Entity + time\ngraph"),
        ("Score", "B × K × C\nZN-RISK-1.0"),
        ("Explain", "Cards &\nrank delta"),
        ("Console", "Streamlit\nSOC workspaces"),
    ]
    for i, (title, body) in enumerate(steps):
        x = 0.55 + i * 2.1
        _card(s, Inches(x), Inches(2.2), Inches(1.95), Inches(2.6))
        _add_text(s, Inches(x + 0.12), Inches(2.45), Inches(1.7), Inches(0.5), f"{i+1}. {title}", size=14, bold=True, color=ACCENT)
        _add_text(s, Inches(x + 0.12), Inches(3.2), Inches(1.7), Inches(1.3), body, size=14, color=TEXT)
        if i < len(steps) - 1:
            _add_text(s, Inches(x + 1.85), Inches(3.2), Inches(0.3), Inches(0.4), "›", size=22, bold=True, color=MUTED)
    _add_text(
        s,
        Inches(0.7),
        Inches(5.3),
        Inches(12),
        Inches(1.2),
        "Logic lives in engine/risk_scorer.py. Parameters live in config/risk-model.yaml.\n"
        "scenario_id grades the demo only — the correlator and scorer never read it.\n"
        "LLM (optional) may rewrite prose only; it cannot change scores or ranks.",
        size=15,
        color=MUTED,
    )

    # 6 Formula
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "Risk model · ZN-RISK-1.0")
    _title(s, "RawRisk = B × K × C")
    cards = [
        ("B · Fidelity", "Severity × confidence × FP dampening\nUnique (rule, tactic) only\nLog volume — not alert spam"),
        ("K · Progression", "Extra ATT&CK stages\nExtra sensors\nExfil / Impact completion bonus"),
        ("C · Blast radius", "Highest-risk asset (env/data/crit)\nHighest-risk identity privilege\nBusiness context, not volume"),
    ]
    for i, (t, b) in enumerate(cards):
        x = 0.7 + i * 4.1
        _card(s, Inches(x), Inches(1.9), Inches(3.9), Inches(2.8))
        _add_text(s, Inches(x + 0.25), Inches(2.15), Inches(3.4), Inches(0.45), t, size=18, bold=True, color=ACCENT)
        _add_text(s, Inches(x + 0.25), Inches(2.75), Inches(3.4), Inches(1.7), b, size=15, color=TEXT)
    _add_text(
        s,
        Inches(0.7),
        Inches(5.1),
        Inches(12),
        Inches(1.5),
        "risk_score = 100 × (1 − exp(−RawRisk / 45))\n"
        "Scored on correlated incidents — never on raw SIEM rows.\n"
        "Expert-defined prototype parameters · not machine-learned · not production-calibrated yet.",
        size=16,
        color=MUTED,
    )

    # 7 Demo scenarios
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "Mandatory scenarios")
    _title(s, "Three stories every demo must show")
    scenarios = [
        ("A  Quiet crown jewel", "4 Medium · ~90 min\nVPN → creds → pivot → exfil\nprd-billing-db-01\nRisk #2 · legacy buried", WARN),
        ("B  Ransomware staging", "6 Medium/High\nPhish → LSASS → shadow-copy\nwrk-corp-14\nRisk #1", OK),
        ("C  Noisy WAF flood", "120 Critical\nCVE-2024-21762 on sandbox\ndev-sandbox-04\nLegacy #1 · Risk #3", DANGER),
    ]
    for i, (t, b, c) in enumerate(scenarios):
        x = 0.7 + i * 4.1
        _card(s, Inches(x), Inches(1.9), Inches(3.9), Inches(4.0))
        _add_text(s, Inches(x + 0.25), Inches(2.15), Inches(3.4), Inches(0.7), t, size=18, bold=True, color=c)
        _add_text(s, Inches(x + 0.25), Inches(3.0), Inches(3.4), Inches(2.6), b, size=15, color=TEXT)

    # 8 Console
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "Analyst experience")
    _title(s, "Dense SOC queue + case workspace")
    _bullets(
        s,
        Inches(0.7),
        Inches(1.9),
        Inches(12),
        Inches(4.8),
        [
            "Incident strips: PRI · RISK · RANK Δ · incident · asset · stage · age · sensors · alerts · status · owner",
            "Scan 10–15 incidents without scrolling; click a strip to open the case",
            "Toggle ZeroNoise vs Legacy SIEM ranking on the same board",
            "Three workspaces: Security overview · Incident queue · Detection intelligence",
            "OpenSIEM Lite foil (python legacy_siem/app.py) shows severity × volume on the same JSONL",
            "Export decision-first Markdown/PDF; presentation mode masks identifiers",
        ],
        size=18,
    )

    # 9 Explainability
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "Trust")
    _title(s, "Every card answers six questions")
    qs = [
        ("What happened?", "executive_summary"),
        ("Why ranked here?", "why_prioritized"),
        ("Why this ranks high", "contrastive_explanation"),
        ("Why maybe real?", "why_not_false_positive"),
        ("How did it evolve?", "attack_timeline"),
        ("What next?", "recommended_actions"),
    ]
    for i, (q, f) in enumerate(qs):
        row, col = divmod(i, 3)
        x = 0.7 + col * 4.1
        y = 1.9 + row * 2.2
        _card(s, Inches(x), Inches(y), Inches(3.9), Inches(1.9))
        _add_text(s, Inches(x + 0.25), Inches(y + 0.35), Inches(3.4), Inches(0.6), q, size=18, bold=True, color=TEXT)
        _add_text(s, Inches(x + 0.25), Inches(y + 1.05), Inches(3.4), Inches(0.5), f, size=14, color=MUTED)

    # 10 Quick start
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _kicker(s, "Quick start · Python 3.12+")
    _title(s, "Run the demo in minutes")
    _card(s, Inches(0.7), Inches(1.9), Inches(12), Inches(3.6))
    cmds = (
        "python -m venv .venv && source .venv/bin/activate\n"
        "pip install -r requirements.txt\n"
        "python data/generate_synthetic_data.py\n"
        "pytest -q\n"
        "streamlit run app.py\n"
        "python legacy_siem/app.py   # optional legacy foil on :8502"
    )
    _add_text(s, Inches(1.1), Inches(2.3), Inches(11.2), Inches(3.0), cmds, size=18, color=OK)
    _add_text(
        s,
        Inches(0.7),
        Inches(5.8),
        Inches(12),
        Inches(0.8),
        "Same seed → same ranks, scores, attribution, and config hash every run.",
        size=16,
        color=MUTED,
    )

    # 11 Close
    s = prs.slides.add_slide(blank)
    _set_slide_bg(s, BG)
    _add_text(s, Inches(0.7), Inches(2.3), Inches(12), Inches(0.4), "ONE-LINE TAKEAWAY", size=12, bold=True, color=ACCENT)
    _add_text(
        s,
        Inches(0.7),
        Inches(2.9),
        Inches(12),
        Inches(1.8),
        "Severity × volume ranked the scanner first.\nRisk × progression × blast ranked the real breach first.",
        size=28,
        bold=True,
        color=TEXT,
    )
    _add_text(
        s,
        Inches(0.7),
        Inches(5.3),
        Inches(12),
        Inches(1.0),
        "ZeroNoise · offline deterministic triage · ZN-RISK-1.0\nGenerated from README.md",
        size=14,
        color=MUTED,
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUT)
    return OUT


if __name__ == "__main__":
    path = build()
    print(f"Wrote {path}")
