"""Case file export. Markdown is the source document; PDF is the same text."""

from __future__ import annotations

import io
import re
import textwrap
from datetime import datetime

from engine.incident_report import build_incident_report, render_report_markdown
from engine.presentation import mask_identifier, mask_text, role_tokens
from engine.schemas import IncidentCard, ScoredIncident

_PDF_REPLACEMENTS = str.maketrans(
    {
        "—": "-",
        "–": "-",
        "×": "x",
        "→": "->",
        "≥": ">=",
        "≤": "<=",
        "•": "*",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "…": "...",
    }
)


def _shown(value: object, item: ScoredIncident, mask: bool) -> str:
    text = "—" if value is None else str(value)
    if not mask:
        return text
    tokens = role_tokens(item)
    return mask_text(text, tokens, True) if tokens else mask_identifier(text)


def export_filenames(item: ScoredIncident, *, mask: bool) -> dict[str, str]:
    ident = _shown(item.incident.incident_id, item, mask)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", ident).strip("-") or "case"
    return {"md": f"zeronoise-{safe}.md", "pdf": f"zeronoise-{safe}.pdf"}


def case_markdown(
    item: ScoredIncident,
    card: IncidentCard,
    record: dict,
    now: datetime,
    *,
    mask: bool = False,
    peers: list[ScoredIncident] | None = None,
) -> str:
    """Decision-first SOC incident report. PDF is the same Markdown."""
    report = build_incident_report(item, card, record, now, mask=mask, peers=peers)
    return render_report_markdown(report)


def _pdf_latin1(text: str) -> str:
    cleaned = text.translate(_PDF_REPLACEMENTS)
    return cleaned.encode("latin-1", "replace").decode("latin-1")


def _pdf_escape(text: str) -> str:
    return (
        _pdf_latin1(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def case_pdf(markdown: str) -> bytes:
    """Readable multi-page PDF of the Markdown case file. No extra library."""
    page_w, page_h = 595.28, 841.89
    left, bottom, top = 50.0, 50.0, 56.0
    usable = page_w - left - 50.0
    pages: list[list[tuple[float, float, str, float, bool]]] = []
    y = page_h - top
    current: list[tuple[float, float, str, float, bool]] = []

    def new_page() -> None:
        nonlocal y, current
        if current:
            pages.append(current)
        current = []
        y = page_h - top

    def add_line(text: str, size: float, bold: bool) -> None:
        nonlocal y
        leading = size + 5.0
        if y - leading < bottom:
            new_page()
        current.append((left, y, text, size, bold))
        y -= leading

    def wrap_line(text: str, size: float) -> list[str]:
        width = max(24, int(usable / (size * 0.5)))
        return textwrap.wrap(text, width=width, break_long_words=True) or [""]

    for raw in markdown.splitlines():
        line = raw.rstrip()
        if not line:
            y -= 6
            if y < bottom:
                new_page()
            continue
        if line.startswith("# "):
            y -= 8
            for part in wrap_line(line[2:], 16):
                add_line(part, 16, True)
        elif line.startswith("## "):
            y -= 10
            for part in wrap_line(line[3:], 13):
                add_line(part, 13, True)
        elif line.startswith("### "):
            y -= 6
            for part in wrap_line(line[4:], 12):
                add_line(part, 12, True)
        elif line.startswith("- "):
            for index, part in enumerate(wrap_line(line[2:], 10)):
                prefix = "* " if index == 0 else "  "
                add_line(prefix + part, 10, False)
        else:
            for part in wrap_line(line, 10):
                add_line(part, 10, False)
    if current or not pages:
        pages.append(current)

    objects: list[bytes] = []

    def add_obj(body: str | bytes) -> int:
        payload = body.encode("latin-1") if isinstance(body, str) else body
        objects.append(payload)
        return len(objects)

    font_reg = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    font_bold = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    content_ids: list[int] = []
    page_ids: list[int] = []
    for page in pages:
        commands = ["BT"]
        last_size = None
        last_bold = None
        for x, y, text, size, bold in page:
            font = "F2" if bold else "F1"
            if last_size != size or last_bold != bold:
                commands.append(f"/{font} {size:.1f} Tf")
                last_size = size
                last_bold = bold
            commands.append(f"1 0 0 1 {x:.2f} {y:.2f} Tm")
            commands.append(f"({_pdf_escape(text)}) Tj")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1")
        content = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        content_ids.append(add_obj(content))
        page_ids.append(0)

    pages_id = len(objects) + len(page_ids) + 1
    catalog_id = pages_id + 1
    for index, content_id in enumerate(content_ids):
        page_obj = (
            f"<< /Type /Page /Parent {pages_id} 0 R "
            f"/MediaBox [0 0 {page_w:.2f} {page_h:.2f}] "
            f"/Contents {content_id} 0 R "
            f"/Resources << /Font << /F1 {font_reg} 0 R /F2 {font_bold} 0 R >> >> >>"
        )
        page_ids[index] = add_obj(page_obj)
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    add_obj(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>")
    add_obj(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(buf.tell())
        buf.write(f"{index} 0 obj\n".encode("latin-1"))
        buf.write(payload)
        buf.write(b"\nendobj\n")
    xref_at = buf.tell()
    buf.write(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    buf.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buf.write(f"{offset:010d} 00000 n \n".encode("latin-1"))
    buf.write(
        (
            f"trailer << /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n"
        ).encode("latin-1")
    )
    return buf.getvalue()
