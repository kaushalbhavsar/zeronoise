"""Case file export. Markdown is the source document; PDF is the same text."""

from __future__ import annotations

import io
import re
import textwrap
from datetime import datetime, timezone

from config import KILL_CHAIN
from console.common import fmt_age, fmt_day, fmt_ts, priority
from engine.presentation import (
    ACTION_GROUPS,
    context_badges,
    driver_label,
    driver_rows,
    evidence_summary,
    group_recommended_actions,
    incident_roles,
    link_evidence,
    mask_identifier,
    mask_text,
    next_recommended_action,
    observable_evidence,
    parse_timeline_line,
    role_tokens,
    vendor_severity,
    why_this_matters,
)
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
) -> str:
    """One document covering the decision brief and investigation facts."""
    roles = incident_roles(item)
    facts = observable_evidence(item)
    pri = priority(item.risk.risk_score)
    status = record.get("status") or "New"
    owner = record.get("assignee") or "Unassigned"
    lines = [
        f"# {_shown(item.title, item, mask)}",
        "",
        f"- Incident ID: `{_shown(item.incident.incident_id, item, mask)}`",
        f"- Priority: {pri} (from risk score; P0 >= 85, P1 >= 70)",
        f"- Status: {status}",
        f"- Owner: {owner}",
        f"- Risk score: {item.risk.risk_score:.1f} (not vendor severity, not confidence)",
        f"- Vendor severity: {vendor_severity(item)}",
        f"- Age: {fmt_age(item.incident.first_seen, now)}",
        f"- First seen: {fmt_day(item.incident.first_seen)}",
        f"- Last seen: {fmt_day(item.incident.last_seen)}",
        f"- AI rank: #{item.risk_rank or '—'} · Legacy rank: #{item.naive_siem_rank or '—'}",
        f"- Context: {', '.join(context_badges(item)) or '—'}",
        "",
        "## Incident context",
        "",
        f"- Initial identity: {_shown(roles['initial_identity'], item, mask)}",
        f"- Privileged identity: {_shown(roles['privileged_identity'], item, mask)}",
        f"- Source host: {_shown(roles['source_host'], item, mask)}",
        f"- Affected destination: {_shown(roles['destination'], item, mask)}",
        f"- Title asset (same as queue): {_shown(roles['affected_asset'], item, mask)}",
        "",
        "## Decision brief",
        "",
        "### What happened?",
        "",
        _shown(card.executive_summary, item, mask),
        "",
        "### What is exposed?",
        "",
        f"Initial identity {_shown(roles['initial_identity'], item, mask)}; "
        f"privileged identity {_shown(roles['privileged_identity'], item, mask)}; "
        f"source host {_shown(roles['source_host'], item, mask)}; "
        f"destination {_shown(roles['destination'], item, mask)}.",
        "",
        "### Why does this matter?",
        "",
        _shown(why_this_matters(item), item, mask),
        "",
        "### What evidence supports the assessment?",
        "",
        _shown(evidence_summary(item), item, mask),
        "",
        "### What should happen next?",
        "",
        _shown(next_recommended_action(card), item, mask),
        "",
    ]
    if card.why_not_false_positive:
        lines.extend(
            ["Uncertainty:", "", _shown(card.why_not_false_positive, item, mask), ""]
        )
    if card.contrastive_explanation or card.contrastive:
        lines.extend(
            [
                "### Why this ranks high",
                "",
                _shown(card.contrastive_explanation or card.contrastive, item, mask),
                "",
            ]
        )

    lines.extend(["## Chronology", ""])
    alerts_by_id = {alert.alert_id: alert for alert in item.incident.alerts}
    for line in card.attack_timeline:
        parsed = parse_timeline_line(line)
        alert = alerts_by_id.get(parsed["alert_id"])
        sensor = alert.source_product if alert else "—"
        identity = (alert.entities.user_id if alert else None) or "—"
        asset = (alert.entities.host_id if alert else None) or "—"
        lines.append(
            f"- {parsed['clock'] or '—'} · {parsed['tactic'] or 'Unmapped'} — "
            f"{_shown(parsed['detail'], item, mask)} "
            f"(sensor {sensor}; identity {_shown(identity, item, mask)}; "
            f"asset {_shown(asset, item, mask)}; "
            f"citation [{_shown(parsed['alert_id'], item, mask)}])"
        )
    if not card.attack_timeline:
        lines.append("- No timeline rows were generated for this incident.")
    lines.append("")

    present = set(card.tactics)
    observed = [name for name in KILL_CHAIN if name in present]
    lines.extend(
        [
            "## ATT&CK path",
            "",
            f"Observed path: {' -> '.join(observed) or 'none'}. "
            "Unobserved stages are listed and are not implied.",
            "",
        ]
    )
    for index, stage in enumerate(KILL_CHAIN, start=1):
        if stage in present:
            supporting = [
                alert for alert in item.incident.alerts if alert.mitre_tactic == stage
            ]
            lines.append(f"- {index:02d} {stage} · observed · {len(supporting)} supporting event(s)")
        else:
            lines.append(f"- {index:02d} {stage} · not observed")
    techniques = item.incident.unique_techniques or card.techniques
    lines.extend(["", "### MITRE techniques", ""])
    if techniques:
        lines.extend(f"- {technique}" for technique in techniques)
    else:
        lines.append("- No mapped techniques.")
    lines.append("")

    lines.extend(
        [
            "## Why this ranks high",
            "",
            f"Risk {item.risk.risk_score:.1f} is not vendor severity ({vendor_severity(item)}) "
            "and is not a confidence percentage.",
            "",
            item.risk.formula,
            "",
        ]
    )
    for driver in driver_rows(card):
        evidence = f" — {_shown(driver.evidence, item, mask)}" if driver.evidence else ""
        lines.append(f"- {driver_label(driver.factor)} · {driver.contribution_pct}%{evidence}")
    lines.extend(
        [
            "",
            f"fidelity_b={item.risk.fidelity_b:.3f}, progression_k={item.risk.progression_k:.3f}, "
            f"blast_c={item.risk.blast_c:.3f}, asset_risk={item.risk.asset_risk:.3f}, "
            f"identity_risk={item.risk.identity_risk:.3f}.",
            "",
            "Ablation percentages are contribution shares, not incident probability.",
            "",
        ]
    )

    recommended = card.recommended_actions or card.containment
    grouped = group_recommended_actions(recommended)
    done = set(record.get("done") or [])
    lines.extend(
        [
            "## Recommended work",
            "",
            "Checking a task records case-file progress. It does not execute infrastructure actions.",
            "",
        ]
    )
    if not recommended:
        lines.append("- No entity-specific actions were generated.")
    for group in ACTION_GROUPS:
        actions = grouped[group]
        if not actions:
            continue
        lines.append(f"### {group}")
        lines.append("")
        for action in actions:
            mark = "x" if action in done else " "
            lines.append(f"- [{mark}] {_shown(action, item, mask)}")
        lines.append("")
    if record.get("close_reason"):
        lines.extend([f"Close reason: {record['close_reason']}", ""])
    notes = (record.get("notes") or "").strip()
    lines.extend(["### Case notes", ""])
    lines.append(notes if notes else "No notes have been saved in this session.")
    lines.append("")

    lines.extend(["## Detections", ""])
    if facts["detections"]:
        for row in facts["detections"]:
            lines.append(
                f"- {row['when']} · {row['sensor']} · {_shown(row['what_was_observed'], item, mask)} "
                f"· {row['tactic']} / {row['technique']} · vendor {row['vendor_severity']} "
                f"· identity {_shown(row['identity'], item, mask)} "
                f"· host {_shown(row['host'], item, mask)} "
                f"· src {_shown(row['src_ip'], item, mask)} "
                f"· dest {_shown(row['dest_ip'], item, mask)} "
                f"· hash {_shown(row['process_hash'], item, mask)} "
                f"· {row['raw_events']} raw events "
                f"· citation [{_shown(row['alert_id'], item, mask)}]"
            )
    else:
        lines.append("- No detections were attached to this incident.")
    lines.append("")

    lines.extend(["## Why these alerts are connected", ""])
    links = link_evidence(item)
    if links:
        for row in links:
            lines.append(
                f"- {row['fact']}: {_shown(row['value'], item, mask)} "
                f"({row['event_count']} events)"
            )
        lines.append("")
        lines.append("One row per shared artifact. This is not a list of alert-id pairs.")
    else:
        lines.append("Single-alert incident — no shared identity, host, IP, or hash links.")
    lines.append("")

    if facts["gaps"] and not mask:
        lines.extend(["## Context gaps", ""])
        lines.extend(f"- {gap}" for gap in facts["gaps"])
        lines.append("")

    history = record.get("history") or []
    lines.extend(["## Session activity", ""])
    if history:
        for event in history:
            lines.append(
                f"- {event['at']} · {event['actor']} · {event['field']}: "
                f"{event['old']} -> {event['new']}"
            )
    else:
        lines.append("No case changes in this session. History is not invented.")
    lines.extend(
        [
            "",
            "## Export notes",
            "",
            f"Exported {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')} from the ZeroNoise case workspace.",
            "Historical / demo snapshot (offline JSONL + CMDB/IAM), not a live SIEM feed.",
            "Risk score is not a confidence percentage. Presentation masking, if applied, is display-only and is not access control.",
            "",
        ]
    )
    if mask:
        lines.append("Identifiers in this file are masked for screen sharing.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


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
