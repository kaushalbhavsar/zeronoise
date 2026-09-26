"""Detection intelligence — ranking comparison and scoring explanation."""

from __future__ import annotations

import streamlit as st

from console.common import (
    defined_metric,
    display,
    heading,
    human_title,
    page_header,
    primary_asset,
    render_load_error,
    session_chrome,
    priority,
)
from console.state import PAGE_QUEUE, init_session, load_result_or_error, open_case_view, presenting
from engine.presentation import (
    METRIC_DEFINITIONS,
    rank_delta,
    rank_delta_label,
    review_reduction_label,
    significant_rank_moves,
)
from engine.schemas import ScoredIncident


def _sensor_rows(items: list[ScoredIncident]) -> list[dict]:
    counts: dict[str, int] = {}
    for item in items:
        for product in item.incident.unique_products:
            counts[product] = counts.get(product, 0) + 1
    return [
        {"Sensor": name, "Incidents covering it": n}
        for name, n in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    ]


def render() -> None:
    result, error = load_result_or_error()
    if result is None:
        render_load_error(error or "Unknown load failure")
        return
    if st.query_params.get("case"):
        st.switch_page(PAGE_QUEUE)
    init_session(result)
    page_header(
        "Detection intelligence",
        result,
        lede="How risk ranking differs from legacy severity × volume on this snapshot.",
    )
    with st.sidebar:
        st.caption("Comparison uses the same cached pipeline result as the other workspaces.")
        session_chrome()

    raw_n = result.metrics.raw_alert_count
    dedup_n = result.metrics.deduplicated_alert_count
    inc_n = result.metrics.incident_count
    high_n = result.metrics.high_priority_count

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        defined_metric("raw", "Raw alerts", raw_n)
    with c2:
        defined_metric("dedup", "After dedup", dedup_n)
    with c3:
        defined_metric("incidents", "Incidents", inc_n)
    with c4:
        defined_metric("high", "High-priority", high_n)
    st.caption(
        f"{review_reduction_label(raw_n, inc_n)} ({raw_n} → {inc_n}). "
        f"Dedup {result.metrics.volume_compression_pct:.0f}% ({raw_n} → {dedup_n}). Volume, not time saved."
    )

    heading("AI rank vs legacy rank")
    rows = []
    for item in result.risk_ranked:
        delta = rank_delta(item.risk_rank, item.naive_siem_rank)
        rows.append(
            {
                "Priority": priority(item.risk.risk_score),
                "Incident": display(human_title(item), item),
                "AI rank": item.risk_rank or "—",
                "Legacy rank": item.naive_siem_rank or "—",
                "Rank delta": rank_delta_label(delta),
                "Risk": round(item.risk.risk_score, 1),
                "Legacy score": round(item.legacy_score, 0),
                "Asset": display(primary_asset(item), item),
                "_id": item.incident.incident_id,
                "_abs": abs(delta or 0),
            }
        )
    st.dataframe(
        [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows],
        width="stretch",
        hide_index=True,
        key="intel-compare",
        height=min(560, 52 + 36 * min(len(rows), 14)),
    )

    moved = significant_rank_moves(result.risk_ranked, min_abs_delta=5)
    heading("Significant rank changes")
    if not moved:
        st.info("No incident moved 5 or more positions between legacy and risk rank.")
    else:
        for item in moved[:8]:
            delta = rank_delta(item.risk_rank, item.naive_siem_rank)
            direction = "higher" if (delta or 0) > 0 else "lower"
            st.markdown(
                f"**{display(human_title(item), item)}** · AI #{item.risk_rank} vs legacy #{item.naive_siem_rank} "
                f"({rank_delta_label(delta)} — ranks {direction} under risk scoring)"
            )
            card = next((c for c in result.cards if c.incident_id == item.incident.incident_id), None)
            why = (card.contrastive_explanation or card.contrastive) if card else None
            if why:
                with st.expander("Why this ranks high", expanded=True):
                    st.write(display(why, item))
            else:
                st.caption("No contrastive explanation was generated for this pair.")
            if st.button("Open case", key=f"intel-{item.incident.incident_id}"):
                open_case_view(item.incident.incident_id, switch=True)

    crown = next(
        (
            item
            for item in result.risk_ranked
            if item.risk_rank == 2 and (item.naive_siem_rank or 0) >= 10
        ),
        None,
    )
    if crown:
        st.markdown("**Example still in this snapshot**")
        st.write(
            f"{display(human_title(crown), crown)} moved from legacy rank #{crown.naive_siem_rank} to risk rank "
            f"#{crown.risk_rank}. The legacy ranking used severity × volume only."
        )

    with st.expander("Sensor coverage, correlation, and scoring", expanded=not presenting()):
        left, right = st.columns(2)
        with left:
            heading("Sensor coverage")
            coverage = _sensor_rows(result.risk_ranked)
            if coverage:
                st.dataframe(coverage, width="stretch", hide_index=True, key="intel-sensors")
            else:
                st.info("No sensor labels are present on this snapshot.")
        with right:
            heading("Why these alerts are connected")
            with_edges = sum(1 for item in result.risk_ranked if item.incident.edges)
            defined_metric("edges", "Incidents with inter-alert edges", with_edges)
            st.metric(
                "Single-alert incidents",
                inc_n - with_edges,
                help=METRIC_DEFINITIONS["incidents"] + " This count is incidents minus those with edges.",
            )

        heading("How scoring works")
        st.write(
            "Risk is RawRisk = B × K × C, then mapped with a saturating curve. "
            "Contribution percentages on a case are ablation shares — they are not confidence probabilities."
        )
        st.code(
            "fidelity_a = severity × confidence × (1 - 0.7 × FPR) × (1 + 0.10 × log1p(n-1))\n"
            "B = min(Σ fidelity_a over unique (rule, tactic), 35)\n"
            "K = 1 + 0.35×(tactics-1) + 0.20×(sensors-1) + 0.50×(Exfil or Impact)\n"
            "C = 0.65×asset_risk + 0.35×privilege\n"
            "risk_score = 100 × (1 − exp(−RawRisk / 45))",
            language=None,
        )
        st.caption("Variables and weights live in config.py. Ranking is deterministic for this dataset.")
