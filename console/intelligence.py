"""Detection intelligence — ranking comparison and scoring explanation."""

from __future__ import annotations

import streamlit as st

from console.common import (
    classify,
    demo_admin_controls,
    page_header,
    primary_asset,
    priority,
)
from console.state import init_session, load_result, open_case_view
from engine.presentation import (
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
    result = load_result()
    init_session(result)
    page_header(
        "Detection intelligence",
        result,
        lede="How risk ranking differs from legacy severity × volume on this snapshot.",
    )
    with st.sidebar:
        st.caption("Comparison uses the same cached pipeline result as the other workspaces.")
        demo_admin_controls()

    raw_n = result.metrics.raw_alert_count
    dedup_n = result.metrics.deduplicated_alert_count
    inc_n = result.metrics.incident_count
    high_n = result.metrics.high_priority_count

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Raw alerts", raw_n)
    c2.metric("After dedup", dedup_n)
    c3.metric("Incidents", inc_n)
    c4.metric("High-priority", high_n)
    st.caption(
        f"{review_reduction_label(raw_n, inc_n)} because {raw_n} raw alerts became {inc_n} incidents. "
        f"Dedup compression is {result.metrics.volume_compression_pct:.0f}% ({raw_n} → {dedup_n}). "
        "These are volume counts, not measured analyst-time savings."
    )

    st.subheader("AI rank vs legacy rank")
    st.caption("Significant change: absolute rank delta of 5 or more on this snapshot.")
    rows = []
    for item in result.risk_ranked:
        delta = rank_delta(item.risk_rank, item.naive_siem_rank)
        rows.append(
            {
                "Priority": priority(item.risk.risk_score),
                "Incident": item.title,
                "AI rank": item.risk_rank or "—",
                "Legacy rank": item.naive_siem_rank or "—",
                "Rank delta": rank_delta_label(delta),
                "Risk": round(item.risk.risk_score, 1),
                "Legacy score": round(item.legacy_score, 0),
                "Asset": primary_asset(item),
                "Class": classify(item),
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
    st.subheader("Significant rank changes")
    if not moved:
        st.info("No incident moved 5 or more positions between legacy and risk rank.")
    else:
        for item in moved[:8]:
            delta = rank_delta(item.risk_rank, item.naive_siem_rank)
            direction = "higher" if (delta or 0) > 0 else "lower"
            st.markdown(
                f"**{item.title}** · AI #{item.risk_rank} vs legacy #{item.naive_siem_rank} "
                f"({rank_delta_label(delta)} — ranks {direction} under risk scoring)"
            )
            card = next((c for c in result.cards if c.incident_id == item.incident.incident_id), None)
            why = (card.contrastive_explanation or card.contrastive) if card else None
            if why:
                st.write(why)
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
            f"{crown.title} moved from legacy rank #{crown.naive_siem_rank} to risk rank "
            f"#{crown.risk_rank}. The legacy ranking used severity × volume only."
        )

    left, right = st.columns(2)
    with left:
        st.subheader("Sensor coverage")
        coverage = _sensor_rows(result.risk_ranked)
        if coverage:
            st.dataframe(coverage, width="stretch", hide_index=True, key="intel-sensors")
            st.caption("Count of incidents that include at least one alert from that sensor. Not a coverage SLA.")
        else:
            st.info("No sensor labels are present on this snapshot.")
    with right:
        st.subheader("Correlation evidence")
        with_edges = sum(1 for item in result.risk_ranked if item.incident.edges)
        st.metric("Incidents with inter-alert edges", with_edges)
        st.metric("Single-alert incidents", inc_n - with_edges)
        st.caption("Edges are SHARED_HOST, SHARED_IDENTITY, attacker IP, pivots, and process hash.")

    st.subheader("How scoring works")
    st.write(
        "Risk is RawRisk = B × K × C, then mapped with a saturating curve. "
        "Contribution percentages on a case are ablation shares — they are not confidence probabilities."
    )
    with st.expander("Scoring details"):
        st.code(
            "fidelity_a = severity × confidence × (1 - 0.7 × FPR) × (1 + 0.10 × log1p(n-1))\n"
            "B = min(Σ fidelity_a over unique (rule, tactic), 35)\n"
            "K = 1 + 0.35×(tactics-1) + 0.20×(sensors-1) + 0.50×(Exfil or Impact)\n"
            "C = 0.65×asset_risk + 0.35×privilege\n"
            "risk_score = 100 × (1 − exp(−RawRisk / 45))",
            language=None,
        )
        st.caption("Variables and weights live in config.py. Ranking is deterministic for this dataset.")
