"""Interactive SOC queue comparing legacy SIEM ranking with risk-based triage."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import plotly.graph_objects as go
import streamlit as st

from config import ALERTS_PATH, CMDB_PATH, IAM_PATH, RISK_WEIGHTS
from engine.pipeline import run_pipeline
from engine.schemas import IncidentCard, PipelineResult, ScoredIncident

st.set_page_config(
    page_title="ZeroNoise SOC Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .stApp { background-color: #0b1220; color: #e8eef7; }
    .block-container { padding-top: 1.2rem; }
    h1, h2, h3 { color: #f4f7fb !important; }
    [data-testid="stMetricLabel"] { color: #c5d4e8 !important; }
    [data-testid="stMetricValue"] { color: #f4f7fb !important; }
    [data-testid="stCaptionContainer"], .stCaption { color: #c5d4e8 !important; }
    .hero {
        background: linear-gradient(135deg, #132033 0%, #163024 100%);
        border: 1px solid #2a3d55;
        border-radius: 16px;
        padding: 1.15rem 1.35rem 1.05rem 1.35rem;
        margin-bottom: 1rem;
    }
    .muted { color: #c5d4e8; font-size: 0.95rem; line-height: 1.45; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner="Running deterministic triage pipeline…")
def load_result() -> PipelineResult:
    if not ALERTS_PATH.exists():
        from data.generate_synthetic_data import write_dataset

        write_dataset()
    return run_pipeline(alerts_path=ALERTS_PATH, cmdb_path=CMDB_PATH, iam_path=IAM_PATH)


def _scenario(item: ScoredIncident) -> str:
    for alert in item.incident.alerts:
        if alert.scenario_id:
            return alert.scenario_id
    return "unknown"


def _label(scenario: str) -> str:
    return {
        "quiet_crown_jewel": "Quiet crown-jewel breach",
        "ransomware_staging": "Ransomware staging",
        "noisy_false_priority": "Noisy false priority (sandbox)",
        "background_noise": "Background noise",
    }.get(scenario, scenario)


def _risk_color(score: float) -> str:
    if score >= 60:
        return "#ff6b6b"
    if score >= 40:
        return "#ffd166"
    return "#7dffa6"


def driver_chart(card: IncidentCard) -> go.Figure:
    drivers = [d for d in card.risk.drivers if d.name != "noise_discount"]
    fig = go.Figure(
        go.Bar(
            x=[d.contribution_pct for d in drivers],
            y=[d.name.replace("_", " ") for d in drivers],
            orientation="h",
            marker_color=["#5b9cff" for _ in drivers],
            text=[f"{d.contribution_pct:.1f}%" for d in drivers],
            textposition="outside",
        )
    )
    fig.update_layout(
        height=320,
        margin=dict(l=10, r=40, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf7"),
        xaxis=dict(title="Attribution % of pre-noise score", range=[0, max(40, max(d.contribution_pct for d in drivers) + 8)]),
        yaxis=dict(autorange="reversed"),
    )
    return fig


def comparison_chart(result: PipelineResult) -> go.Figure:
    risk_ids = [item.incident.incident_id for item in result.risk_ranked[:8]]
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            name="Risk score",
            x=risk_ids,
            y=[item.risk.risk_score for item in result.risk_ranked[:8]],
            marker_color="#5b9cff",
        )
    )
    # Normalize legacy into 0-100 for visual comparison only.
    legacy_by_id = {item.incident.incident_id: item.legacy_score for item in result.legacy_ranked}
    max_legacy = max(legacy_by_id.values()) or 1
    fig.add_trace(
        go.Bar(
            name="Legacy SIEM (scaled)",
            x=risk_ids,
            y=[100.0 * legacy_by_id[i] / max_legacy for i in risk_ids],
            marker_color="#ffb347",
        )
    )
    fig.update_layout(
        barmode="group",
        height=360,
        margin=dict(l=10, r=10, t=10, b=40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf7"),
        legend=dict(orientation="h"),
        yaxis=dict(title="Score (legacy scaled to 100)"),
    )
    return fig


def render_queue_table(items: list[ScoredIncident], score_attr: str) -> None:
    rows = []
    for idx, item in enumerate(items, start=1):
        score = item.risk.risk_score if score_attr == "risk" else item.legacy_score
        rows.append(
            {
                "rank": idx,
                "incident": item.incident.incident_id,
                "score": round(score, 1),
                "scenario": _label(_scenario(item)),
                "severity": item.incident.max_severity,
                "events": item.incident.total_event_count,
                "tactics": len(item.incident.unique_tactics),
                "title": item.title,
            }
        )
    st.dataframe(rows, width="stretch", hide_index=True)


def main() -> None:
    result = load_result()
    metrics = result.metrics
    cards = {card.incident_id: card for card in result.cards}

    st.markdown(
        """
        <div class="hero">
          <h1>ZeroNoise — risk-based SOC incident triage</h1>
          <p class="muted">
            Context + correlation + attack progression + business impact
            outweigh raw alert volume. The core engine is deterministic and
            fully offline. An LLM, if enabled, may only rewrite prose.
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Raw alerts", f"{metrics.raw_alert_count}")
    c2.metric("After dedup", f"{metrics.deduplicated_alert_count}")
    c3.metric("Incidents", f"{metrics.incident_count}")
    c4.metric("Fatigue reduction", f"{metrics.fatigue_reduction_pct:.1f}%")
    c5.metric(
        "Ranking inverted",
        "Yes" if metrics.ranking_inverted else "No",
    )

    st.caption(
        f"Quiet crown-jewel ranks #{metrics.quiet_crown_jewel_risk_rank} by risk "
        f"and #{metrics.quiet_crown_jewel_legacy_rank} in a legacy SIEM. "
        f"Ransomware staging ranks #{metrics.ransomware_staging_risk_rank} by risk. "
        f"Sandbox scanner ranks #{metrics.noisy_false_priority_risk_rank} by risk "
        f"and #{metrics.noisy_false_priority_legacy_rank} in a legacy SIEM."
    )

    tab_queue, tab_compare, tab_card, tab_method = st.tabs(
        ["SOC queue", "Ranking comparison", "Incident card", "Scoring model"]
    )

    with tab_queue:
        st.subheader("Prioritized analyst queue")
        st.write(
            "This is the queue a Tier-1 analyst would work. Rank is risk, not "
            "vendor severity and not raw volume."
        )
        render_queue_table(result.risk_ranked, "risk")

    with tab_compare:
        left, right = st.columns(2)
        with left:
            st.subheader("Risk-based ranking")
            render_queue_table(result.risk_ranked[:8], "risk")
        with right:
            st.subheader("Legacy SIEM ranking")
            st.caption("max(vendor severity) × 1000 + 10 × alerts + events")
            render_queue_table(result.legacy_ranked[:8], "legacy")
        st.plotly_chart(comparison_chart(result), width="stretch")
        if metrics.ranking_inverted:
            st.success(
                "The stealthy crown-jewel breach outranks the Critical sandbox "
                "scanner on risk, while the legacy queue does the opposite. "
                "That is the alert-fatigue failure mode this engine exists to fix."
            )

    with tab_card:
        options = {
            f"{idx}. [{item.risk.risk_score:.1f}] {item.incident.incident_id} — {_label(_scenario(item))}": item.incident.incident_id
            for idx, item in enumerate(result.risk_ranked, start=1)
        }
        choice = st.selectbox("Select an incident", list(options.keys()))
        incident_id = options[choice]
        card = cards[incident_id]
        scored = next(i for i in result.risk_ranked if i.incident.incident_id == incident_id)

        h1, h2, h3, h4 = st.columns(4)
        h1.metric("Risk score", f"{card.risk_score:.1f}")
        h2.metric("Risk rank", f"#{card.risk_rank}")
        h3.metric("Legacy rank", f"#{card.legacy_rank}")
        h4.metric("Raw events", f"{card.raw_event_count}")

        st.markdown(f"**{card.title}**")
        st.write(card.executive_summary)
        st.write(card.narrative)
        if card.contrastive:
            st.info(card.contrastive)

        d1, d2 = st.columns((1.1, 0.9))
        with d1:
            st.plotly_chart(driver_chart(card), width="stretch")
            st.caption(card.risk.formula)
        with d2:
            st.markdown("**Containment (evidence-bound)**")
            for action in card.containment:
                st.write(f"- {action}")
            st.markdown("**ATT&CK tactics**")
            st.write(" → ".join(card.tactics) if card.tactics else "n/a")
            st.markdown("**Entities**")
            st.write("Users: " + (", ".join(card.users) or "none"))
            st.write("Hosts: " + (", ".join(card.hosts) or "none"))
            st.caption(
                f"Explanation source: {card.explanation_source}. "
                "LLM enhancement does not change scores or attribution."
            )

        with st.expander("Driver evidence and member alerts"):
            for driver in card.risk.drivers:
                st.markdown(
                    f"**{driver.name}** — score {driver.score:.3f}, "
                    f"weight {driver.weight:.2f}, "
                    f"attribution {driver.contribution_pct:.2f}%"
                )
                for line in driver.evidence:
                    st.write(f"- {line}")
            st.markdown("**Deduplicated alert IDs**")
            st.code("\n".join(card.alert_ids))
            st.markdown("**Timeline**")
            timeline = [
                {
                    "time": alert.timestamp.isoformat(),
                    "id": alert.alert_id,
                    "product": alert.source_product,
                    "severity": alert.severity_raw,
                    "tactic": alert.mitre_tactic,
                    "rule": alert.rule_name,
                    "events": alert.event_count,
                }
                for alert in scored.incident.alerts
            ]
            st.dataframe(timeline, width="stretch", hide_index=True)

    with tab_method:
        st.subheader("Why this is not a black box")
        st.write(
            "Every incident score is a weighted sum of six bounded components, "
            "then a noise discount that can only reduce the result. The same "
            "dataset and config always produce the same ranks."
        )
        st.code(
            "risk = 100 * Σ(w_i * s_i) * (1 - 0.45 * noise)\n"
            "contribution_pct_i = 100 * (w_i * s_i) / Σ(w_j * s_j)",
            language="text",
        )
        st.dataframe(
            [
                {"driver": name.replace("_", " "), "weight": weight}
                for name, weight in RISK_WEIGHTS.items()
            ],
            width="stretch",
            hide_index=True,
        )
        st.markdown(
            """
- **Business impact** — production, crown-jewel / PCI, criticality beat sandbox/public.
- **Identity privilege** — tier-0 domain admin outranks a standard user.
- **Attack progression** — unique ATT&CK tactics, late-stage presence, kill-chain span, multi-sensor corroboration.
- **Signal quality** — confidence × (1 − false-positive rate), boosted by product/technique diversity.
- **Blast radius** — distinct hosts and identities.
- **Severity residual** — vendor severity is kept, but only at 6% weight.
- **Noise discount** — bursty, high-FPR, single-stage piles (scanners) lose up to 45% of the raw score.
            """
        )
        st.warning(
            "`scenario_id` exists only so this demo can be graded. "
            "The correlator and risk scorer never read it."
        )


if __name__ == "__main__":
    main()
