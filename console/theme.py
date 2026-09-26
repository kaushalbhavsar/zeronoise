"""Centralized visual system. Native Streamlit theme first; no generated-class selectors."""

from __future__ import annotations

import streamlit as st

CSS = """
<style>
:root {
  --zn-bg: #0a1220;
  --zn-panel: #121a2a;
  --zn-panel-2: #162033;
  --zn-border: #24344c;
  --zn-text: #e8eef7;
  --zn-muted: #93a4bb;
  --zn-accent: #3b82f6;
  --zn-radius: 10px;
  --zn-pad: 22px;
}
html, body, .stApp { background: var(--zn-bg); color: var(--zn-text); }
.block-container { padding: 1.35rem 1.6rem 2.2rem 1.6rem; max-width: 1480px; }
h1 { font-size: 1.9rem !important; line-height: 1.2 !important; font-weight: 650 !important; letter-spacing: -0.02em; }
h2 { font-size: 1.2rem !important; line-height: 1.3 !important; font-weight: 600 !important; }
h3 { font-size: 1.05rem !important; line-height: 1.35 !important; font-weight: 600 !important; }
p, li, .stMarkdown, [data-testid="stCaption"] { font-size: 0.95rem; }
[data-testid="stMetricLabel"] {
  color: var(--zn-muted) !important; font-size: 0.78rem !important;
  text-transform: uppercase; letter-spacing: 0.04em;
}
[data-testid="stMetricValue"] {
  color: var(--zn-text) !important;
  font-variant-numeric: tabular-nums;
  font-feature-settings: "tnum";
}
[data-testid="stSidebar"] { background: #0c1524; }
header[data-testid="stHeader"],
.stAppHeader,
[data-testid="stToolbar"],
.stAppToolbar {
  background: transparent !important;
  box-shadow: none !important;
  height: 0 !important;
  min-height: 0 !important;
  border: 0 !important;
}
[data-testid="stDecoration"] { display: none !important; }
[data-testid="stStatusWidget"],
.stDeployButton,
[data-testid="stAppDeployButton"],
.stAppDeployButton { display: none !important; }
#MainMenu, footer { visibility: hidden; display: none !important; }
iframe[title="streamlit toolbar"] { display: none !important; }
button:focus-visible, a:focus-visible, [tabindex]:focus-visible,
[data-testid="stSelectbox"] div:focus-visible,
input:focus-visible, textarea:focus-visible {
  outline: 2px solid var(--zn-accent) !important;
  outline-offset: 2px !important;
}
.zn-kicker {
  font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--zn-muted); margin: 0 0 0.35rem 0;
}
.zn-title {
  font-size: 1.9rem; font-weight: 650; letter-spacing: -0.02em;
  color: var(--zn-text); margin: 0 0 0.35rem 0; line-height: 1.2;
}
.zn-sub {
  color: var(--zn-muted); font-size: 0.95rem; margin: 0 0 1rem 0;
}
.zn-panel {
  background: var(--zn-panel); border: 1px solid var(--zn-border);
  border-radius: var(--zn-radius); padding: var(--zn-pad);
}
.zn-metric {
  background: var(--zn-panel); border: 1px solid var(--zn-border);
  border-radius: var(--zn-radius); padding: 1rem 1.1rem;
}
.zn-metric .n {
  font-size: 1.65rem; font-weight: 700; color: var(--zn-text);
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
}
.zn-metric .l {
  font-size: 0.78rem; color: var(--zn-muted); text-transform: uppercase;
  letter-spacing: 0.04em; margin-top: 0.2rem;
}
.zn-metric .h { font-size: 0.82rem; color: var(--zn-muted); margin-top: 0.35rem; }
.pri {
  display: inline-block; min-width: 2rem; text-align: center;
  font-size: 0.75rem; font-weight: 700; padding: 0.12rem 0.45rem;
  border-radius: 8px; border: 1px solid transparent; letter-spacing: 0.03em;
  font-variant-numeric: tabular-nums;
}
.p0 { background: #2a1848; color: #d6c7ff; border-color: #7c3aed; }
.p1 { background: #4a1515; color: #ff8a8a; border-color: #c43c3c; }
.p2 { background: #3a2e10; color: #f3d27a; border-color: #c4921f; }
.p3 { background: #15202c; color: #c5d2e0; border-color: #2a3b50; }
.p4 { background: #10161e; color: #8fa2b8; border-color: #1c2736; }
.badge {
  display: inline-block; font-size: 0.72rem; padding: 0.12rem 0.45rem;
  border-radius: 8px; margin: 0 0.22rem 0.22rem 0; border: 1px solid var(--zn-border);
  color: #d7e0ea; background: #162033;
}
.badge.hot { border-color: #8a3a3a; color: #ffb4b4; background: #2a1212; }
.badge.warn { border-color: #7a5a20; color: #ffd089; background: #2a2010; }
.badge.ctx { border-color: #3a4a60; color: #c5d2e0; background: #162033; }
.badge.ok { border-color: #2a4a3a; color: #b6e0c8; background: #102018; }
.delta.up { color: #8ee0a8; }
.delta.down { color: #ff9a9a; }
.icard {
  border: 1px solid var(--zn-border); border-left-width: 4px;
  border-radius: var(--zn-radius); padding: 1.15rem 1.2rem;
  background: var(--zn-panel); min-height: 0; height: 100%;
  display: flex; flex-direction: column; gap: 0.35rem;
}
.icard.pri-p0 { border-left-color: #7c3aed; }
.icard.pri-p1 { border-left-color: #c43c3c; }
.icard.pri-p2 { border-left-color: #c4921f; }
.icard.pri-p3, .icard.pri-p4 { border-left-color: #2a3b50; }
.icard.active { box-shadow: inset 0 0 0 1px var(--zn-accent); }
.icard .title {
  font-size: 1.12rem; font-weight: 650; color: var(--zn-text);
  line-height: 1.3; margin: 0.1rem 0 0.15rem 0;
}
.icard .urgency { color: var(--zn-text); font-size: 0.95rem; line-height: 1.4; flex: 1; }
.icard .meta {
  color: var(--zn-muted); font-size: 0.86rem;
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
}
.icard .id, .zn-id {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.72rem; color: var(--zn-muted); white-space: nowrap;
}
.zn-notice {
  color: #b6e0c8; font-size: 0.86rem; margin: 0.35rem 0 0.55rem 0;
}
.case-header {
  position: sticky; top: 0.35rem; z-index: 20;
  border: 1px solid var(--zn-border); border-left-width: 4px;
  border-radius: var(--zn-radius); padding: 1rem 1.15rem;
  background: #0e1726; margin: 0.2rem 0 0.9rem 0;
}
.case-header.pri-p0 { border-left-color: #7c3aed; }
.case-header.pri-p1 { border-left-color: #c43c3c; }
.case-header.pri-p2 { border-left-color: #c4921f; }
.case-header.pri-p3, .case-header.pri-p4 { border-left-color: #2a3b50; }
.case-title { font-size: 1.35rem; font-weight: 650; color: var(--zn-text); margin: 0.2rem 0; }
.case-meta { color: var(--zn-muted); font-size: 0.86rem; font-variant-numeric: tabular-nums; }
.zn-kind {
  font-size: 0.72rem; letter-spacing: 0.05em; text-transform: uppercase;
  color: var(--zn-muted); margin: 0 0 0.15rem 0;
}
.zn-heading {
  font-size: 1.2rem; font-weight: 600; color: var(--zn-text);
  letter-spacing: -0.01em; line-height: 1.3; margin: 0;
}
.zn-section { margin: 1.05rem 0 0.5rem 0; }
.brief {
  background: var(--zn-panel); border: 1px solid var(--zn-border);
  border-radius: var(--zn-radius); padding: 1.1rem 1.2rem; margin: 0 0 0.7rem 0;
}
.brief h3 { margin: 0 0 0.35rem 0; font-size: 1.05rem; }
.brief .kind { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--zn-muted); }
.tl {
  position: relative; padding-left: 1.1rem; margin: 0.2rem 0 0.9rem 0;
}
.tl::before {
  content: ""; position: absolute; left: 0.28rem; top: 0.2rem; bottom: 0.2rem;
  width: 2px; background: #2a3b50;
}
.tl-item {
  position: relative; background: var(--zn-panel); border: 1px solid var(--zn-border);
  border-radius: 8px; padding: 0.7rem 0.85rem; margin: 0 0 0.55rem 0;
}
.tl-item::before {
  content: ""; position: absolute; left: -1.02rem; top: 1rem;
  width: 10px; height: 10px; border-radius: 50%;
  background: #3b82f6; border: 2px solid #0a1220;
}
.tl-item.p0::before { background: #7c3aed; }
.tl-item.p1::before { background: #c43c3c; }
.tl-item.p2::before { background: #c4921f; }
.tl-time {
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
  color: var(--zn-muted); font-size: 0.82rem;
}
.tl-id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8rem; color: #c5d2e0; }
.kc-vert { display: flex; flex-direction: column; gap: 0.4rem; margin: 0.35rem 0 0.8rem 0; }
.kc-row {
  display: flex; align-items: center; gap: 0.75rem;
  padding: 0.55rem 0.8rem; border: 1px solid var(--zn-border);
  border-radius: 8px; background: #0e1622; color: #5d7088;
}
.kc-row.on { border-color: #3b82f6; color: #e8eef7; background: #152a4a; }
.kc-index {
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.78rem; min-width: 1.8rem; color: inherit;
}
.kc-label { flex: 1 1 auto; font-size: 0.95rem; line-height: 1.35; overflow: visible; }
.kc-state { font-size: 0.78rem; letter-spacing: 0.04em; text-transform: uppercase; white-space: nowrap; }
.rank-up { background: #102018; }
.rank-down { background: #2a1212; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }

/* Dense SOC incident board — operational strips, not cards */
.zn-board-chrome {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 1rem; flex-wrap: wrap; margin: 0.15rem 0 0.55rem 0;
}
.zn-board-chrome .title {
  font-size: 0.78rem; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--zn-muted); font-weight: 600; margin: 0;
}
.zn-board-chrome .mode {
  font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase;
  color: #c5d2e0; font-weight: 650;
}
.zn-board-chrome .mode.legacy { color: #f3d27a; }
.zn-summary-bar {
  display: flex; flex-wrap: wrap; gap: 0.35rem 1.1rem;
  padding: 0.45rem 0.15rem 0.65rem 0.15rem;
  color: var(--zn-muted); font-size: 0.82rem;
  border-bottom: 1px solid var(--zn-border); margin-bottom: 0.55rem;
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
}
.zn-summary-bar strong { color: var(--zn-text); font-weight: 650; }
.zn-board {
  border: 1px solid var(--zn-border);
  border-radius: 8px;
  background: #0c1522;
  overflow: hidden;
}
.zn-board-scroll {
  max-height: min(72vh, 920px);
  overflow: auto;
}
.zn-board-head, .zn-strip {
  display: grid;
  grid-template-columns:
    2.6rem 3.2rem 5.2rem minmax(9rem, 1.5fr) minmax(7rem, 1.1fr)
    5.4rem 3rem 6.2rem 4.6rem 6.2rem 5.4rem 1.4rem;
  gap: 0.35rem 0.55rem;
  align-items: center;
  padding: 0 0.75rem;
  column-gap: 0.55rem;
}
.zn-board-head {
  position: sticky; top: 0; z-index: 5;
  height: 2rem;
  background: #101a2a;
  border-bottom: 1px solid var(--zn-border);
  color: var(--zn-muted);
  font-size: 0.68rem; letter-spacing: 0.06em; text-transform: uppercase;
  font-weight: 600;
}
.zn-strip {
  min-height: 3.5rem; /* ~56px */
  max-height: 4.5rem; /* ~72px */
  border-bottom: 1px solid #1a2738;
  text-decoration: none; color: inherit;
  transition: background 0.12s ease;
  cursor: pointer;
}
.zn-strip:has(.zn-preview) {
  max-height: none;
}
.zn-strip:last-child { border-bottom: 0; }
.zn-strip:hover, .zn-strip:focus-visible {
  background: #152033;
  outline: none;
}
.zn-strip:focus-visible {
  box-shadow: inset 0 0 0 2px var(--zn-accent);
}
.zn-strip.active { background: #152a4a; }
.zn-strip .pri-rail {
  display: flex; align-items: center; gap: 0.25rem;
  font-size: 0.78rem; font-weight: 700; letter-spacing: 0.02em;
  font-variant-numeric: tabular-nums;
}
.zn-strip .pri-rail::before {
  content: ""; width: 3px; height: 1.55rem; border-radius: 2px;
  background: #2a3b50;
}
.zn-strip.pri-p0 .pri-rail::before { background: #c43c3c; }
.zn-strip.pri-p1 .pri-rail::before { background: #d97706; }
.zn-strip.pri-p2 .pri-rail::before { background: #a78b2a; }
.zn-strip.pri-p3 .pri-rail::before,
.zn-strip.pri-p4 .pri-rail::before { background: #3a4a60; }
.zn-strip .pri-rail.p0 { color: #ff8a8a; }
.zn-strip .pri-rail.p1 { color: #fbbf24; }
.zn-strip .pri-rail.p2 { color: #e8d48a; }
.zn-strip .pri-rail.p3, .zn-strip .pri-rail.p4 { color: #9db0c5; }
.zn-risk {
  font-size: 1.15rem; font-weight: 700; color: var(--zn-text);
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
  line-height: 1.1;
}
.zn-risk-sub {
  font-size: 0.62rem; color: var(--zn-muted); letter-spacing: 0.04em;
  text-transform: uppercase; margin-top: 0.1rem;
}
.zn-rank {
  font-size: 0.86rem; font-weight: 650; color: var(--zn-text);
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
  white-space: nowrap;
}
.zn-rank .up { color: #8ee0a8; }
.zn-rank .down { color: #ff9a9a; }
.zn-rank .flat { color: var(--zn-muted); }
.zn-inc-title {
  font-size: 0.95rem; font-weight: 650; color: var(--zn-text);
  line-height: 1.25; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.zn-inc-sub {
  font-size: 0.7rem; color: var(--zn-muted); white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; margin-top: 0.08rem;
}
.zn-asset {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.82rem; color: #d7e0ea; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis;
}
.zn-asset-tag {
  display: inline-block; margin-top: 0.12rem;
  font-size: 0.62rem; letter-spacing: 0.05em; text-transform: uppercase;
  color: var(--zn-muted); border: 1px solid #2a3b50;
  border-radius: 3px; padding: 0 0.28rem; line-height: 1.35;
}
.zn-stage {
  font-size: 0.72rem; font-weight: 700; letter-spacing: 0.05em;
  color: #d7e0ea; white-space: nowrap;
}
.zn-stage.impact, .zn-stage.exfil { color: #ffb4b4; }
.zn-stage.credential, .zn-stage.lateral { color: #f3d27a; }
.zn-age {
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
  font-size: 0.82rem; color: var(--zn-muted);
}
.zn-sensors { display: flex; flex-wrap: wrap; gap: 0.18rem; }
.zn-sensor {
  font-size: 0.62rem; letter-spacing: 0.03em; padding: 0.08rem 0.28rem;
  border: 1px solid #2a3b50; border-radius: 3px; color: #b8c7d9;
  background: #121c2c; white-space: nowrap;
}
.zn-comp {
  font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
  font-size: 0.82rem; color: #c5d2e0; white-space: nowrap;
}
.zn-status {
  display: inline-block; font-size: 0.72rem; padding: 0.12rem 0.4rem;
  border-radius: 4px; border: 1px solid #2a3b50; color: #c5d2e0;
  background: #121c2c; white-space: nowrap; max-width: 100%;
  overflow: hidden; text-overflow: ellipsis;
}
.zn-status.unassigned-adj { border-color: #5a4a20; color: #e8d48a; }
.zn-owner {
  font-size: 0.78rem; color: var(--zn-muted); white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis;
}
.zn-owner.unassigned { color: #e8d48a; }
.zn-open-affordance {
  color: var(--zn-muted); font-size: 1.1rem; text-align: right;
  opacity: 0; transition: opacity 0.12s ease;
}
.zn-strip:hover .zn-open-affordance,
.zn-strip:focus-visible .zn-open-affordance { opacity: 1; color: var(--zn-text); }
.zn-board-empty {
  padding: 1.4rem 1rem; color: var(--zn-muted); font-size: 0.92rem; text-align: left;
}
.zn-board-skeleton .zn-strip {
  pointer-events: none; opacity: 0.45;
}
.zn-board-skeleton .zn-skel {
  height: 0.7rem; border-radius: 3px; background: #1a2738;
}
.zn-preview {
  grid-column: 1 / -1;
  padding: 0.35rem 0 0.55rem 0;
  border-top: 1px dashed #24344c;
  margin-top: 0.2rem;
  font-size: 0.8rem; color: var(--zn-muted); line-height: 1.4;
}
.zn-preview strong { color: #d7e0ea; font-weight: 600; }
.zn-preview .path {
  color: #c5d2e0; font-size: 0.78rem; margin-bottom: 0.2rem;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.zn-mobile-primary, .zn-mobile-secondary { display: none; }
@media (max-width: 1200px) {
  .zn-board-head .col-owner,
  .zn-strip .col-owner,
  .zn-board-head .col-sensors,
  .zn-strip .col-sensors {
    display: none;
  }
  .zn-board-head, .zn-strip {
    grid-template-columns:
      2.6rem 3.2rem 5.2rem minmax(8rem, 1.4fr) minmax(6rem, 1fr)
      5.2rem 3rem 4.4rem 5.8rem 1.2rem;
  }
}
@media (max-width: 960px) {
  .block-container { padding: 1rem 0.85rem 1.6rem 0.85rem; }
  .zn-title, h1 { font-size: 1.55rem !important; }
  .icard { min-height: 0; }
  .case-header { position: static; }
  .case-title { font-size: 1.2rem; }
  [data-testid="stHorizontalBlock"] { flex-wrap: wrap; }
  [data-testid="stHorizontalBlock"] > div[data-testid="stColumn"] {
    min-width: min(100%, 20rem) !important;
    flex: 1 1 20rem !important;
  }
  .zn-board-head { display: none; }
  .zn-strip {
    display: flex; flex-direction: column; align-items: stretch;
    gap: 0.2rem; padding: 0.55rem 0.75rem;
    max-height: none; min-height: 0;
  }
  .zn-strip .zn-desk { display: none !important; }
  .zn-mobile-primary, .zn-mobile-secondary { display: flex; }
  .zn-mobile-primary {
    flex-wrap: wrap; align-items: baseline; gap: 0.4rem 0.65rem;
  }
  .zn-mobile-primary .zn-risk { font-size: 1rem; }
  .zn-mobile-primary .pri-rail::before { height: 1rem; }
  .zn-mobile-secondary {
    flex-wrap: wrap; gap: 0.25rem 0.5rem;
    color: var(--zn-muted); font-size: 0.78rem;
  }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation: none !important;
    transition: none !important;
    scroll-behavior: auto !important;
  }
}
</style>
"""


def inject_theme() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
