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
.stDeployButton { display: none !important; }
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
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
  background: var(--zn-panel); min-height: 13.5rem; height: 100%;
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
.icard .id {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.78rem; color: var(--zn-muted); white-space: nowrap;
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
@media (max-width: 960px) {
  .block-container { padding: 1rem 0.85rem 1.6rem 0.85rem; }
  .zn-title, h1 { font-size: 1.55rem !important; }
  .icard { min-height: 0; }
  [data-testid="stHorizontalBlock"] { flex-wrap: wrap; }
  [data-testid="stHorizontalBlock"] > div[data-testid="stColumn"] {
    min-width: min(100%, 20rem) !important;
    flex: 1 1 20rem !important;
  }
}
</style>
"""


def inject_theme() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
