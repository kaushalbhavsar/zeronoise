#!/usr/bin/env python3
"""Minimal legacy SIEM alert queue for ZeroNoise demos.

Parses the same JSONL alert feed ZeroNoise uses and shows a basic
open-source-SIEM-style queue ranked by severity × volume (no context,
no correlation, no risk scoring).

Usage:
  python legacy_siem/app.py
  python legacy_siem/app.py --data data/sample_alerts.jsonl --port 8502
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import ALERTS_PATH, SEVERITY_WEIGHTS

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def load_alerts(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def aggregate(alerts: list[dict]) -> list[dict]:
    """Group like a basic SIEM: same rule + host + severity."""
    buckets: dict[tuple, dict] = {}
    for alert in alerts:
        host = alert.get("host_id") or "—"
        rule = alert.get("signature") or alert.get("rule_name") or "—"
        sev = alert.get("sev") or alert.get("severity_raw") or "Low"
        product = alert.get("vendor") or alert.get("source_product") or "—"
        key = (sev, host, rule, product)
        row = buckets.get(key)
        ts = parse_time(alert["time"] if "time" in alert else alert["timestamp"])
        if row is None:
            buckets[key] = {
                "severity": sev,
                "host": host,
                "rule": rule,
                "product": product,
                "count": 1,
                "first_seen": ts,
                "last_seen": ts,
                "src_ips": {alert.get("src_ip")} if alert.get("src_ip") else set(),
                "score": SEVERITY_WEIGHTS.get(sev, 1),
            }
        else:
            row["count"] += 1
            row["score"] = SEVERITY_WEIGHTS.get(sev, 1) * row["count"]
            row["first_seen"] = min(row["first_seen"], ts)
            row["last_seen"] = max(row["last_seen"], ts)
            if alert.get("src_ip"):
                row["src_ips"].add(alert["src_ip"])
    rows = list(buckets.values())
    rows.sort(
        key=lambda r: (
            -r["score"],
            SEV_ORDER.get(r["severity"], 9),
            -r["count"],
            r["host"],
            r["rule"],
        )
    )
    for idx, row in enumerate(rows, start=1):
        row["rank"] = idx
        row["src_ip"] = sorted(x for x in row["src_ips"] if x)[:1]
        row["src_ip"] = row["src_ip"][0] if row["src_ip"] else "—"
        del row["src_ips"]
    return rows


def filter_rows(rows: list[dict], *, q: str, sev: str) -> list[dict]:
    out = []
    needle = q.lower().strip()
    for row in rows:
        if sev and sev != "All" and row["severity"] != sev:
            continue
        blob = " ".join(
            [
                row["severity"],
                row["host"],
                row["rule"],
                row["product"],
                row["src_ip"],
                str(row["count"]),
            ]
        ).lower()
        if needle and needle not in blob:
            continue
        out.append(row)
    return out


def fmt_ts(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S")


def render_page(
    *,
    source: Path,
    rows: list[dict],
    total_alerts: int,
    q: str,
    sev: str,
) -> str:
    crit = sum(1 for r in rows if r["severity"] == "Critical")
    options = ["All", "Critical", "High", "Medium", "Low"]
    sev_opts = "".join(
        f'<option value="{html.escape(opt)}"{" selected" if opt == sev else ""}>'
        f"{html.escape(opt)}</option>"
        for opt in options
    )
    body_rows = []
    for row in rows:
        sev_cls = row["severity"].lower()
        body_rows.append(
            "<tr>"
            f"<td class='rank'>{row['rank']}</td>"
            f"<td><span class='sev {html.escape(sev_cls)}'>{html.escape(row['severity'])}</span></td>"
            f"<td class='num'>{row['score']}</td>"
            f"<td class='num'>{row['count']}</td>"
            f"<td class='mono'>{html.escape(row['host'])}</td>"
            f"<td>{html.escape(row['rule'])}</td>"
            f"<td>{html.escape(row['product'])}</td>"
            f"<td class='mono'>{html.escape(row['src_ip'])}</td>"
            f"<td class='mono'>{fmt_ts(row['last_seen'])}</td>"
            "</tr>"
        )
    table_body = "\n".join(body_rows) or (
        "<tr><td colspan='9' class='empty'>No alerts match the current filter.</td></tr>"
    )
    top = rows[0] if rows else None
    banner = ""
    if top and top["severity"] == "Critical" and top["count"] >= 20:
        banner = (
            "<div class='banner'>"
            f"Top queue item: <strong>{html.escape(top['rule'])}</strong> on "
            f"<span class='mono'>{html.escape(top['host'])}</span> "
            f"({top['count']} Critical · score {top['score']})"
            "</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenSIEM Lite · Alert Queue</title>
  <style>
    :root {{
      --bg: #ecefe8;
      --panel: #f7f8f4;
      --line: #c5ccb8;
      --text: #1f2a1f;
      --muted: #5c6758;
      --head: #2f3b2f;
      --crit: #8b1e1e;
      --high: #9a4b00;
      --med: #6b5a00;
      --low: #3d4a3d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font: 13px/1.35 "Lucida Grande", "Segoe UI", Tahoma, sans-serif;
      color: var(--text);
      background: var(--bg);
    }}
    header {{
      background: var(--head);
      color: #e8efe4;
      padding: 0.55rem 0.9rem;
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 1rem;
      border-bottom: 3px solid #6f8f4e;
    }}
    header .brand {{ font-weight: 700; letter-spacing: 0.02em; }}
    header .brand span {{ color: #b7d48e; font-weight: 600; }}
    header .meta {{ color: #b7c2b0; font-size: 12px; }}
    .wrap {{ padding: 0.75rem 0.9rem 1.5rem; }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem 0.85rem;
      align-items: end;
      background: var(--panel);
      border: 1px solid var(--line);
      padding: 0.55rem 0.7rem;
      margin-bottom: 0.65rem;
    }}
    label {{ display: grid; gap: 0.15rem; color: var(--muted); font-size: 11px; text-transform: uppercase; }}
    input[type=search], select {{
      min-width: 12rem;
      border: 1px solid #9aa68f;
      background: #fff;
      color: var(--text);
      padding: 0.28rem 0.4rem;
      font: inherit;
    }}
    button {{
      border: 1px solid #7d8a6f;
      background: #dfe6d4;
      color: var(--text);
      padding: 0.32rem 0.7rem;
      font: inherit;
      cursor: pointer;
    }}
    button:hover {{ background: #d0d9c2; }}
    .stats {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.85rem;
      color: var(--muted);
      margin: 0 0 0.55rem;
      font-size: 12px;
    }}
    .stats strong {{ color: var(--text); }}
    .banner {{
      background: #f3e4e4;
      border: 1px solid #d2a0a0;
      color: #5c2020;
      padding: 0.45rem 0.6rem;
      margin-bottom: 0.55rem;
      font-size: 12px;
    }}
    .note {{
      color: var(--muted);
      font-size: 11px;
      margin: 0 0 0.55rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border: 1px solid var(--line);
    }}
    thead th {{
      position: sticky;
      top: 0;
      background: #d9e0cf;
      border-bottom: 1px solid var(--line);
      text-align: left;
      padding: 0.4rem 0.45rem;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #334033;
      white-space: nowrap;
    }}
    tbody td {{
      padding: 0.38rem 0.45rem;
      border-bottom: 1px solid #e4e8dc;
      vertical-align: top;
    }}
    tbody tr:nth-child(even) {{ background: #fafbf7; }}
    tbody tr:hover {{ background: #eef3e4; }}
    .rank, .num {{ font-variant-numeric: tabular-nums; text-align: right; width: 3.2rem; }}
    .mono {{ font-family: Consolas, "Courier New", monospace; font-size: 12px; }}
    .sev {{
      display: inline-block;
      min-width: 4.4rem;
      text-align: center;
      font-size: 11px;
      font-weight: 700;
      padding: 0.1rem 0.35rem;
      border: 1px solid;
    }}
    .sev.critical {{ color: #fff; background: var(--crit); border-color: var(--crit); }}
    .sev.high {{ color: #fff; background: var(--high); border-color: var(--high); }}
    .sev.medium {{ color: #fff; background: #8a7a18; border-color: #8a7a18; }}
    .sev.low {{ color: #fff; background: #5a6a5a; border-color: #5a6a5a; }}
    .empty {{ color: var(--muted); padding: 1rem !important; }}
    footer {{
      margin-top: 0.7rem;
      color: var(--muted);
      font-size: 11px;
    }}
  </style>
</head>
<body>
  <header>
    <div class="brand">OpenSIEM Lite <span>· Alert Queue</span></div>
    <div class="meta">severity × volume · no asset context · no correlation</div>
  </header>
  <div class="wrap">
    <form class="toolbar" method="get" action="/">
      <label>Search
        <input type="search" name="q" value="{html.escape(q)}" placeholder="host, rule, IP, product" />
      </label>
      <label>Severity
        <select name="sev">{sev_opts}</select>
      </label>
      <button type="submit">Apply</button>
    </form>
    <div class="stats">
      <span><strong>{total_alerts}</strong> raw alerts</span>
      <span><strong>{len(rows)}</strong> queue groups</span>
      <span><strong>{crit}</strong> critical groups shown</span>
      <span>source <span class="mono">{html.escape(str(source))}</span></span>
    </div>
    {banner}
    <p class="note">
      Ranked by legacy score = severity weight × alert count.
      Critical=15, High=10, Medium=5, Low=2. Same feed ZeroNoise uses; different triage logic.
    </p>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Severity</th>
          <th>Score</th>
          <th>Count</th>
          <th>Host</th>
          <th>Rule</th>
          <th>Product</th>
          <th>Src IP</th>
          <th>Last</th>
        </tr>
      </thead>
      <tbody>
        {table_body}
      </tbody>
    </table>
    <footer>
      Demo foil for ZeroNoise · not a production SIEM · read-only parser over JSONL
    </footer>
  </div>
</body>
</html>
"""


def build_handler(data_path: Path):
    alerts = load_alerts(data_path)
    grouped = aggregate(alerts)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path not in {"/", "/index.html", "/queue"}:
                self.send_error(404, "Not found")
                return
            qs = parse_qs(parsed.query)
            q = (qs.get("q") or [""])[0]
            sev = (qs.get("sev") or ["All"])[0]
            rows = filter_rows(grouped, q=q, sev=sev)
            # Re-number after filter for a clean queue.
            for idx, row in enumerate(rows, start=1):
                row = dict(row)
                row["rank"] = idx
                rows[idx - 1] = row
            page = render_page(
                source=data_path,
                rows=rows,
                total_alerts=len(alerts),
                q=q,
                sev=sev,
            )
            payload = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args) -> None:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal legacy SIEM alert queue")
    parser.add_argument(
        "--data",
        type=Path,
        default=ALERTS_PATH,
        help="Path to alerts JSONL (default: data/sample_alerts.jsonl)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8502)
    args = parser.parse_args()
    if not args.data.exists():
        raise SystemExit(f"Alert file not found: {args.data}")

    handler = build_handler(args.data.resolve())
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"OpenSIEM Lite queue → http://{args.host}:{args.port}/")
    print(f"Parsing {args.data.resolve()}")
    print("Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    main()
