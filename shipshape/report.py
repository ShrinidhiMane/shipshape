"""Turn a scan Result into text, JSON, HTML or SARIF."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import __version__
from .model import RULES, Factor, Result, Severity

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def text(res: Result, color: bool = True, show_fix: bool = True) -> str:
    c = (lambda code: code) if color else (lambda code: "")
    lines: list[str] = []
    by_factor = {f: [x for x in res.sorted() if x.rule.factor is f] for f in Factor}
    for factor, items in by_factor.items():
        status = f"{c(DIM)}ok{c(RESET)}" if not items else f"{len(items)} finding{'s' * (len(items) != 1)}"
        lines.append(f"\n{c(BOLD)}{factor.number}. {factor.title}{c(RESET)}  {status}")
        for f in items:
            sev = f.rule.severity.label
            lines.append(f"  {c(COLORS[sev])}{sev.upper():8}{c(RESET)} {f.rule.id:7} {f.rule.title}")
            obj = "" if f.obj == f.file else f"  {f.obj}"
            lines.append(f"           {c(DIM)}{f.file}:{f.line}{obj}{c(RESET)}")
            lines.append(f"           {f.message}")
            if show_fix:
                lines.append(f"           {c(DIM)}fix: {f.rule.fix}{c(RESET)}")
    counts = "  ".join(f"{s.label}: {res.count(s)}" for s in Severity)
    lines.append(
        f"\n{c(BOLD)}Score {res.score}/100  grade {res.grade}{c(RESET)}   {counts}"
        f"   ({res.files_scanned} files, {res.objects_scanned} objects"
        f"{f', {len(res.suppressed)} suppressed' if res.suppressed else ''})"
    )
    return "\n".join(lines).lstrip("\n") + "\n"


def to_json(res: Result) -> str:
    return json.dumps(
        {
            "tool": "shipshape",
            "version": __version__,
            "score": res.score,
            "grade": res.grade,
            "counts": {s.label: res.count(s) for s in Severity},
            "files_scanned": res.files_scanned,
            "objects_scanned": res.objects_scanned,
            "findings": [f.to_dict() for f in res.sorted()],
            "suppressed": [{**f.to_dict(), "reason": why} for f, why in res.suppressed],
        },
        indent=2,
    )


def sarif(res: Result) -> str:
    """SARIF 2.1.0, so GitHub code scanning can show findings on pull requests."""
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    used = sorted({f.rule.id for f in res.findings})
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "shipshape",
                            "version": __version__,
                            "rules": [
                                {
                                    "id": rid,
                                    "shortDescription": {"text": RULES[rid].title},
                                    "help": {"text": RULES[rid].fix},
                                    "properties": {"tags": [f"factor-{RULES[rid].factor.number}", "security"]},
                                    "defaultConfiguration": {"level": level[RULES[rid].severity.label]},
                                }
                                for rid in used
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule.id,
                            "level": level[f.rule.severity.label],
                            "message": {"text": f"{f.obj}: {f.message}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file.lstrip("./")},
                                        "region": {"startLine": max(1, f.line)},
                                    }
                                }
                            ],
                        }
                        for f in res.sorted()
                    ],
                }
            ],
        },
        indent=2,
    )


def to_html(res: Result, title: str = "Shipshape report") -> str:
    e = html.escape
    when = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")
    grade_class = {"A": "g-a", "B": "g-b", "C": "g-c", "D": "g-d", "F": "g-f"}[res.grade]

    factor_cards = []
    sections = []
    for factor in Factor:
        items = [f for f in res.sorted() if f.rule.factor is factor]
        worst = max((f.rule.severity.rank for f in items), default=0)
        state = {
            0: ("pass", "No issues"),
            1: ("low", "Minor"),
            2: ("medium", "Needs work"),
            3: ("high", "Serious"),
            4: ("critical", "Critical"),
        }[worst]
        sev_counts = " · ".join(
            f"{sum(1 for f in items if f.rule.severity is s)} {s.label}"
            for s in Severity
            if any(f.rule.severity is s for f in items)
        )
        factor_cards.append(f"""
        <a class="factor {state[0]}" href="#f{factor.number}">
          <span class="fn">Factor {factor.number}</span>
          <span class="ft">{e(factor.title)}</span>
          <span class="fs">{state[1]}{(" · " + sev_counts) if items else ""}</span>
        </a>""")
        rows = "".join(
            f"""
          <tr>
            <td><span class="sev {f.rule.severity.label}">{f.rule.severity.label}</span></td>
            <td class="mono">{e(f.rule.id)}</td>
            <td><b>{e(f.rule.title)}</b><div class="msg">{e(f.message)}</div><div class="fix">Fix: {e(f.rule.fix)}</div></td>
            <td class="mono where">{"" if f.obj == f.file else e(f.obj)}<div class="loc">{e(f.file)}:{f.line}</div></td>
          </tr>"""
            for f in items
        )
        body = (
            (
                f"<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Where</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
            if items
            else '<p class="none">Nothing found for this factor.</p>'
        )
        sections.append(f"""
      <section id="f{factor.number}">
        <h2><span class="num">{factor.number}</span>{e(factor.title)}</h2>
        <p class="blurb">{e(factor.blurb)}</p>
        <div class="tw">{body}</div>
      </section>""")

    suppressed = ""
    if res.suppressed:
        srows = "".join(
            f"<tr><td class='mono'>{e(f.rule.id)}</td><td>{e(f.obj)}</td><td>{e(why)}</td></tr>"
            for f, why in res.suppressed
        )
        suppressed = f"""
      <section><h2>Suppressed on purpose</h2>
        <p class="blurb">Findings someone marked as accepted, with their reason.</p>
        <div class="tw"><table><thead><tr><th>Rule</th><th>Where</th><th>Reason</th></tr></thead>
        <tbody>{srows}</tbody></table></div></section>"""

    counts = "".join(
        f'<div class="count {s.label}"><b>{res.count(s)}</b><span>{s.label}</span></div>' for s in Severity
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --ink:#15191f; --muted:#5d6675; --line:#e2e5ea;
  --crit:#b3261e; --high:#d1452b; --med:#b26a00; --low:#2f6fb3; --ok:#1a7f37; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0e1116; --panel:#161b22; --ink:#e6edf3; --muted:#8d96a0;
  --line:#2d333b; --crit:#ff6b61; --high:#ff8a65; --med:#e3a33a; --low:#6aa8ff; --ok:#46c25a; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:28px 16px 56px; }}
.top {{ display:flex; flex-wrap:wrap; gap:20px; align-items:center; margin-bottom:22px; }}
.grade {{ width:88px; height:88px; border-radius:50%; display:grid; place-items:center; font-size:40px; font-weight:750;
  color:#fff; flex:none; }}
.g-a {{ background:var(--ok); }} .g-b {{ background:#4d8f2a; }} .g-c {{ background:var(--med); }}
.g-d {{ background:var(--high); }} .g-f {{ background:var(--crit); }}
h1 {{ margin:0; font-size:24px; letter-spacing:-.01em; }}
.sub {{ color:var(--muted); }}
.counts {{ display:flex; gap:10px; margin-left:auto; flex-wrap:wrap; }}
.count {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:8px 14px; min-width:84px; }}
.count b {{ display:block; font-size:22px; font-variant-numeric:tabular-nums; }}
.count span {{ font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); }}
.count.critical b {{ color:var(--crit); }} .count.high b {{ color:var(--high); }}
.count.medium b {{ color:var(--med); }} .count.low b {{ color:var(--low); }}
.factors {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; margin-bottom:26px; }}
.factor {{ display:flex; flex-direction:column; gap:2px; text-decoration:none; color:inherit; background:var(--panel);
  border:1px solid var(--line); border-left:5px solid var(--ok); border-radius:10px; padding:10px 12px; }}
.factor.low {{ border-left-color:var(--low); }} .factor.medium {{ border-left-color:var(--med); }}
.factor.high {{ border-left-color:var(--high); }} .factor.critical {{ border-left-color:var(--crit); }}
.fn {{ font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }}
.ft {{ font-weight:650; }} .fs {{ font-size:12px; color:var(--muted); }}
section {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px 18px; margin-bottom:14px; }}
h2 {{ font-size:16px; margin:0 0 2px; display:flex; align-items:center; gap:10px; }}
.num {{ display:inline-grid; place-items:center; width:24px; height:24px; border-radius:50%; background:var(--line); font-size:12px; }}
.blurb {{ color:var(--muted); margin:0 0 10px; }}
.none {{ color:var(--ok); margin:4px 0; }}
.tw {{ overflow-x:auto; }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ text-align:left; vertical-align:top; padding:9px 8px; border-top:1px solid var(--line); }}
th {{ font-size:12px; font-weight:500; color:var(--muted); border-top:none; }}
.mono {{ font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.where {{ max-width:300px; word-break:break-word; }}
.loc {{ color:var(--muted); }}
.msg {{ margin-top:2px; }} .fix {{ margin-top:4px; color:var(--muted); font-size:13px; }}
.sev {{ display:inline-block; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.04em;
  padding:2px 8px; border-radius:999px; color:#fff; }}
.sev.critical {{ background:var(--crit); }} .sev.high {{ background:var(--high); }}
.sev.medium {{ background:var(--med); }} .sev.low {{ background:var(--low); }}
footer {{ color:var(--muted); font-size:12px; margin-top:18px; }}
</style></head>
<body><main>
  <div class="top">
    <div class="grade {grade_class}">{res.grade}</div>
    <div>
      <h1>{e(title)}</h1>
      <div class="sub">Score {res.score}/100 · {len(res.findings)} findings · {res.files_scanned} files ·
        {res.objects_scanned} objects scanned · {e(when)}</div>
    </div>
    <div class="counts">{counts}</div>
  </div>
  <div class="factors">{"".join(factor_cards)}</div>
  {"".join(sections)}
  {suppressed}
  <footer>Shipshape {__version__}. Checks follow the five-factor model: code, images, host and container
    environment, applications in Kubernetes, and the cluster, plus logging and monitoring.</footer>
</main></body></html>
"""
