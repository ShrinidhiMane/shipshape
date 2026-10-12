"""Command line:

shipshape scan PATH [PATH ...]           scan folders/files ("-" reads YAML from stdin)
    --format text|json|html|sarif        output format (default: text)
    --output FILE                        write the report to a file
    --fail-on critical|high|medium|low   exit 1 if any finding is this bad or worse (for CI)
    --min-severity LEVEL                 hide findings below this level
    --trusted-registry HOST              allowed image registry (repeatable)
    --no-source                          skip the secret scan of source files
shipshape rules                          list every rule
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, report
from .model import RULES, Factor, Severity
from .scanner import scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="shipshape", description="Security checks for Dockerfiles and Kubernetes manifests."
    )
    p.add_argument("--version", action="version", version=f"shipshape {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files or folders")
    s.add_argument("paths", nargs="+")
    s.add_argument("--format", choices=["text", "json", "html", "sarif"], default="text")
    s.add_argument("--output", "-o")
    s.add_argument("--fail-on", choices=[x.label for x in Severity])
    s.add_argument("--min-severity", choices=[x.label for x in Severity], default="low")
    s.add_argument("--trusted-registry", action="append", default=[])
    s.add_argument("--no-source", action="store_true", help="don't scan source files for secrets")
    s.add_argument("--title", default="Shipshape report")

    sub.add_parser("rules", help="list all rules")
    args = p.parse_args(argv)

    if args.cmd == "rules":
        for factor in Factor:
            print(f"\n{factor.number}. {factor.title}")
            for r in RULES.values():
                if r.factor is factor:
                    print(f"   {r.id:8} {r.severity.label:9} {r.title}")
        return 0

    res, errors = scan(
        args.paths,
        trusted=args.trusted_registry,
        scan_source=not args.no_source,
        min_severity=Severity.parse(args.min_severity),
    )
    for err in errors:
        print(f"warning: {err}", file=sys.stderr)

    to_tty = args.output is None and sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    out = {
        "text": lambda: report.text(res, color=to_tty),
        "json": lambda: report.to_json(res),
        "html": lambda: report.to_html(res, args.title),
        "sarif": lambda: report.sarif(res),
    }[args.format]()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Wrote {args.format} report to {args.output}  (score {res.score}/100, grade {res.grade})")
    else:
        sys.stdout.write(out)

    if args.fail_on:
        bar = Severity.parse(args.fail_on).rank
        bad = [f for f in res.findings if f.rule.severity.rank >= bar]
        if bad:
            print(f"\n{len(bad)} finding(s) at '{args.fail_on}' or worse.", file=sys.stderr)
            return 1
    return 0
