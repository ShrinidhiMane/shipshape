"""Runs every rule over the loaded inputs and applies suppressions.

Suppressing a finding is allowed, but it has to be written down where the
reviewer will see it:
  - Kubernetes: annotation  shipshape.dev/ignore: "K8S012: talks to the API to list pods"
  - Dockerfile: comment     # shipshape:ignore DF005 probes handle this on Kubernetes
  - source line: comment    shipshape:ignore on the same line
"""

from __future__ import annotations

import re

from .loader import Inputs, load
from .model import Finding, Result, Severity
from .rules import apps, cluster, code, host, images, monitoring

IGNORE_KEY = "shipshape.dev/ignore"


def _ignored_ids(text: str) -> dict[str, str]:
    """'K8S012, K8S007: reason' -> {'K8S012': 'reason', 'K8S007': 'reason'}"""
    out: dict[str, str] = {}
    for line in str(text).splitlines() or [str(text)]:
        ids_part, _, reason = line.partition(":")
        for rid in re.findall(r"[A-Z][A-Z0-9]*\d{3}", ids_part):
            out[rid] = reason.strip() or "no reason given"
    return out


def scan_inputs(inp: Inputs, trusted: list[str] | None = None, min_severity: Severity = Severity.LOW) -> Result:
    trusted = trusted or []
    res = Result(files_scanned=inp.files, objects_scanned=len(inp.objects) + len(inp.dockerfiles))

    def keep(findings: list[Finding], ignore: dict[str, str]):
        for f in findings:
            if f.rule.severity.rank < min_severity.rank:
                continue
            if f.rule.id in ignore:
                res.suppressed.append((f, ignore[f.rule.id]))
            else:
                res.findings.append(f)

    for obj in inp.objects:
        ignore = _ignored_ids(obj.annotations.get(IGNORE_KEY, ""))
        found = (
            images.check_object(obj, trusted)
            + host.check(obj)
            + apps.check(obj)
            + cluster.check(obj)
            + monitoring.check(obj)
        )
        keep(found, ignore)
    keep(apps.check_all(inp.objects), {})

    for df in inp.dockerfiles:
        ignore: dict[str, str] = {}
        for m in re.finditer(r"#\s*shipshape:ignore\s+([A-Z0-9, ]+?)(?:\s+(.*))?$", df.raw, re.M):
            for rid in re.findall(r"[A-Z][A-Z0-9]*\d{3}", m.group(1)):
                ignore[rid] = (m.group(2) or "no reason given").strip()
        keep(images.check_dockerfile(df, trusted), ignore)

    for src in inp.sources:
        keep(code.check(src), {})
    return res


def scan(
    paths: list[str], trusted: list[str] | None = None, scan_source: bool = True, min_severity: Severity = Severity.LOW
) -> tuple[Result, list[str]]:
    inp = load(paths, scan_source=scan_source)
    return scan_inputs(inp, trusted, min_severity), inp.errors
