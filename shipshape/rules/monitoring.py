"""Logging and monitoring (the course's 'additional considerations' chapter).
You can't defend what you can't see. The API server audit-log rule (CL007)
lives in cluster.py, since it reads the same control-plane flags."""

from __future__ import annotations

from ..loader import K8sObject
from ..model import Factor, Finding, Severity, rule
from ._pods import LONG_RUNNING, is_control_plane, pod_spec, where

MON001 = rule(
    "MON001",
    Factor.MONITORING,
    Severity.LOW,
    "No health probes",
    "Add a readinessProbe and a livenessProbe, so Kubernetes notices (and fixes) a broken container.",
)


def check(obj: K8sObject) -> list[Finding]:
    if obj.kind not in LONG_RUNNING:
        return []
    spec = pod_spec(obj)
    if spec is None or is_control_plane(spec):
        return []
    out = []
    for c in spec.get("containers") or []:
        if isinstance(c, dict) and not c.get("livenessProbe") and not c.get("readinessProbe"):
            out.append(Finding(MON001, obj.file, obj.line, where(obj, c), "No livenessProbe or readinessProbe."))
    return out
