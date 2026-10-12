"""Helpers for reading pod specs out of any workload kind."""

from __future__ import annotations

from collections.abc import Iterator

from ..loader import K8sObject

WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
}
LONG_RUNNING = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController"}
CONTROL_PLANE = ("kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler")


def pod_spec(obj: K8sObject) -> dict | None:
    d = obj.doc
    kind = obj.kind
    if kind not in WORKLOAD_KINDS:
        return None
    spec = d.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def containers(spec: dict) -> Iterator[tuple[str, dict]]:
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for c in spec.get(key) or []:
            if isinstance(c, dict):
                yield key, c


def effective(spec: dict, c: dict, key: str):
    """A container's securityContext setting, falling back to the pod's."""
    csc = c.get("securityContext") or {}
    if csc.get(key) is not None:
        return csc.get(key)
    return (spec.get("securityContext") or {}).get(key)


def command_line(c: dict) -> list[str]:
    return [str(x) for x in (c.get("command") or []) + (c.get("args") or [])]


def control_plane_component(c: dict) -> str | None:
    cmd = command_line(c)
    if not cmd:
        return None
    first = cmd[0].rsplit("/", 1)[-1]
    return first if first in CONTROL_PLANE else None


def is_control_plane(spec: dict) -> bool:
    return any(control_plane_component(c) for _, c in containers(spec))


def where(obj: K8sObject, c: dict | None = None) -> str:
    return f"{obj.label} (container {c.get('name', '?')})" if c else obj.label
