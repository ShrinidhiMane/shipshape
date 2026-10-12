"""Factor 3: host and container environment. How much a container can
reach outside itself, into the node and the other containers on it."""

from __future__ import annotations

from ..loader import K8sObject
from ..model import Factor, Finding, Severity, rule
from ._pods import containers, is_control_plane, pod_spec, where

K8S001 = rule(
    "K8S001",
    Factor.HOST,
    Severity.CRITICAL,
    "Privileged container",
    "Remove privileged: true. A privileged container is effectively root on the node.",
)
K8S002 = rule(
    "K8S002",
    Factor.HOST,
    Severity.CRITICAL,
    "Shares the node's network, process or IPC namespace",
    "Remove hostNetwork / hostPID / hostIPC. The pod can see and touch everything on the node.",
)
K8S003 = rule(
    "K8S003",
    Factor.HOST,
    Severity.HIGH,
    "Mounts a folder from the node (hostPath)",
    "Use a PersistentVolumeClaim, ConfigMap or emptyDir instead of a hostPath volume.",
)
K8S004 = rule(
    "K8S004",
    Factor.HOST,
    Severity.HIGH,
    "Privilege escalation not blocked",
    "Set securityContext.allowPrivilegeEscalation: false on the container.",
)
K8S005 = rule(
    "K8S005",
    Factor.HOST,
    Severity.HIGH,
    "Adds a dangerous Linux capability",
    "Remove it from capabilities.add. Most apps need no extra capabilities.",
)
K8S006 = rule(
    "K8S006",
    Factor.HOST,
    Severity.MEDIUM,
    "Doesn't drop all Linux capabilities",
    'Set securityContext.capabilities.drop: ["ALL"], then add back only what\'s needed.',
)
K8S007 = rule(
    "K8S007",
    Factor.HOST,
    Severity.MEDIUM,
    "Root filesystem is writable",
    "Set readOnlyRootFilesystem: true and mount an emptyDir where the app needs to write.",
)
K8S008 = rule(
    "K8S008",
    Factor.HOST,
    Severity.MEDIUM,
    "No seccomp profile",
    "Set securityContext.seccompProfile.type: RuntimeDefault on the pod.",
)
K8S009 = rule(
    "K8S009",
    Factor.HOST,
    Severity.MEDIUM,
    "No CPU or memory limit",
    "Set resources.limits so one container can't starve everything else on the node.",
)
K8S010 = rule(
    "K8S010",
    Factor.HOST,
    Severity.MEDIUM,
    "Opens a port directly on the node (hostPort)",
    "Remove hostPort and expose the pod through a Service.",
)

DANGEROUS_CAPS = {
    "ALL",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "NET_RAW",
    "DAC_READ_SEARCH",
    "SYS_RAWIO",
    "BPF",
}


def check(obj: K8sObject) -> list[Finding]:
    spec = pod_spec(obj)
    if spec is None or is_control_plane(spec):
        return []
    f, ln = obj.file, obj.line
    out: list[Finding] = []

    shared = [k for k in ("hostNetwork", "hostPID", "hostIPC") if spec.get(k) is True]
    if shared:
        out.append(Finding(K8S002, f, ln, where(obj), f"{', '.join(shared)} is set to true."))
    for v in spec.get("volumes") or []:
        if isinstance(v, dict) and "hostPath" in v:
            path = (v.get("hostPath") or {}).get("path", "?")
            out.append(Finding(K8S003, f, ln, where(obj), f"Volume '{v.get('name')}' mounts {path} from the node."))
    pod_seccomp = ((spec.get("securityContext") or {}).get("seccompProfile") or {}).get("type")

    for _, c in containers(spec):
        sc = c.get("securityContext") or {}
        w = where(obj, c)
        if sc.get("privileged") is True:
            out.append(Finding(K8S001, f, ln, w, "privileged: true"))
        if sc.get("allowPrivilegeEscalation") is not False and sc.get("privileged") is not True:
            out.append(Finding(K8S004, f, ln, w, "allowPrivilegeEscalation is not set to false."))
        caps = sc.get("capabilities") or {}
        added = {str(x).upper() for x in caps.get("add") or []} & DANGEROUS_CAPS
        if added:
            out.append(Finding(K8S005, f, ln, w, f"Adds {', '.join(sorted(added))}."))
        if "ALL" not in {str(x).upper() for x in caps.get("drop") or []}:
            out.append(Finding(K8S006, f, ln, w, "capabilities.drop doesn't include ALL."))
        if sc.get("readOnlyRootFilesystem") is not True:
            out.append(Finding(K8S007, f, ln, w, "readOnlyRootFilesystem is not true."))
        c_seccomp = (sc.get("seccompProfile") or {}).get("type")
        if (c_seccomp or pod_seccomp) not in ("RuntimeDefault", "Localhost"):
            out.append(Finding(K8S008, f, ln, w, "No RuntimeDefault or Localhost seccomp profile."))
        limits = (c.get("resources") or {}).get("limits") or {}
        missing = [r for r in ("cpu", "memory") if r not in limits]
        if missing:
            out.append(Finding(K8S009, f, ln, w, f"No {' or '.join(missing)} limit."))
        for p in c.get("ports") or []:
            if isinstance(p, dict) and p.get("hostPort"):
                out.append(Finding(K8S010, f, ln, w, f"hostPort {p['hostPort']}."))
    return out
