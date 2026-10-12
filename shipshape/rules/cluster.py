"""Factor 5: the cluster itself. These rules read the flags of control-plane
static pods (kube-apiserver, etcd, controller-manager, scheduler), which you
can scan straight from a live cluster:

    kubectl get pods -n kube-system -o yaml | shipshape scan -
"""

from __future__ import annotations

from ..loader import K8sObject
from ..model import Factor, Finding, Severity, rule
from ._pods import command_line, containers, control_plane_component, pod_spec

CL001 = rule(
    "CL001",
    Factor.CLUSTER,
    Severity.HIGH,
    "API server accepts anonymous requests",
    "Start kube-apiserver with --anonymous-auth=false.",
)
CL002 = rule(
    "CL002",
    Factor.CLUSTER,
    Severity.CRITICAL,
    "API server authorization is too open",
    "Use --authorization-mode=Node,RBAC and never AlwaysAllow.",
)
CL003 = rule(
    "CL003",
    Factor.CLUSTER,
    Severity.CRITICAL,
    "API server has an unencrypted, unauthenticated port",
    "Remove --insecure-port / --insecure-bind-address (or set --insecure-port=0).",
)
CL004 = rule(
    "CL004",
    Factor.CLUSTER,
    Severity.HIGH,
    "NodeRestriction admission plugin is off",
    "Add NodeRestriction to --enable-admission-plugins, so a node can only change its own objects.",
)
CL005 = rule(
    "CL005",
    Factor.CLUSTER,
    Severity.MEDIUM,
    "Secrets aren't encrypted at rest in etcd",
    "Pass --encryption-provider-config with an aescbc, secretbox or KMS provider.",
)
CL006 = rule(
    "CL006",
    Factor.CLUSTER,
    Severity.LOW,
    "Profiling endpoint is on",
    "Add --profiling=false to the control-plane component.",
)
CL008 = rule(
    "CL008",
    Factor.CLUSTER,
    Severity.HIGH,
    "API server has no TLS certificate set",
    "Set --tls-cert-file and --tls-private-key-file so all API traffic is encrypted.",
)
CL009 = rule(
    "CL009",
    Factor.CLUSTER,
    Severity.HIGH,
    "etcd doesn't require client certificates",
    "Start etcd with --client-cert-auth=true and --peer-client-cert-auth=true.",
)
CL010 = rule(
    "CL010",
    Factor.CLUSTER,
    Severity.HIGH,
    "etcd traffic isn't encrypted",
    "Set --cert-file/--key-file (and --peer-cert-file/--peer-key-file) on etcd.",
)
CL011 = rule(
    "CL011",
    Factor.CLUSTER,
    Severity.MEDIUM,
    "Component listens on all network interfaces",
    "Set --bind-address=127.0.0.1 on kube-controller-manager and kube-scheduler.",
)
CL007 = rule(
    "CL007",
    Factor.MONITORING,
    Severity.MEDIUM,
    "API server audit logging is off",
    "Set --audit-log-path and --audit-policy-file so you can see who did what in the cluster.",
)


def flags(c: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in command_line(c)[1:]:
        if part.startswith("--"):
            k, _, v = part[2:].partition("=")
            out[k] = v if v else "true"
    return out


def check(obj: K8sObject) -> list[Finding]:
    spec = pod_spec(obj)
    if spec is None:
        return []
    out: list[Finding] = []
    for _, c in containers(spec):
        comp = control_plane_component(c)
        if not comp:
            continue
        fl = flags(c)
        w = f"{obj.label} ({comp})"

        def add(r, msg, w=w):
            out.append(Finding(r, obj.file, obj.line, w, msg))

        # etcd has no --profiling flag (its pprof endpoint is off unless --enable-pprof is set).
        if comp == "etcd":
            if fl.get("enable-pprof") == "true":
                add(CL006, "--enable-pprof=true")
        elif fl.get("profiling", "true") != "false":
            add(CL006, "--profiling is not false.")
        if comp == "kube-apiserver":
            if fl.get("anonymous-auth", "true") != "false":
                add(CL001, "--anonymous-auth is not set to false (the default is true).")
            modes = fl.get("authorization-mode", "AlwaysAllow").split(",")
            if "AlwaysAllow" in modes or "RBAC" not in modes:
                add(CL002, f"--authorization-mode={','.join(modes)}")
            if fl.get("insecure-port", "0") != "0" or "insecure-bind-address" in fl:
                add(CL003, "An insecure port is configured.")
            if "NodeRestriction" not in fl.get("enable-admission-plugins", "").split(","):
                add(CL004, "NodeRestriction is not in --enable-admission-plugins.")
            if "encryption-provider-config" not in fl:
                add(CL005, "No --encryption-provider-config.")
            if "tls-cert-file" not in fl:
                add(CL008, "No --tls-cert-file.")
            if "audit-log-path" not in fl:
                add(CL007, "No --audit-log-path.")
        elif comp == "etcd":
            missing = [k for k in ("client-cert-auth", "peer-client-cert-auth") if fl.get(k) != "true"]
            if missing:
                add(CL009, f"Not true: {', '.join('--' + m for m in missing)}.")
            if "cert-file" not in fl:
                add(CL010, "No --cert-file.")
        elif comp in ("kube-controller-manager", "kube-scheduler"):
            if fl.get("bind-address", "0.0.0.0") not in ("127.0.0.1", "localhost", "::1"):
                add(CL011, f"--bind-address={fl.get('bind-address', '0.0.0.0 (default)')}")
    return out
