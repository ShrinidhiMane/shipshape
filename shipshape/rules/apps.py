"""Factor 4: applications in Kubernetes. Identity (service accounts and RBAC),
secrets, admission (Pod Security), and network rules."""

from __future__ import annotations

import re

from ..loader import K8sObject
from ..model import Factor, Finding, Severity, rule
from ._pods import LONG_RUNNING, containers, effective, is_control_plane, pod_spec, where

K8S011 = rule(
    "K8S011",
    Factor.APPS,
    Severity.HIGH,
    "Container may run as root",
    "Set runAsNonRoot: true and a non-zero runAsUser in the pod's securityContext.",
)
K8S012 = rule(
    "K8S012",
    Factor.APPS,
    Severity.MEDIUM,
    "Service account token mounted into the pod",
    "Set automountServiceAccountToken: false unless the app really calls the Kubernetes API.",
)
K8S013 = rule(
    "K8S013",
    Factor.APPS,
    Severity.HIGH,
    "Secret written as a plain env value",
    "Use valueFrom.secretKeyRef so the value lives in a Secret, not in the manifest.",
)
K8S014 = rule(
    "K8S014",
    Factor.APPS,
    Severity.MEDIUM,
    "Secret with real values stored in a file",
    "Don't commit Secrets. Create them with kubectl, or use Sealed Secrets or an external secret store.",
)
K8S015 = rule(
    "K8S015",
    Factor.APPS,
    Severity.MEDIUM,
    "Namespace doesn't enforce a Pod Security Standard",
    "Add the label pod-security.kubernetes.io/enforce: restricted (or baseline) to the namespace.",
)
K8S016 = rule(
    "K8S016",
    Factor.APPS,
    Severity.MEDIUM,
    "No NetworkPolicy for this namespace",
    "Add a NetworkPolicy so only the pods that need to talk to each other can.",
)
K8S017 = rule(
    "K8S017",
    Factor.APPS,
    Severity.LOW,
    "Service reachable from outside the cluster",
    "Check that this should be public. If not, use type: ClusterIP.",
)
K8S018 = rule(
    "K8S018",
    Factor.APPS,
    Severity.LOW,
    "Runs as the namespace's default service account",
    "Give the workload its own service account, so its permissions can be limited on their own.",
)
RBAC001 = rule(
    "RBAC001",
    Factor.APPS,
    Severity.CRITICAL,
    "Role allows everything (* on *)",
    "List only the resources and verbs the subject actually needs.",
)
RBAC002 = rule(
    "RBAC002",
    Factor.APPS,
    Severity.HIGH,
    "Role uses a wildcard (*)",
    "Replace * with the exact resources or verbs needed.",
)
RBAC003 = rule(
    "RBAC003",
    Factor.APPS,
    Severity.HIGH,
    "Role can read Secrets",
    "Remove get/list/watch on secrets, or limit it with resourceNames.",
)
RBAC004 = rule(
    "RBAC004",
    Factor.APPS,
    Severity.HIGH,
    "Role can escalate its own access",
    "Remove create on pods or pods/exec, and the escalate, bind and impersonate verbs.",
)
RBAC005 = rule(
    "RBAC005",
    Factor.APPS,
    Severity.CRITICAL,
    "Binding grants cluster-admin",
    "Bind a narrower role. cluster-admin can do anything in every namespace.",
)
RBAC006 = rule(
    "RBAC006",
    Factor.APPS,
    Severity.CRITICAL,
    "Binding grants access to anonymous or all users",
    "Remove system:anonymous, system:unauthenticated and system:authenticated from the subjects.",
)

SECRET_NAME = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)")
PLACEHOLDER = re.compile(r"(?i)change[-_ ]?me|example|placeholder|^x+$|dummy|redacted|^$")
PUBLIC_GROUPS = {"system:anonymous", "system:unauthenticated", "system:authenticated"}
READ = {"get", "list", "watch", "*"}


def check(obj: K8sObject) -> list[Finding]:
    kind = obj.kind
    if kind in ("Role", "ClusterRole"):
        return _role(obj)
    if kind in ("RoleBinding", "ClusterRoleBinding"):
        return _binding(obj)
    if kind == "Secret":
        return _secret(obj)
    if kind == "Namespace":
        return _namespace(obj)
    if kind == "Service":
        t = (obj.doc.get("spec") or {}).get("type", "ClusterIP")
        if t in ("NodePort", "LoadBalancer"):
            return [Finding(K8S017, obj.file, obj.line, obj.label, f"type: {t}")]
        return []
    spec = pod_spec(obj)
    if spec is None or is_control_plane(spec):
        return []
    return _workload(obj, spec)


def _workload(obj: K8sObject, spec: dict) -> list[Finding]:
    f, ln = obj.file, obj.line
    out: list[Finding] = []
    for _, c in containers(spec):
        w = where(obj, c)
        non_root = effective(spec, c, "runAsNonRoot")
        uid = effective(spec, c, "runAsUser")
        if uid == 0:
            out.append(Finding(K8S011, f, ln, w, "runAsUser is 0 (root)."))
        elif non_root is not True and not (isinstance(uid, int) and uid > 0):
            out.append(Finding(K8S011, f, ln, w, "Neither runAsNonRoot: true nor a non-zero runAsUser is set."))
        for e in c.get("env") or []:
            if isinstance(e, dict) and "value" in e and SECRET_NAME.search(str(e.get("name", ""))):
                if not PLACEHOLDER.search(str(e.get("value") or "")):
                    out.append(Finding(K8S013, f, ln, w, f"env {e['name']} has its value written in the manifest."))
    if spec.get("automountServiceAccountToken") is not False:
        out.append(Finding(K8S012, f, ln, where(obj), "automountServiceAccountToken is not false."))
    if obj.kind in LONG_RUNNING and spec.get("serviceAccountName", spec.get("serviceAccount", "default")) == "default":
        out.append(Finding(K8S018, f, ln, where(obj), "No serviceAccountName, so it uses 'default'."))
    return out


def _secret(obj: K8sObject) -> list[Finding]:
    if obj.file == "<stdin>":  # a live cluster dump, not a file in a repo
        return []
    if (obj.doc.get("type") or "Opaque") == "kubernetes.io/service-account-token":
        return []
    values = {**(obj.doc.get("data") or {}), **(obj.doc.get("stringData") or {})}
    real = [k for k, v in values.items() if not PLACEHOLDER.search(str(v or ""))]
    if not real:
        return []
    return [Finding(K8S014, obj.file, obj.line, obj.label, f"Holds values for: {', '.join(sorted(real))}.")]


def _namespace(obj: K8sObject) -> list[Finding]:
    if obj.name in ("kube-system", "kube-public", "kube-node-lease"):
        return []
    labels = (obj.doc.get("metadata") or {}).get("labels") or {}
    level = labels.get("pod-security.kubernetes.io/enforce")
    if level in ("baseline", "restricted"):
        return []
    msg = "No pod-security.kubernetes.io/enforce label." if level is None else f"enforce is '{level}'."
    return [Finding(K8S015, obj.file, obj.line, obj.label, msg)]


def _role(obj: K8sObject) -> list[Finding]:
    if obj.name.startswith("system:") or obj.doc.get("aggregationRule"):
        return []
    out: list[Finding] = []
    for i, r in enumerate(obj.doc.get("rules") or []):
        if not isinstance(r, dict):
            continue
        verbs = {str(v) for v in r.get("verbs") or []}
        resources = {str(x) for x in r.get("resources") or []}
        where_ = f"{obj.label} (rule {i + 1})"
        if "*" in verbs and "*" in resources:
            out.append(Finding(RBAC001, obj.file, obj.line, where_, "verbs: ['*'] on resources: ['*']."))
            continue
        if "*" in verbs or "*" in resources:
            out.append(Finding(RBAC002, obj.file, obj.line, where_, f"verbs {sorted(verbs)} on {sorted(resources)}."))
        if ("secrets" in resources or "*" in resources) and verbs & READ:
            out.append(Finding(RBAC003, obj.file, obj.line, where_, f"Can {', '.join(sorted(verbs & READ))} secrets."))
        risky = []
        if {"pods", "pods/exec"} & resources and {"create", "*"} & verbs:
            risky.append("create " + "/".join(sorted({"pods", "pods/exec"} & resources)))
        risky += sorted({"escalate", "bind", "impersonate"} & verbs)
        if risky:
            out.append(Finding(RBAC004, obj.file, obj.line, where_, f"Allows {', '.join(risky)}."))
    return out


def _binding(obj: K8sObject) -> list[Finding]:
    if obj.name.startswith("system:") or obj.name == "cluster-admin":
        return []
    out: list[Finding] = []
    role = (obj.doc.get("roleRef") or {}).get("name")
    subjects = [s for s in obj.doc.get("subjects") or [] if isinstance(s, dict)]
    if role == "cluster-admin":
        who = ", ".join(f"{s.get('kind')} {s.get('name')}" for s in subjects) or "no subjects"
        out.append(Finding(RBAC005, obj.file, obj.line, obj.label, f"Gives cluster-admin to {who}."))
    public = sorted({s.get("name") for s in subjects} & PUBLIC_GROUPS)
    if public:
        out.append(Finding(RBAC006, obj.file, obj.line, obj.label, f"Subjects include {', '.join(public)}."))
    return out


def check_all(objects: list[K8sObject]) -> list[Finding]:
    """Cross-object rule: every namespace with workloads should have a NetworkPolicy."""
    workloads: dict[str, K8sObject] = {}
    with_policy: set[str] = set()
    for o in objects:
        ns = o.namespace or "default"
        if o.kind == "NetworkPolicy":
            with_policy.add(ns)
        spec = pod_spec(o)
        if spec is not None and not is_control_plane(spec) and ns not in ("kube-system",):
            workloads.setdefault(ns, o)
    out = []
    for ns, first in sorted(workloads.items()):
        if ns not in with_policy:
            out.append(
                Finding(
                    K8S016,
                    first.file,
                    first.line,
                    f"Namespace/{ns}",
                    f"Workloads run in '{ns}', but no NetworkPolicy was found for it.",
                )
            )
    return out
