import textwrap

from shipshape.loader import Dockerfile, Inputs, SourceFile, k8s_objects, parse_dockerfile
from shipshape.scanner import scan_inputs


def yaml_inputs(text: str, file: str = "test.yaml") -> Inputs:
    errors: list[str] = []
    objs = k8s_objects(textwrap.dedent(text), file, errors)
    assert not errors, errors
    return Inputs(objs, [], [], 1, errors)


def ids(text: str, file: str = "test.yaml") -> list[str]:
    return sorted(f.rule.id for f in scan_inputs(yaml_inputs(text, file)).findings)


def docker_ids(text: str) -> list[str]:
    df: Dockerfile = parse_dockerfile(textwrap.dedent(text), "Dockerfile")
    return sorted(f.rule.id for f in scan_inputs(Inputs([], [df], [], 1, [])).findings)


def source_ids(text: str, file: str = "app.py") -> list[str]:
    return sorted(
        f.rule.id for f in scan_inputs(Inputs([], [], [SourceFile(file, textwrap.dedent(text))], 1, [])).findings
    )


SAFE_POD = """
apiVersion: v1
kind: Pod
metadata: {name: ok, namespace: ns}
spec:
  serviceAccountName: app
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: app
      image: registry.example.com/app:1.0@sha256:abc
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      resources:
        limits: {cpu: 100m, memory: 64Mi}
      readinessProbe: {tcpSocket: {port: 80}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: np, namespace: ns}
spec: {podSelector: {}}
"""
