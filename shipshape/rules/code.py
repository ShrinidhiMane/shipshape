"""Factor 1: application code. Secrets written into source or config files
end up in Git history and in every image built from it."""

from __future__ import annotations

import re

from ..loader import SourceFile
from ..model import Factor, Finding, Severity, rule

SC001 = rule(
    "SC001",
    Factor.CODE,
    Severity.CRITICAL,
    "Private key in a file",
    "Remove the key, rotate it, and load it at runtime from a Secret or a secret manager.",
)
SC002 = rule(
    "SC002",
    Factor.CODE,
    Severity.CRITICAL,
    "AWS access key in a file",
    "Deactivate the key in AWS now, then use IAM roles or a Secret instead of a hardcoded key.",
)
SC003 = rule(
    "SC003",
    Factor.CODE,
    Severity.HIGH,
    "Hardcoded password or token",
    "Read it from an environment variable that's filled from a Kubernetes Secret.",
)

PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
CREDENTIAL = re.compile(
    r"""(?ix)
    (?<![a-z])(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)(?![a-z])
    ["']?\s*[:=]\s*
    ["']([^"'\s]{8,})["']
    """
)
PLACEHOLDER = re.compile(
    r"(?i)change|example|placeholder|xxx|dummy|redacted|your[_-]|sample|\*\*\*|<|\$\{|\$\(|\{\{|%\("
)


def check(src: SourceFile) -> list[Finding]:
    out: list[Finding] = []
    for n, line in enumerate(src.text.splitlines(), start=1):
        if "shipshape:ignore" in line:
            continue
        if PRIVATE_KEY.search(line):
            out.append(Finding(SC001, src.file, n, src.file, "A private key is stored in this file."))
        if m := AWS_KEY.search(line):
            out.append(Finding(SC002, src.file, n, src.file, f"Looks like an AWS access key ({m.group()[:8]}…)."))
        for m in CREDENTIAL.finditer(line):
            value = m.group(2)
            if PLACEHOLDER.search(value):
                continue
            out.append(
                Finding(
                    SC003,
                    src.file,
                    n,
                    src.file,
                    f"'{m.group(1)}' is set to a literal value ({value[:3]}…, {len(value)} chars).",
                )
            )
    return out
