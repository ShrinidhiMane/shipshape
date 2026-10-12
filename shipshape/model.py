"""Core types: factors, severities, rules and findings."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class Factor(Enum):
    """The five-factor model from the course, plus the 'additional' chapter."""

    CODE = (1, "Application code", "Secrets and credentials in source and config files")
    IMAGES = (2, "Images", "What goes into the image, and where it comes from")
    HOST = (3, "Host and container environment", "What a container can do to the node it runs on")
    APPS = (4, "Applications in Kubernetes", "Identity, access, secrets and network rules for workloads")
    CLUSTER = (5, "Kubernetes cluster", "Control plane settings: API server, etcd, admission")
    MONITORING = (6, "Logging and monitoring", "Being able to see problems: probes and audit logs")

    def __init__(self, number: int, title: str, blurb: str):
        self.number = number
        self.title = title
        self.blurb = blurb


class Severity(Enum):
    CRITICAL = ("critical", 20)
    HIGH = ("high", 8)
    MEDIUM = ("medium", 3)
    LOW = ("low", 1)

    def __init__(self, label: str, points: int):
        self.label = label
        self.points = points

    @classmethod
    def parse(cls, value: str) -> Severity:
        for s in cls:
            if s.label == value.lower():
                return s
        raise ValueError(f"unknown severity: {value}")

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.label]


@dataclass(frozen=True)
class Rule:
    id: str
    factor: Factor
    severity: Severity
    title: str
    fix: str


@dataclass
class Finding:
    rule: Rule
    file: str
    line: int
    obj: str  # e.g. "Deployment/web (container app)" or "Dockerfile"
    message: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.id,
            "severity": self.rule.severity.label,
            "factor": self.rule.factor.number,
            "factor_title": self.rule.factor.title,
            "title": self.rule.title,
            "file": self.file,
            "line": self.line,
            "object": self.obj,
            "message": self.message,
            "fix": self.rule.fix,
        }


RULES: dict[str, Rule] = {}


def rule(id: str, factor: Factor, severity: Severity, title: str, fix: str) -> Rule:
    r = Rule(id, factor, severity, title, fix)
    if id in RULES:
        raise ValueError(f"duplicate rule id {id}")
    RULES[id] = r
    return r


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[tuple[Finding, str]] = field(default_factory=list)
    files_scanned: int = 0
    objects_scanned: int = 0

    @property
    def points(self) -> int:
        return sum(f.rule.severity.points for f in self.findings)

    @property
    def score(self) -> int:
        return max(0, 100 - self.points)

    @property
    def grade(self) -> str:
        s = self.score
        if any(f.rule.severity is Severity.CRITICAL for f in self.findings):
            s = min(s, 59)  # any critical issue caps the grade at F
        for limit, g in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
            if s >= limit:
                return g
        return "F"

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.rule.severity is severity)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.rule.factor.number, -f.rule.severity.rank, f.file, f.line))


Check = Callable[..., list[Finding]]
