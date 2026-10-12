"""Find and load the files to scan: Kubernetes YAML, Dockerfiles, and source files."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

SKIP_DIRS = {
    ".git",
    ".hg",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "tests",
    "test",
}
YAML_EXT = {".yaml", ".yml"}
TEXT_EXT = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".sh",
    ".bash",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".toml",
    ".properties",
    ".json",
    ".tf",
    ".yaml",
    ".yml",
    ".xml",
    ".txt",
}
MAX_BYTES = 1_000_000


@dataclass
class K8sObject:
    doc: dict
    file: str
    line: int

    @property
    def kind(self) -> str:
        return str(self.doc.get("kind", ""))

    @property
    def name(self) -> str:
        return str((self.doc.get("metadata") or {}).get("name", "?"))

    @property
    def namespace(self) -> str | None:
        return (self.doc.get("metadata") or {}).get("namespace")

    @property
    def annotations(self) -> dict:
        return (self.doc.get("metadata") or {}).get("annotations") or {}

    @property
    def label(self) -> str:
        return f"{self.kind}/{self.name}"


@dataclass
class Dockerfile:
    file: str
    lines: list[tuple[int, str]]  # (line number, logical instruction with continuations joined)
    raw: str


@dataclass
class SourceFile:
    file: str
    text: str


@dataclass
class Inputs:
    objects: list[K8sObject]
    dockerfiles: list[Dockerfile]
    sources: list[SourceFile]
    files: int
    errors: list[str]


def is_dockerfile(p: Path) -> bool:
    n = p.name.lower()
    return n in ("dockerfile", "containerfile") or n.startswith("dockerfile.") or n.endswith(".dockerfile")


def split_yaml_docs(text: str) -> list[tuple[int, str]]:
    """Split a multi-document YAML file, remembering where each document starts."""
    docs, start, buf = [], 1, []
    for i, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^---\s*($|#)", line):
            if buf:
                docs.append((start, "\n".join(buf)))
            buf, start = [], i + 1
        else:
            buf.append(line)
    if buf:
        docs.append((start, "\n".join(buf)))
    return docs


def k8s_objects(text: str, file: str, errors: list[str]) -> list[K8sObject]:
    out: list[K8sObject] = []
    for start, chunk in split_yaml_docs(text):
        try:
            doc = yaml.safe_load(chunk)
        except yaml.YAMLError as e:
            errors.append(f"{file}:{start}: not valid YAML ({str(e).splitlines()[0]})")
            continue
        if not isinstance(doc, dict) or "kind" not in doc or "apiVersion" not in doc:
            continue
        first = next(
            (n for n, ln in enumerate(chunk.splitlines()) if ln.strip() and not ln.lstrip().startswith("#")), 0
        )
        if doc.get("kind") == "List" or str(doc.get("kind", "")).endswith("List"):
            for item in doc.get("items") or []:  # `kubectl get ... -o yaml` output
                if isinstance(item, dict) and "kind" in item:
                    out.append(K8sObject(item, file, start + first))
        else:
            out.append(K8sObject(doc, file, start + first))
    return out


def parse_dockerfile(text: str, file: str) -> Dockerfile:
    lines: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), start=1):
        s = raw.strip()
        if not buf and (not s or s.startswith("#")):
            continue
        if not buf:
            start = i
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        lines.append((start, buf.strip()))
        buf = ""
    if buf:
        lines.append((start, buf.strip()))
    return Dockerfile(file, lines, text)


def _display_path(p: Path, root: Path) -> str:
    """A short path for reports: relative to the current folder if possible,
    otherwise relative to the folder that was scanned (keeping its name)."""
    try:
        rel = os.path.relpath(p)
        if not rel.startswith(".."):
            return rel.replace(os.sep, "/")
    except ValueError:  # different drive on Windows
        pass
    base = root.parent if root.is_dir() else root.parent
    return os.path.relpath(p, base).replace(os.sep, "/")


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for p in sorted(root.iterdir()):
        if p.is_dir():
            if p.name in SKIP_DIRS or (p.name.startswith(".") and p.name not in (".github",)):
                continue
            yield from _walk(p)
        else:
            yield p


def load(paths: list[str], scan_source: bool = True) -> Inputs:
    objects: list[K8sObject] = []
    dockerfiles: list[Dockerfile] = []
    sources: list[SourceFile] = []
    errors: list[str] = []
    files = 0

    for raw in paths:
        if raw == "-":
            text = sys.stdin.read()
            files += 1
            objects += k8s_objects(text, "<stdin>", errors)
            continue
        root = Path(raw)
        if not root.exists():
            errors.append(f"{raw}: no such file or directory")
            continue
        for p in _walk(root):
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            rel = _display_path(p, root)
            used = False
            if is_dockerfile(p):
                dockerfiles.append(parse_dockerfile(text, rel))
                used = True
            elif p.suffix.lower() in YAML_EXT:
                objs = k8s_objects(text, rel, errors)
                objects += objs
                used = used or bool(objs)
            if scan_source and (p.suffix.lower() in TEXT_EXT or p.name.startswith(".env") or is_dockerfile(p)):
                sources.append(SourceFile(rel, text))
                used = True
            files += int(used)
    return Inputs(objects, dockerfiles, sources, files, errors)
