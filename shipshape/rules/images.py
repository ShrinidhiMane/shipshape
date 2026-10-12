"""Factor 2: images. What goes into an image, and where it comes from."""

from __future__ import annotations

import re

from ..loader import Dockerfile, K8sObject
from ..model import Factor, Finding, Severity, rule
from ._pods import containers, is_control_plane, pod_spec, where

IMG001 = rule(
    "IMG001",
    Factor.IMAGES,
    Severity.HIGH,
    "Image has no fixed version (latest or no tag)",
    "Use a specific tag like python:3.12-slim, so every deploy runs the image you tested.",
)
IMG002 = rule(
    "IMG002",
    Factor.IMAGES,
    Severity.LOW,
    "Image not pinned by digest",
    "Add @sha256:... after the tag. A tag can be moved to a different image; a digest can't.",
)
IMG003 = rule(
    "IMG003",
    Factor.IMAGES,
    Severity.MEDIUM,
    "Image from a registry you didn't list as trusted",
    "Pull only from registries you trust, or add this one to --trusted-registry.",
)
DF001 = rule(
    "DF001",
    Factor.IMAGES,
    Severity.HIGH,
    "Dockerfile runs the app as root",
    "Create a user (RUN useradd -u 10001 app) and switch to it with USER 10001 at the end.",
)
DF002 = rule(
    "DF002",
    Factor.IMAGES,
    Severity.HIGH,
    "Secret baked into the image (ENV/ARG)",
    "Anyone who pulls the image can read ENV and ARG values. Pass secrets at runtime instead.",
)
DF003 = rule(
    "DF003",
    Factor.IMAGES,
    Severity.MEDIUM,
    "ADD downloads from a URL",
    "Use COPY for local files, or RUN curl with a checksum check for downloads.",
)
DF004 = rule(
    "DF004",
    Factor.IMAGES,
    Severity.HIGH,
    "Downloaded script piped straight into a shell",
    "Download the file, check its checksum, then run it.",
)
DF005 = rule(
    "DF005",
    Factor.IMAGES,
    Severity.LOW,
    "No HEALTHCHECK in the Dockerfile",
    "Add a HEALTHCHECK for plain Docker. On Kubernetes, probes do this job instead.",
)

SECRET_NAME = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)")
PIPE_TO_SHELL = re.compile(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|ash)\b")


def split_image(image: str) -> tuple[str, str | None, str | None]:
    """Return (registry/repo, tag, digest)."""
    digest = None
    if "@" in image:
        image, digest = image.split("@", 1)
    last = image.rsplit("/", 1)[-1]
    tag = None
    if ":" in last:
        repo_last, tag = last.rsplit(":", 1)
        image = image[: len(image) - len(last)] + repo_last
    return image, tag, digest


def registry_of(image: str) -> str:
    first = image.split("/", 1)[0]
    if "/" in image and ("." in first or ":" in first or first == "localhost"):
        return first
    return "docker.io"


def image_findings(
    image: str, file: str, line: int, obj: str, trusted: list[str], local: bool = False
) -> list[Finding]:
    out = []
    repo, tag, digest = split_image(image)
    if image.lower() == "scratch":
        return out
    if not digest and (tag is None or tag == "latest"):
        out.append(Finding(IMG001, file, line, obj, f"'{image}' will pull whatever 'latest' is at deploy time."))
    if not digest and not local:
        out.append(Finding(IMG002, file, line, obj, f"'{image}' is referenced by tag only."))
    if trusted and registry_of(repo) not in trusted and not local:
        out.append(Finding(IMG003, file, line, obj, f"'{image}' comes from {registry_of(repo)}."))
    return out


def check_object(obj: K8sObject, trusted: list[str]) -> list[Finding]:
    spec = pod_spec(obj)
    if spec is None or is_control_plane(spec):
        return []
    out = []
    for _, c in containers(spec):
        image = str(c.get("image", ""))
        if not image:
            continue
        # imagePullPolicy: Never/IfNotPresent with no registry usually means a locally built image (minikube).
        local = (
            c.get("imagePullPolicy") in ("Never", "IfNotPresent")
            and "/" not in image
            and "." not in image.split(":")[0]
        )
        out += image_findings(image, obj.file, obj.line, where(obj, c), trusted, local=local)
    return out


def check_dockerfile(df: Dockerfile, trusted: list[str]) -> list[Finding]:
    out: list[Finding] = []
    stages: set[str] = set()
    user: tuple[int, str] | None = None  # the USER in effect in the current (finally: last) stage
    has_healthcheck = False
    for n, ins in df.lines:
        op, _, rest = ins.partition(" ")
        op = op.upper()
        rest = rest.strip()
        if op == "FROM":
            parts = rest.split()
            image = next((p for p in parts if not p.startswith("--")), "")
            if " as " in rest.lower():
                stages.add(parts[-1].lower())
            if image.lower() not in stages and not image.startswith("$"):
                out += image_findings(image, df.file, n, df.file, trusted)
            user = None  # each stage starts as root again
        elif op == "USER":
            user = (n, rest.split(":")[0])
        elif op in ("ENV", "ARG"):
            for name, value in _kv(rest):
                if SECRET_NAME.search(name) and value and not value.startswith("$"):
                    out.append(Finding(DF002, df.file, n, df.file, f"{op} {name} holds a value in the image."))
        elif op == "ADD" and re.search(r"https?://", rest):
            out.append(Finding(DF003, df.file, n, df.file, "ADD fetches a remote file with no integrity check."))
        elif op == "RUN" and PIPE_TO_SHELL.search(rest):
            out.append(Finding(DF004, df.file, n, df.file, "A downloaded script runs without being checked."))
        elif op == "HEALTHCHECK":
            has_healthcheck = not rest.upper().startswith("NONE")
    if user is None or user[1] in ("root", "0"):
        line = user[0] if user else (df.lines[-1][0] if df.lines else 1)
        msg = "The final stage has no USER, so the app runs as root." if user is None else "USER is set to root."
        out.append(Finding(DF001, df.file, line, df.file, msg))
    if not has_healthcheck:
        out.append(Finding(DF005, df.file, df.lines[-1][0] if df.lines else 1, df.file, "No HEALTHCHECK instruction."))
    return out


def _kv(rest: str) -> list[tuple[str, str]]:
    if "=" in rest.split(" ", 1)[0]:
        pairs = re.findall(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)', rest)
        return [(k, v.strip("\"'")) for k, v in pairs]
    name, _, value = rest.partition(" ")
    return [(name, value.strip().strip("\"'"))]
