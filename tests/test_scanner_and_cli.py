import json
import subprocess
import sys
from pathlib import Path

from helpers import SAFE_POD, yaml_inputs

from shipshape.cli import main
from shipshape.model import RULES, Factor
from shipshape.scanner import scan, scan_inputs

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def test_every_factor_has_rules_and_every_rule_has_a_fix():
    for factor in Factor:
        assert any(r.factor is factor for r in RULES.values()), factor
    for r in RULES.values():
        assert r.fix.strip() and r.title.strip()


def test_insecure_example_hits_every_factor_and_fails():
    res, errors = scan([str(EXAMPLES / "insecure")])
    assert not errors
    hit = {f.rule.factor for f in res.findings}
    assert hit == set(Factor)
    assert res.grade == "F"


def test_hardened_example_is_clean():
    res, errors = scan([str(EXAMPLES / "hardened")])
    assert not errors
    assert [f.to_dict() for f in res.findings] == []
    assert (res.score, res.grade) == (100, "A")


def test_suppression_needs_an_annotation_and_keeps_the_reason():
    text = SAFE_POD.replace(
        "metadata: {name: ok, namespace: ns}",
        'metadata: {name: ok, namespace: ns, annotations: {shipshape.dev/ignore: "K8S007: app writes a cache file"}}',
    ).replace("readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false")
    res = scan_inputs(yaml_inputs(text))
    assert res.findings == []
    [(finding, reason)] = res.suppressed
    assert finding.rule.id == "K8S007" and reason == "app writes a cache file"


def test_one_critical_caps_the_grade_at_f():
    text = SAFE_POD.replace(
        "allowPrivilegeEscalation: false", "privileged: true\n        allowPrivilegeEscalation: false"
    )
    res = scan_inputs(yaml_inputs(text))
    assert res.score > 60 and res.grade == "F"


def test_cli_fail_on_gates_ci(tmp_path, capsys):
    assert main(["scan", str(EXAMPLES / "hardened"), "--fail-on", "low"]) == 0
    assert main(["scan", str(EXAMPLES / "insecure"), "--fail-on", "critical"]) == 1


def test_cli_writes_json_html_and_sarif(tmp_path):
    for fmt in ("json", "html", "sarif"):
        out = tmp_path / f"report.{fmt}"
        assert main(["scan", str(EXAMPLES / "insecure"), "--format", fmt, "-o", str(out)]) == 0
        body = out.read_text()
        if fmt == "html":
            assert "<title>Shipshape report</title>" in body and "Factor 5" in body
        else:
            data = json.loads(body)
            if fmt == "json":
                assert data["grade"] == "F" and data["findings"]
            else:
                assert data["version"] == "2.1.0" and data["runs"][0]["results"]


def test_cli_reads_kubectl_output_from_stdin():
    dump = (ROOT / "tests" / "fixtures" / "kubectl-get-pods.yaml").read_text()
    p = subprocess.run(
        [sys.executable, "-m", "shipshape", "scan", "-", "--format", "json"],
        input=dump,
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    data = json.loads(p.stdout)
    rules = {f["rule"] for f in data["findings"]}
    assert {"CL001", "CL007", "K8S001", "K8S002"} <= rules  # control plane + a privileged kube-proxy


def test_rules_command_lists_everything(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert all(rid in out for rid in RULES)
