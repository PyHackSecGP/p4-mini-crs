"""Tests for SARIF 2.1.0 export."""
from __future__ import annotations
import json
from models import Analysis, ValidationResult
from stages.sarif_exporter import _parse_vulnerable_line, generate_sarif


# ── _parse_vulnerable_line ────────────────────────────────────────────────────

def _make_analysis(vulnerable_lines: str) -> Analysis:
    return Analysis(vulnerable_lines=vulnerable_lines)


def test_parse_filename_and_line():
    a = _make_analysis("main.c:42")
    fname, lineno = _parse_vulnerable_line(a)
    assert fname == "main.c"
    assert lineno == 42


def test_parse_bare_line_number():
    a = _make_analysis("42")
    _, lineno = _parse_vulnerable_line(a)
    assert lineno == 42


def test_parse_line_with_range():
    a = _make_analysis("main.c:18-22")
    fname, lineno = _parse_vulnerable_line(a)
    assert fname == "main.c"
    assert lineno == 18


def test_parse_no_match_returns_defaults():
    a = _make_analysis("")
    fname, lineno = _parse_vulnerable_line(a)
    assert fname == "unknown"
    assert lineno == 1


def test_parse_none_vulnerable_lines():
    a = _make_analysis(None)
    fname, lineno = _parse_vulnerable_line(a)
    assert fname == "unknown"
    assert lineno == 1


def test_parse_src_path_with_slash():
    a = _make_analysis("src/main.c:55")
    fname, lineno = _parse_vulnerable_line(a)
    assert "main.c" in fname
    assert lineno == 55


# ── generate_sarif ────────────────────────────────────────────────────────────

def test_generate_sarif_creates_file(tmp_path, minimal_result):
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    assert (tmp_path / "report.sarif").exists()


def test_generate_sarif_valid_json(tmp_path, minimal_result):
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    content = json.loads((tmp_path / "report.sarif").read_text())
    assert isinstance(content, dict)


def test_generate_sarif_version_2_1_0(tmp_path, minimal_result):
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    doc = json.loads((tmp_path / "report.sarif").read_text())
    assert doc["version"] == "2.1.0"


def test_generate_sarif_has_runs(tmp_path, minimal_result):
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    doc = json.loads((tmp_path / "report.sarif").read_text())
    assert "runs" in doc
    assert len(doc["runs"]) == 1


def test_generate_sarif_tool_name(tmp_path, minimal_result):
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    doc = json.loads((tmp_path / "report.sarif").read_text())
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mini-crs"


def test_generate_sarif_results_contain_finding(tmp_path, minimal_result):
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    doc = json.loads((tmp_path / "report.sarif").read_text())
    results = doc["runs"][0]["results"]
    assert len(results) == 1


def test_generate_sarif_fingerprint_is_stack_hash(tmp_path, minimal_result):
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    doc = json.loads((tmp_path / "report.sarif").read_text())
    result = doc["runs"][0]["results"][0]
    assert "fingerprints" in result
    assert "stackHash/v1" in result["fingerprints"]
    assert result["fingerprints"]["stackHash/v1"] == "abc123def456"


def test_generate_sarif_rule_id_contains_cwe(tmp_path, minimal_result):
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    doc = json.loads((tmp_path / "report.sarif").read_text())
    result = doc["runs"][0]["results"][0]
    assert "CWE-122" in result["ruleId"]


def test_generate_sarif_empty_findings(tmp_path, minimal_result):
    minimal_result.findings = []
    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    doc = json.loads((tmp_path / "report.sarif").read_text())
    assert doc["runs"][0]["results"] == []


def test_generate_sarif_deduplicates_rules(tmp_path, minimal_result):
    """Two findings with same CWE should produce one rule, two results."""
    from copy import deepcopy
    f2 = deepcopy(minimal_result.findings[0])
    f2.crash.crash_id = "CRASH-002"
    f2.crash.stack_hash = "deadbeef0000"
    minimal_result.findings.append(f2)

    out = str(tmp_path / "report.sarif")
    generate_sarif(minimal_result, out)
    doc = json.loads((tmp_path / "report.sarif").read_text())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]
    assert len(rules) == 1   # deduped
    assert len(results) == 2  # two findings
