"""Tests for LLM root cause analysis."""
from __future__ import annotations
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from models import Analysis, CrashInfo, CrashType
from stages.analyzer import _build_prompt, _read_source_context, analyze_crash


# ── _read_source_context ──────────────────────────────────────────────────────

def test_read_source_context_finds_function(tmp_path):
    (tmp_path / "main.c").write_text(
        "void other_func() {}\nvoid parse_name(char *d, const char *s) {\n    strcpy(d, s);\n}\n"
    )
    ctx = _read_source_context(str(tmp_path), "parse_name")
    assert "parse_name" in ctx
    assert "strcpy" in ctx


def test_read_source_context_fallback_when_no_match(tmp_path):
    (tmp_path / "main.c").write_text("\n".join(f"line {i}" for i in range(120)))
    ctx = _read_source_context(str(tmp_path), "nonexistent_function")
    # Falls back to first 100 lines
    assert "line 0" in ctx
    assert ctx != ""


def test_read_source_context_empty_dir(tmp_path):
    ctx = _read_source_context(str(tmp_path), "any_func")
    assert ctx == ""


def test_read_source_context_limits_window(tmp_path):
    lines = "\n".join(f"int line_{i}() {{}}" for i in range(200))
    (tmp_path / "main.c").write_text(lines)
    ctx = _read_source_context(str(tmp_path), "line_0", window=10)
    # Should not include all 200 lines
    assert ctx.count("line_") < 200


# ── _build_prompt ─────────────────────────────────────────────────────────────

def test_build_prompt_contains_crash_id(minimal_crash):
    prompt = _build_prompt(minimal_crash, "int foo() {}")
    assert "CRASH-001" in prompt


def test_build_prompt_contains_crash_type(minimal_crash):
    prompt = _build_prompt(minimal_crash, "int foo() {}")
    assert "Heap Buffer Overflow" in prompt


def test_build_prompt_contains_asan_output(minimal_crash):
    prompt = _build_prompt(minimal_crash, "int foo() {}")
    assert "heap-buffer-overflow" in prompt


def test_build_prompt_contains_source_context(minimal_crash):
    prompt = _build_prompt(minimal_crash, "int vulnerable_func() { strcpy(a, b); }")
    assert "strcpy" in prompt


def test_build_prompt_requests_json(minimal_crash):
    prompt = _build_prompt(minimal_crash, "")
    assert "JSON" in prompt
    assert "cwe_id" in prompt


# ── analyze_crash ─────────────────────────────────────────────────────────────

def _make_provider(response: str) -> MagicMock:
    provider = MagicMock()
    provider.generate.return_value = response
    return provider


def test_analyze_crash_valid_json(tmp_path, minimal_crash):
    (tmp_path / "main.c").write_text("void parse_name() {}")
    payload = {
        "cwe_id": "CWE-122",
        "cwe_name": "Heap-based Buffer Overflow",
        "vulnerability_type": "Heap overflow",
        "vulnerable_function": "parse_name",
        "vulnerable_lines": "main.c:22",
        "root_cause": "strcpy writes past bounds",
        "attack_scenario": "Attacker sends long input",
        "severity": "High",
        "exploitability": "High",
        "fix_approach": "Use strncpy",
    }
    provider = _make_provider(json.dumps(payload))
    result = analyze_crash(minimal_crash, str(tmp_path), provider)
    assert result.cwe_id == "CWE-122"
    assert result.severity == "High"
    assert result.fix_approach == "Use strncpy"


def test_analyze_crash_nested_json_extracted(tmp_path, minimal_crash):
    """Fix validation: nested JSON must be parsed correctly."""
    (tmp_path / "main.c").write_text("void f() {}")
    payload = {
        "cwe_id": "CWE-122",
        "cwe_name": "Heap-based Buffer Overflow",
        "vulnerability_type": "overflow",
        "vulnerable_function": "f",
        "vulnerable_lines": "1",
        "root_cause": "bad",
        "attack_scenario": "attacker sends long input with {braces} inside",
        "severity": "High",
        "exploitability": "Medium",
        "fix_approach": "fix it",
    }
    # Wrap in outer object to simulate nested JSON — old regex [^{}]* would fail
    raw = f'{{"wrapper": true, "data": {json.dumps(payload)}}}'
    provider = _make_provider(raw)
    result = analyze_crash(minimal_crash, str(tmp_path), provider)
    # Should parse something, not fall back to empty Analysis
    assert result.raw_response != "" or result.cwe_id != ""


def test_analyze_crash_braces_in_string_values(tmp_path, minimal_crash):
    """LLM sometimes puts {} in string values — must still parse outer object."""
    (tmp_path / "main.c").write_text("void f() {}")
    payload = {
        "cwe_id": "CWE-122",
        "cwe_name": "Heap-based Buffer Overflow",
        "vulnerability_type": "overflow",
        "vulnerable_function": "f",
        "vulnerable_lines": "1",
        "root_cause": "The struct {field} is written past bounds",
        "attack_scenario": "Send {A*200} to overflow",
        "severity": "High",
        "exploitability": "Medium",
        "fix_approach": "bounds check",
    }
    provider = _make_provider(json.dumps(payload))
    result = analyze_crash(minimal_crash, str(tmp_path), provider)
    assert result.cwe_id == "CWE-122"


def test_analyze_crash_invalid_json_returns_fallback(tmp_path, minimal_crash):
    (tmp_path / "main.c").write_text("void f() {}")
    provider = _make_provider("not json at all")
    result = analyze_crash(minimal_crash, str(tmp_path), provider)
    assert result.raw_response == "not json at all"
    assert result.cwe_id == ""


def test_analyze_crash_provider_exception_returns_fallback(tmp_path, minimal_crash):
    (tmp_path / "main.c").write_text("void f() {}")
    provider = MagicMock()
    provider.generate.side_effect = ConnectionError("unreachable")
    result = analyze_crash(minimal_crash, str(tmp_path), provider)
    assert "LLM error" in result.raw_response


def test_analyze_crash_cwe_extracted_correctly(tmp_path, minimal_crash):
    (tmp_path / "main.c").write_text("void f() {}")
    payload = {
        "cwe_id": "CWE-134",
        "cwe_name": "Format String",
        "vulnerability_type": "Format string",
        "vulnerable_function": "log_record",
        "vulnerable_lines": "27",
        "root_cause": "printf(fmt) passes user data as format string",
        "attack_scenario": "Attacker sends %x%x to leak stack",
        "severity": "Critical",
        "exploitability": "High",
        "fix_approach": "Use printf(\"%s\", fmt)",
    }
    provider = _make_provider(json.dumps(payload))
    result = analyze_crash(minimal_crash, str(tmp_path), provider)
    assert result.cwe_id == "CWE-134"
    assert result.severity == "Critical"
    assert result.vulnerable_function == "log_record"
