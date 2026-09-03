"""Tests for HTML report generation."""
from __future__ import annotations
import pytest
from models import ValidationResult
from stages.reporter import _escape, _val_badge, _sev_badge, generate_html


# ── _escape ───────────────────────────────────────────────────────────────────

def test_escape_ampersand():
    assert _escape("a & b") == "a &amp; b"


def test_escape_less_than():
    assert _escape("<script>") == "&lt;script&gt;"


def test_escape_greater_than():
    assert _escape("a > b") == "a &gt; b"


def test_escape_no_special_chars():
    assert _escape("plain text") == "plain text"


def test_escape_empty():
    assert _escape("") == ""


# ── _val_badge ────────────────────────────────────────────────────────────────

def test_val_badge_fixed_green():
    badge = _val_badge(ValidationResult.FIXED)
    assert "#44bb44" in badge
    assert "FIXED" in badge


def test_val_badge_failed_red():
    badge = _val_badge(ValidationResult.FAILED)
    assert "#ff4444" in badge
    assert "FAILED" in badge


def test_val_badge_skipped():
    badge = _val_badge(ValidationResult.SKIPPED)
    assert "SKIPPED" in badge


# ── _sev_badge ────────────────────────────────────────────────────────────────

def test_sev_badge_critical():
    badge = _sev_badge("Critical")
    assert "#ff4444" in badge
    assert "Critical" in badge


def test_sev_badge_high():
    badge = _sev_badge("High")
    assert "#ff8800" in badge


def test_sev_badge_medium():
    badge = _sev_badge("Medium")
    assert "#ffcc00" in badge


def test_sev_badge_unknown_severity():
    badge = _sev_badge("Unknown")
    assert "Unknown" in badge


# ── generate_html ─────────────────────────────────────────────────────────────

def test_generate_html_creates_file(tmp_path, minimal_result):
    out = str(tmp_path / "report.html")
    generate_html(minimal_result, out)
    assert (tmp_path / "report.html").exists()


def test_generate_html_contains_target_name(tmp_path, minimal_result):
    out = str(tmp_path / "report.html")
    generate_html(minimal_result, out)
    content = (tmp_path / "report.html").read_text()
    assert "vulnerable_parser" in content


def test_generate_html_contains_crash_id(tmp_path, minimal_result):
    out = str(tmp_path / "report.html")
    generate_html(minimal_result, out)
    content = (tmp_path / "report.html").read_text()
    assert "CRASH-001" in content


def test_generate_html_contains_cwe(tmp_path, minimal_result):
    out = str(tmp_path / "report.html")
    generate_html(minimal_result, out)
    content = (tmp_path / "report.html").read_text()
    assert "CWE-122" in content


def test_generate_html_contains_fixed_badge(tmp_path, minimal_result):
    out = str(tmp_path / "report.html")
    generate_html(minimal_result, out)
    content = (tmp_path / "report.html").read_text()
    assert "FIXED" in content


def test_generate_html_escapes_asan_output(tmp_path, minimal_result):
    minimal_result.findings[0].crash.asan_output = "<script>alert(1)</script>"
    out = str(tmp_path / "report.html")
    generate_html(minimal_result, out)
    content = (tmp_path / "report.html").read_text()
    assert "<script>" not in content
    assert "&lt;script&gt;" in content


def test_generate_html_no_findings(tmp_path, minimal_result):
    minimal_result.findings = []
    out = str(tmp_path / "report.html")
    generate_html(minimal_result, out)
    content = (tmp_path / "report.html").read_text()
    assert "No crashes" in content


def test_generate_html_stats_present(tmp_path, minimal_result):
    out = str(tmp_path / "report.html")
    generate_html(minimal_result, out)
    content = (tmp_path / "report.html").read_text()
    # Crash count stats
    assert "150,000" in content or "150000" in content or "60" in content
