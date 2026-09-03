"""Tests for data models."""
from __future__ import annotations
import pytest
from models import (
    Analysis, CRSResult, CrashInfo, CrashType, Finding, Patch, ValidationResult,
)


def test_crash_type_values():
    assert CrashType.HEAP_OVERFLOW == "Heap Buffer Overflow"
    assert CrashType.STACK_OVERFLOW == "Stack Buffer Overflow"
    assert CrashType.USE_AFTER_FREE == "Use After Free"
    assert CrashType.FORMAT_STRING == "Format String"
    assert CrashType.NULL_DEREF == "Null Dereference"
    assert CrashType.INTEGER_OVERFLOW == "Integer Overflow"
    assert CrashType.UNKNOWN == "Unknown"


def test_validation_result_values():
    assert ValidationResult.FIXED == "Fixed"
    assert ValidationResult.FAILED == "Failed"
    assert ValidationResult.SKIPPED == "Skipped"


def test_validation_result_no_partial():
    values = [v.value for v in ValidationResult]
    assert "Partial" not in values


def test_crs_result_fixed_count_zero(minimal_result):
    minimal_result.findings[0].patch.validation = ValidationResult.FAILED
    assert minimal_result.fixed_count == 0


def test_crs_result_fixed_count_one(minimal_result):
    minimal_result.findings[0].patch.validation = ValidationResult.FIXED
    assert minimal_result.fixed_count == 1


def test_crs_result_patched_count_zero(minimal_result):
    minimal_result.findings[0].patch.applied = False
    assert minimal_result.patched_count == 0


def test_crs_result_patched_count_one(minimal_result):
    minimal_result.findings[0].patch.applied = True
    assert minimal_result.patched_count == 1


def test_analysis_default_severity():
    a = Analysis()
    assert a.severity == "High"


def test_analysis_default_exploitability():
    a = Analysis()
    assert a.exploitability == "Medium"


def test_patch_default_validation():
    p = Patch()
    assert p.validation == ValidationResult.SKIPPED


def test_patch_default_applied():
    p = Patch()
    assert p.applied is False


def test_finding_default_factories():
    crash = CrashInfo(crash_id="X", crash_file="/tmp/x", stack_hash="abc")
    f = Finding(crash=crash)
    assert isinstance(f.analysis, Analysis)
    assert isinstance(f.patch, Patch)


def test_crs_result_multiple_findings():
    crash1 = CrashInfo(crash_id="C1", crash_file="/tmp/1", stack_hash="aaa")
    crash2 = CrashInfo(crash_id="C2", crash_file="/tmp/2", stack_hash="bbb")
    f1 = Finding(crash=crash1, patch=Patch(applied=True, validation=ValidationResult.FIXED))
    f2 = Finding(crash=crash2, patch=Patch(applied=True, validation=ValidationResult.FAILED))
    result = CRSResult(
        target_name="t", target_source="s", binary_path="b", findings=[f1, f2],
    )
    assert result.fixed_count == 1
    assert result.patched_count == 2
