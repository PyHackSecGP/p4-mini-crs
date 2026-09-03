"""Shared fixtures for P4 Mini-CRS tests."""
from __future__ import annotations
import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from models import (
    Analysis, CRSResult, CrashInfo, CrashType, Finding, Patch, ValidationResult,
)


@pytest.fixture
def minimal_crash() -> CrashInfo:
    return CrashInfo(
        crash_id="CRASH-001",
        crash_file="/tmp/id:000001",
        stack_hash="abc123def456",
        crash_type=CrashType.HEAP_OVERFLOW,
        signal="SIGSEGV",
        backtrace="#0  0x... in vulnerable_func\n#1  0x... in main\n",
        asan_output="heap-buffer-overflow\n#0 in vulnerable_func\n",
        crash_address="0xdeadbeef",
        top_frame="vulnerable_func",
    )


@pytest.fixture
def minimal_analysis() -> Analysis:
    return Analysis(
        cwe_id="CWE-122",
        cwe_name="Heap-based Buffer Overflow",
        vulnerability_type="Heap buffer overflow via unbounded strcpy",
        vulnerable_function="parse_name",
        vulnerable_lines="main.c:22",
        root_cause="strcpy writes past the 64-byte buffer boundary.",
        attack_scenario="Attacker supplies a name field > 64 bytes.",
        severity="High",
        exploitability="High",
        fix_approach="Replace strcpy with strncpy using sizeof(dest)-1.",
    )


@pytest.fixture
def minimal_patch() -> Patch:
    return Patch(
        diff="--- a/main.c\n+++ b/main.c\n@@ -20,1 +20,1 @@\n-    strcpy(dest, src);\n+    strncpy(dest, src, RECORD_SIZE - 1);\n",
        applied=True,
        validation=ValidationResult.FIXED,
    )


@pytest.fixture
def minimal_finding(minimal_crash, minimal_analysis, minimal_patch) -> Finding:
    return Finding(crash=minimal_crash, analysis=minimal_analysis, patch=minimal_patch)


@pytest.fixture
def minimal_result(minimal_finding) -> CRSResult:
    return CRSResult(
        target_name="vulnerable_parser",
        target_source="/tmp/targets/vulnerable_parser",
        binary_path="/tmp/build/target_afl",
        fuzzing_duration_seconds=60,
        total_executions=150000,
        crashes_found=3,
        unique_crashes=1,
        findings=[minimal_finding],
        generated_at="2026-09-03 12:00:00",
        llm_provider="ollama",
    )
