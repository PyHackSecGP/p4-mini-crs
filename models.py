"""Data models for P4 Mini-CRS."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class CrashType(str, Enum):
    STACK_OVERFLOW  = "Stack Buffer Overflow"
    HEAP_OVERFLOW   = "Heap Buffer Overflow"
    USE_AFTER_FREE  = "Use After Free"
    FORMAT_STRING   = "Format String"
    NULL_DEREF      = "Null Dereference"
    INTEGER_OVERFLOW= "Integer Overflow"
    UNKNOWN         = "Unknown"


class ValidationResult(str, Enum):
    FIXED    = "Fixed"
    PARTIAL  = "Partial"
    FAILED   = "Failed"
    SKIPPED  = "Skipped"


@dataclass
class CrashInfo:
    crash_id: str
    crash_file: str
    stack_hash: str
    crash_type: CrashType = CrashType.UNKNOWN
    signal: str = ""
    backtrace: str = ""
    asan_output: str = ""
    crash_address: str = ""
    top_frame: str = ""


@dataclass
class Analysis:
    cwe_id: str = ""
    cwe_name: str = ""
    vulnerability_type: str = ""
    vulnerable_function: str = ""
    vulnerable_lines: str = ""
    root_cause: str = ""
    attack_scenario: str = ""
    severity: str = "High"
    exploitability: str = "Medium"
    fix_approach: str = ""
    raw_response: str = ""


@dataclass
class Patch:
    diff: str = ""
    patched_source: str = ""
    applied: bool = False
    validation: ValidationResult = ValidationResult.SKIPPED
    validation_output: str = ""
    compile_output: str = ""


@dataclass
class Finding:
    crash: CrashInfo
    analysis: Analysis = field(default_factory=Analysis)
    patch: Patch = field(default_factory=Patch)
    source_context: str = ""


@dataclass
class CRSResult:
    target_name: str
    target_source: str
    binary_path: str
    fuzzing_duration_seconds: int = 0
    total_executions: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    findings: list[Finding] = field(default_factory=list)
    generated_at: str = ""
    llm_provider: str = ""

    @property
    def fixed_count(self) -> int:
        return sum(1 for f in self.findings if f.patch.validation == ValidationResult.FIXED)

    @property
    def patched_count(self) -> int:
        return sum(1 for f in self.findings if f.patch.applied)
