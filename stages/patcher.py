"""LLM patch generation, application, and validation — provider-agnostic."""
from __future__ import annotations
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from models import Analysis, CrashInfo, Patch, ValidationResult
from engine.llm_provider import LLMProvider


def _build_patch_prompt(crash: CrashInfo, analysis: Analysis, source: str) -> str:
    return f"""You are a security engineer fixing a vulnerability in C code.

## Vulnerability
- Type: {analysis.vulnerability_type}
- CWE: {analysis.cwe_id} — {analysis.cwe_name}
- Vulnerable function: {analysis.vulnerable_function}
- Vulnerable lines: {analysis.vulnerable_lines}
- Root cause: {analysis.root_cause}
- Fix approach: {analysis.fix_approach}

## Current Source Code
{source}

## Task
Generate a minimal, correct patch that fixes only this vulnerability without changing program behaviour.

Rules:
1. Fix ONLY the vulnerability — no refactoring, no unrelated changes
2. Preserve existing function signatures and calling conventions
3. Use safe C idioms (snprintf, strncpy with explicit null-termination, bounds checks)
4. Return a unified diff in this exact format:

--- a/main.c
+++ b/main.c
@@ -LINE,COUNT +LINE,COUNT @@
 context line
-removed line
+added line
 context line

Return only the unified diff. No markdown fences, no explanation."""


def _apply_patch(diff: str, source_dir: str) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
        f.write(diff)
        patch_file = f.name

    dry = subprocess.run(
        ["patch", "-p1", "--dry-run", "-i", patch_file],
        cwd=source_dir, capture_output=True, text=True,
    )
    if dry.returncode != 0:
        return False, f"Dry-run failed:\n{dry.stderr}"

    result = subprocess.run(
        ["patch", "-p1", "-i", patch_file],
        cwd=source_dir, capture_output=True, text=True,
    )
    return result.returncode == 0, result.stdout + result.stderr


def _validate_patch(source_dir: str, crash_file: str, output_dir: str) -> tuple[ValidationResult, str, str]:
    from stages.builder import build_patched
    import os

    patched_binary = build_patched(source_dir, output_dir)
    if not patched_binary:
        return ValidationResult.FAILED, "Compilation failed after patching", ""

    env = {**os.environ, "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0"}
    try:
        result = subprocess.run(
            [patched_binary, crash_file],
            capture_output=True, timeout=10, env=env,
        )
        run_out = (result.stdout + result.stderr).decode('utf-8', errors='replace')
        if result.returncode == 0 and "ERROR" not in run_out and "CHECK failed" not in run_out:
            return ValidationResult.FIXED, f"Compiled: {patched_binary}", run_out
        return ValidationResult.FAILED, f"Compiled: {patched_binary}", run_out
    except subprocess.TimeoutExpired:
        return ValidationResult.FAILED, f"Compiled: {patched_binary}", "[timeout]"


def generate_patch(
    crash: CrashInfo,
    analysis: Analysis,
    source_dir: str,
    output_dir: str,
    provider: LLMProvider,
) -> Patch:
    """Generate, apply, and validate a patch using the given LLM provider."""
    src_path = Path(source_dir)
    c_files = list(src_path.glob("*.c"))
    if not c_files:
        return Patch(validation=ValidationResult.SKIPPED)
    main_c = next((f for f in c_files if f.name == "main.c"), c_files[0])

    source = main_c.read_text()
    prompt = _build_patch_prompt(crash, analysis, source)

    try:
        diff = provider.generate(prompt)
    except Exception as e:
        return Patch(validation=ValidationResult.SKIPPED, validation_output=f"LLM error: {e}")

    # Extract unified diff portion
    diff_match = re.search(r'(---\s+a/.*?\+\+\+\s+b/.*?(?=\Z))', diff, re.DOTALL)
    if diff_match:
        diff = diff_match.group(0).strip()

    backup = str(main_c) + ".orig"
    shutil.copy2(str(main_c), backup)

    applied, apply_out = _apply_patch(diff, source_dir)
    if not applied:
        shutil.copy2(backup, str(main_c))
        return Patch(
            diff=diff, applied=False,
            validation=ValidationResult.FAILED,
            validation_output=f"Patch did not apply:\n{apply_out}",
        )

    patched_source = main_c.read_text()
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    validation, compile_out, run_out = _validate_patch(source_dir, crash.crash_file, output_dir)

    # Always restore original so the target stays vulnerable between runs
    shutil.copy2(backup, str(main_c))

    return Patch(
        diff=diff,
        patched_source=patched_source,
        applied=True,
        validation=validation,
        validation_output=run_out[:2000],
        compile_output=compile_out,
    )
