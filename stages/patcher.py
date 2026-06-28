"""LLM patch generation, application, and validation."""
from __future__ import annotations
import re
import shutil
import subprocess
import tempfile
import requests
from pathlib import Path
from models import Analysis, CrashInfo, Patch, ValidationResult

OLLAMA_BASE = "http://100.126.22.55:11434"
MODEL = "hermes3:70b"
TIMEOUT = 180


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
Generate a minimal, correct patch that fixes the vulnerability without changing program behaviour.

Rules:
1. Fix ONLY the vulnerability — do not refactor or add unrelated changes
2. Preserve the existing function signatures and calling conventions
3. Use safe C idioms (strncpy with explicit null termination, snprintf, bounds checks)
4. Return a unified diff patch in this exact format:

--- a/main.c
+++ b/main.c
@@ -LINE,COUNT +LINE,COUNT @@
 context line
-removed line
+added line
 context line

Return only the unified diff. No explanation, no markdown fences."""


def _apply_patch(diff: str, source_dir: str) -> tuple[bool, str]:
    """Apply unified diff to source directory. Returns (success, output)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
        f.write(diff)
        patch_file = f.name

    result = subprocess.run(
        ["patch", "-p1", "--dry-run", "-i", patch_file],
        cwd=source_dir, capture_output=True, text=True,
    )
    if result.returncode != 0:
        return False, f"Dry-run failed:\n{result.stderr}"

    result = subprocess.run(
        ["patch", "-p1", "-i", patch_file],
        cwd=source_dir, capture_output=True, text=True,
    )
    return result.returncode == 0, result.stdout + result.stderr


def _validate_patch(
    source_dir: str,
    crash_file: str,
    output_dir: str,
) -> tuple[ValidationResult, str, str]:
    """Recompile patched source and rerun crash input. Returns (result, compile_out, run_out)."""
    from stages.builder import build_patched
    patched_binary = build_patched(source_dir, output_dir)
    if not patched_binary:
        return ValidationResult.FAILED, "Compilation failed after patching", ""

    compile_out = f"Compiled: {patched_binary}"

    import os
    env = {**os.environ, "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0"}
    try:
        result = subprocess.run(
            [patched_binary, crash_file],
            capture_output=True, text=True, timeout=10, env=env,
        )
        run_out = result.stdout + result.stderr
        if result.returncode == 0 and "ERROR" not in run_out and "ASAN" not in run_out:
            return ValidationResult.FIXED, compile_out, run_out
        elif "ASAN" in run_out or result.returncode != 0:
            return ValidationResult.FAILED, compile_out, run_out
        else:
            return ValidationResult.PARTIAL, compile_out, run_out
    except subprocess.TimeoutExpired:
        return ValidationResult.FAILED, compile_out, "[timeout — possible hang]"


def generate_patch(
    crash: CrashInfo,
    analysis: Analysis,
    source_dir: str,
    output_dir: str,
) -> Patch:
    """Generate, apply, and validate a patch for a crash."""
    src_path = Path(source_dir)
    main_c = src_path / "main.c"
    if not main_c.exists():
        c_files = list(src_path.glob("*.c"))
        if not c_files:
            return Patch(validation=ValidationResult.SKIPPED)
        main_c = c_files[0]

    source = main_c.read_text()

    # Generate patch via LLM
    prompt = _build_patch_prompt(crash, analysis, source)
    try:
        resp = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        diff = resp.json().get("response", "").strip()
    except Exception as e:
        return Patch(validation=ValidationResult.SKIPPED, validation_output=f"LLM error: {e}")

    # Extract just the unified diff portion
    diff_match = re.search(r'(---.*?\+\+\+.*?(?=\Z|\n(?![-+@ ])|\Z))', diff, re.DOTALL)
    if diff_match:
        diff = diff_match.group(0).strip()

    # Make a backup of source before patching
    backup = str(main_c) + ".orig"
    shutil.copy2(str(main_c), backup)

    # Apply patch
    applied, apply_out = _apply_patch(diff, source_dir)
    if not applied:
        # Restore backup
        shutil.copy2(backup, str(main_c))
        return Patch(
            diff=diff, applied=False,
            validation=ValidationResult.FAILED,
            validation_output=f"Patch did not apply cleanly:\n{apply_out}",
        )

    patched_source = main_c.read_text()

    # Validate
    validation, compile_out, run_out = _validate_patch(
        source_dir, crash.crash_file, output_dir
    )

    if validation != ValidationResult.FIXED:
        # Restore original on failure
        shutil.copy2(backup, str(main_c))

    return Patch(
        diff=diff,
        patched_source=patched_source,
        applied=True,
        validation=validation,
        validation_output=run_out[:2000],
        compile_output=compile_out,
    )
