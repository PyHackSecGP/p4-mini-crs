"""Tests for patch generation, application, and hunk header correction."""
from __future__ import annotations
from unittest.mock import MagicMock, patch

import pytest

from models import Analysis, CrashInfo, CrashType, ValidationResult
from stages.patcher import _fix_hunk_headers, _build_patch_prompt, generate_patch


# ── _fix_hunk_headers ─────────────────────────────────────────────────────────

SIMPLE_DIFF = """\
--- a/main.c
+++ b/main.c
@@ -20,3 +20,3 @@
 void parse_name(char *dest, const char *src) {
-    strcpy(dest, src);
+    strncpy(dest, src, RECORD_SIZE - 1);
 }
"""

def test_fix_hunk_headers_correct_unchanged():
    result = _fix_hunk_headers(SIMPLE_DIFF)
    assert "@@ -20" in result
    assert "+++ b/main.c" in result


def test_fix_hunk_headers_corrects_wrong_counts():
    bad = """\
--- a/main.c
+++ b/main.c
@@ -20,99 +20,99 @@
 void parse_name(char *dest, const char *src) {
-    strcpy(dest, src);
+    strncpy(dest, src, RECORD_SIZE - 1);
 }
"""
    result = _fix_hunk_headers(bad)
    # context (2) + removed (1) = 3 old lines; context (2) + added (1) = 3 new
    assert "@@ -20,3 +20,3 @@" in result


def test_fix_hunk_headers_multi_hunk():
    multi = """\
--- a/main.c
+++ b/main.c
@@ -10,99 +10,99 @@
 int a;
-int b;
+int c;
@@ -30,99 +30,99 @@
 void foo() {
-    bad();
+    good();
 }
"""
    result = _fix_hunk_headers(multi)
    # Hunk 1: 1 context + 1 removed = 2 old; 1 context + 1 added = 2 new
    assert "@@ -10,2 +10,2 @@" in result
    # Hunk 2: 2 context + 1 removed = 3 old; 2 context + 1 added = 3 new
    assert "@@ -30,3 +30,3 @@" in result


def test_fix_hunk_headers_add_only_hunk():
    add_only = """\
--- a/main.c
+++ b/main.c
@@ -20,1 +20,99 @@
 int x;
+int y;
+int z;
"""
    result = _fix_hunk_headers(add_only)
    # 1 context = 1 old line; 1 context + 2 added = 3 new lines
    assert "@@ -20,1 +20,3 @@" in result


def test_fix_hunk_headers_preserves_non_hunk_lines():
    result = _fix_hunk_headers(SIMPLE_DIFF)
    assert "--- a/main.c" in result
    assert "+++ b/main.c" in result
    assert "strncpy" in result


# ── _build_patch_prompt ───────────────────────────────────────────────────────

def test_build_patch_prompt_contains_cwe(minimal_crash, minimal_analysis):
    prompt = _build_patch_prompt(minimal_crash, minimal_analysis, "int main() {}")
    assert "CWE-122" in prompt


def test_build_patch_prompt_contains_fix_approach(minimal_crash, minimal_analysis):
    prompt = _build_patch_prompt(minimal_crash, minimal_analysis, "int main() {}")
    assert "strncpy" in prompt


def test_build_patch_prompt_contains_source(minimal_crash, minimal_analysis):
    prompt = _build_patch_prompt(minimal_crash, minimal_analysis, "void parse_name() { strcpy(a,b); }")
    assert "strcpy" in prompt


def test_build_patch_prompt_requests_unified_diff(minimal_crash, minimal_analysis):
    prompt = _build_patch_prompt(minimal_crash, minimal_analysis, "int main() {}")
    assert "unified diff" in prompt.lower() or "unified" in prompt


# ── generate_patch ────────────────────────────────────────────────────────────

def test_generate_patch_no_c_files_returns_skipped(tmp_path, minimal_crash, minimal_analysis):
    provider = MagicMock()
    result = generate_patch(minimal_crash, minimal_analysis, str(tmp_path), str(tmp_path / "out"), provider)
    assert result.validation == ValidationResult.SKIPPED
    provider.generate.assert_not_called()


def test_generate_patch_provider_exception_returns_skipped(tmp_path, minimal_crash, minimal_analysis):
    (tmp_path / "main.c").write_text("int main() { return 0; }")
    provider = MagicMock()
    provider.generate.side_effect = RuntimeError("LLM down")
    result = generate_patch(minimal_crash, minimal_analysis, str(tmp_path), str(tmp_path / "out"), provider)
    assert result.validation == ValidationResult.SKIPPED


@patch("stages.patcher.subprocess.run")
def test_generate_patch_dry_run_fails_returns_failed(mock_run, tmp_path, minimal_crash, minimal_analysis):
    (tmp_path / "main.c").write_text("int main() { return 0; }")
    provider = MagicMock()
    provider.generate.return_value = SIMPLE_DIFF

    dry_run_result = MagicMock()
    dry_run_result.returncode = 1
    dry_run_result.stderr = "patch failed"
    dry_run_result.stdout = ""
    mock_run.return_value = dry_run_result

    result = generate_patch(minimal_crash, minimal_analysis, str(tmp_path), str(tmp_path / "out"), provider)
    assert result.validation == ValidationResult.FAILED
    assert result.applied is False


def test_generate_patch_restores_original_after_run(tmp_path, minimal_crash, minimal_analysis):
    """Source file must be restored to original content regardless of patch outcome."""
    original_content = "int main() { return 0; }\n"
    main_c = tmp_path / "main.c"
    main_c.write_text(original_content)

    provider = MagicMock()
    provider.generate.return_value = "not a valid diff"

    with patch("stages.patcher.subprocess.run") as mock_run:
        m = MagicMock()
        m.returncode = 1
        m.stderr = "failed"
        m.stdout = ""
        mock_run.return_value = m
        generate_patch(minimal_crash, minimal_analysis, str(tmp_path), str(tmp_path / "out"), provider)

    assert main_c.read_text() == original_content
