"""Tests for crash triage: type detection, stack hashing, deduplication."""
from __future__ import annotations
import hashlib
from unittest.mock import MagicMock, patch

import pytest

from models import CrashType
from stages.triage import (
    _detect_crash_type,
    _stack_hash,
    _top_user_frame,
    triage_crashes,
)


# ── _detect_crash_type ────────────────────────────────────────────────────────

def test_detect_heap_overflow():
    assert _detect_crash_type("ERROR: heap-buffer-overflow") == CrashType.HEAP_OVERFLOW


def test_detect_stack_overflow():
    assert _detect_crash_type("ERROR: stack-buffer-overflow") == CrashType.STACK_OVERFLOW


def test_detect_use_after_free():
    assert _detect_crash_type("ERROR: heap-use-after-free") == CrashType.USE_AFTER_FREE


def test_detect_use_after_free_variant():
    assert _detect_crash_type("use-after-free at 0x...") == CrashType.USE_AFTER_FREE


def test_detect_format_string_asan_pattern():
    assert _detect_crash_type("ERROR: format-string at 0x...") == CrashType.FORMAT_STRING


def test_detect_format_string_via_printf():
    output = "Program received signal SIGSEGV\n in vprintf () from libc\n"
    assert _detect_crash_type(output) == CrashType.FORMAT_STRING


def test_detect_format_string_via_sprintf():
    output = "in sprintf at somewhere\n"
    assert _detect_crash_type(output) == CrashType.FORMAT_STRING


def test_detect_sigabrt_maps_to_stack():
    assert _detect_crash_type("SIGABRT") == CrashType.STACK_OVERFLOW


def test_detect_sigsegv_maps_to_null_deref():
    assert _detect_crash_type("Segmentation fault") == CrashType.NULL_DEREF


def test_detect_unknown_for_unrecognized():
    assert _detect_crash_type("some random output") == CrashType.UNKNOWN


def test_detect_case_insensitive():
    assert _detect_crash_type("HEAP-BUFFER-OVERFLOW") == CrashType.HEAP_OVERFLOW


# ── _stack_hash ───────────────────────────────────────────────────────────────

def test_stack_hash_deterministic():
    bt = "#0  0x7fff in parse_name\n#1  0x7ffe in process_file\n"
    assert _stack_hash(bt) == _stack_hash(bt)


def test_stack_hash_different_inputs_differ():
    bt1 = "#0  0x7fff in parse_name\n"
    bt2 = "#0  0x7fff in log_record\n"
    assert _stack_hash(bt1) != _stack_hash(bt2)


def test_stack_hash_filters_asan_internals():
    bt_asan = "#0 in __asan::ReportGenericError\n#1 in __sanitizer::Die\n"
    bt_user = "#0 in __asan::ReportGenericError\n#1 in parse_name\n"
    # asan-only backtrace falls back to raw; user frame should be extracted
    hash_asan = _stack_hash(bt_asan)
    hash_user = _stack_hash(bt_user)
    assert isinstance(hash_asan, str) and len(hash_asan) == 12
    assert isinstance(hash_user, str) and len(hash_user) == 12


def test_stack_hash_length():
    bt = "#0  0x7fff in parse_name\n"
    result = _stack_hash(bt)
    assert len(result) == 12


def test_stack_hash_empty_falls_back():
    result = _stack_hash("")
    assert isinstance(result, str)
    assert len(result) == 12


def test_stack_hash_user_frames_take_priority():
    # GDB format requires address token between frame# and "in"
    bt = (
        "#0  0x7fff1000 in __asan::ReportGenericError\n"
        "#1  0x7fff2000 in parse_name\n"
        "#2  0x7fff3000 in process_file\n"
    )
    result = _stack_hash(bt)
    expected_frames = "parse_name|process_file"
    expected = hashlib.sha1(expected_frames.encode(), usedforsecurity=False).hexdigest()[:12]
    assert result == expected


# ── _top_user_frame ───────────────────────────────────────────────────────────

def test_top_user_frame_basic():
    bt = "#0  0x7fff in parse_name at main.c:22\n"
    assert _top_user_frame(bt) == "parse_name"


def test_top_user_frame_skips_asan():
    bt = (
        "#0 in __asan_report_load8\n"
        "#1 in parse_name at main.c:22\n"
    )
    assert _top_user_frame(bt) == "parse_name"


def test_top_user_frame_empty_returns_empty():
    assert _top_user_frame("") == ""


def test_top_user_frame_all_internal_returns_empty():
    bt = "#0 in __sanitizer::Die\n#1 in __asan::CheckUnwind\n"
    assert _top_user_frame(bt) == ""


def test_top_user_frame_strips_namespace():
    bt = "#0 in std::string::parse_name at foo.cc:10\n"
    result = _top_user_frame(bt)
    assert result == "parse_name"


# ── triage_crashes ────────────────────────────────────────────────────────────

def _make_mock_run(asan_out: str, gdb_out: str):
    """Build subprocess.run mock that distinguishes ASan (bytes) from GDB (text=True) calls."""
    def side_effect(*args, **kwargs):
        m = MagicMock()
        if kwargs.get("text"):
            # GDB call uses text=True
            m.stdout = gdb_out
            m.stderr = ""
        else:
            # ASan call: no text=True, returns bytes
            m.stdout = asan_out.encode()
            m.stderr = b""
        return m

    return side_effect


@patch("stages.triage.shutil.which", return_value="/usr/bin/gdb")
@patch("stages.triage.subprocess.run")
def test_triage_deduplicates_same_hash(mock_run, mock_which, tmp_path):
    asan_out = "heap-buffer-overflow\n"
    gdb_out = "#0  0x7fff in parse_name\n"
    mock_run.side_effect = _make_mock_run(asan_out, gdb_out)

    crash1 = str(tmp_path / "crash1")
    crash2 = str(tmp_path / "crash2")
    for p in [crash1, crash2]:
        open(p, "w").close()

    results = triage_crashes([crash1, crash2], "/fake/asan_bin", str(tmp_path / "out"))
    assert len(results) == 1


@patch("stages.triage.shutil.which", return_value="/usr/bin/gdb")
@patch("stages.triage.subprocess.run")
def test_triage_keeps_unique_hashes(mock_run, mock_which, tmp_path):
    call_count = [0]

    def side_effect(*args, **kwargs):
        m = MagicMock()
        idx = call_count[0]
        if idx % 2 == 0:
            m.stdout = b"heap-buffer-overflow\n"
            m.stderr = b""
        else:
            frame = "func_a" if (idx // 2) % 2 == 0 else "func_b"
            m.stdout = f"#0  0x7fff in {frame}\n"
            m.stderr = ""
        call_count[0] += 1
        return m

    mock_run.side_effect = side_effect

    crash1 = str(tmp_path / "crash1")
    crash2 = str(tmp_path / "crash2")
    for p in [crash1, crash2]:
        open(p, "w").close()

    results = triage_crashes([crash1, crash2], "/fake/asan_bin", str(tmp_path / "out"))
    assert len(results) == 2


@patch("stages.triage.shutil.which", return_value="/usr/bin/gdb")
@patch("stages.triage.subprocess.run")
def test_triage_handles_timeout_gracefully(mock_run, mock_which, tmp_path):
    import subprocess as sp
    call_count = [0]

    def side_effect(*args, **kwargs):
        if call_count[0] == 0:
            call_count[0] += 1
            raise sp.TimeoutExpired(cmd="asan", timeout=10)
        m = MagicMock()
        m.stdout = ""
        m.stderr = ""
        call_count[0] += 1
        return m

    mock_run.side_effect = side_effect

    crash1 = str(tmp_path / "crash1")
    open(crash1, "w").close()

    # Should not raise — timeout handled internally
    results = triage_crashes([crash1], "/fake/asan_bin", str(tmp_path / "out"))
    assert isinstance(results, list)
