"""Crash triage: GDB stack traces, ASan output, deduplication."""
from __future__ import annotations
import hashlib
import re
import subprocess
import shutil
from pathlib import Path
from models import CrashInfo, CrashType


_GDB_SCRIPT = """set pagination off
set print thread-events off
run {input_file}
bt
info registers
quit
"""

_ASAN_PATTERNS: list[tuple[re.Pattern, CrashType]] = [
    (re.compile(r"stack-buffer-overflow",              re.I), CrashType.STACK_OVERFLOW),
    (re.compile(r"heap-buffer-overflow",               re.I), CrashType.HEAP_OVERFLOW),
    (re.compile(r"heap-use-after-free|use-after-free", re.I), CrashType.USE_AFTER_FREE),
    (re.compile(r"format-string|interceptors_format",  re.I), CrashType.FORMAT_STRING),
    (re.compile(r"integer.*overflow",                  re.I), CrashType.INTEGER_OVERFLOW),
    (re.compile(r"null.*dereference|SEGV.*0x0",        re.I), CrashType.NULL_DEREF),
]

# ASan/sanitizer internal frame prefixes to skip when finding real crash location
_ASAN_INTERNAL = re.compile(
    r"(__asan|__sanitizer|__interceptor|printf_common|CheckFailed|CheckUnwind|"
    r"asan_rtl|asan_interceptor|_start|libc\.so|libpthread)",
    re.I,
)


def _detect_crash_type(output: str) -> CrashType:
    for pattern, ctype in _ASAN_PATTERNS:
        if pattern.search(output):
            return ctype
    # Format string crashes often appear as SIGSEGV inside printf/vprintf
    if re.search(r"in\s+(v?printf|vfprintf|sprintf|vsnprintf)", output, re.I):
        return CrashType.FORMAT_STRING
    if "SIGABRT" in output:
        return CrashType.STACK_OVERFLOW
    if "SIGSEGV" in output or "Segmentation fault" in output:
        return CrashType.NULL_DEREF
    return CrashType.UNKNOWN


def _stack_hash(backtrace: str) -> str:
    """Hash top 5 user-code frame function names for deduplication."""
    all_frames = re.findall(r"#\d+\s+\S+\s+in\s+(\S+)", backtrace)
    user_frames = [f for f in all_frames if not _ASAN_INTERNAL.search(f)][:5]
    frames = user_frames if user_frames else all_frames[:5]
    key = "|".join(frames) if frames else backtrace[:200]
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def _top_user_frame(combined: str) -> str:
    """Return first non-ASan-internal function name from backtrace."""
    for match in re.finditer(r"in\s+(\S+)\s", combined):
        fname = match.group(1)
        if not _ASAN_INTERNAL.search(fname):
            # Strip namespace/path separators
            return fname.split("::")[-1].split("/")[-1]
    return ""


def _run_asan(binary: str, crash_file: str) -> str:
    """Run ASan binary with crash input, capture output."""
    env_extra = {"ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0:print_stats=1"}
    import os
    env = {**os.environ, **env_extra}
    result = subprocess.run(
        [binary, crash_file],
        capture_output=True, timeout=10, env=env,
    )
    return (result.stdout + result.stderr).decode('utf-8', errors='replace')


def _run_gdb(binary: str, crash_file: str) -> str:
    """Run GDB in batch mode, capture backtrace."""
    if not shutil.which("gdb"):
        return ""
    script = _GDB_SCRIPT.format(input_file=crash_file)
    result = subprocess.run(
        ["gdb", "-batch", "-ex", f"file {binary}",
         "-ex", f"run {crash_file}", "-ex", "bt", "-ex", "quit"],
        capture_output=True, text=True, timeout=15,
    )
    return result.stdout + result.stderr


def triage_crashes(
    crash_files: list[str],
    asan_binary: str,
    output_dir: str,
) -> list[CrashInfo]:
    """Triage all crash files. Return deduplicated CrashInfo list."""
    seen_hashes: set[str] = set()
    findings: list[CrashInfo] = []
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    for i, crash_file in enumerate(crash_files):
        crash_id = f"CRASH-{i+1:03d}"
        print(f"[triage] {crash_id}: {Path(crash_file).name}")

        try:
            asan_out = _run_asan(asan_binary, crash_file)
        except subprocess.TimeoutExpired:
            asan_out = "[timeout]"
        except Exception as e:
            asan_out = f"[error: {e}]"

        try:
            gdb_out = _run_gdb(asan_binary, crash_file)
        except Exception:
            gdb_out = ""

        combined = asan_out + gdb_out
        stack_hash = _stack_hash(combined)

        if stack_hash in seen_hashes:
            print(f"[triage] {crash_id}: duplicate (hash {stack_hash}) — skipping")
            continue
        seen_hashes.add(stack_hash)

        crash_type = _detect_crash_type(asan_out)

        top_frame = _top_user_frame(combined)

        # Extract crash address
        addr_match = re.search(r"0x[0-9a-fA-F]{8,}", asan_out)
        crash_address = addr_match.group(0) if addr_match else ""

        # Detect signal
        signal = "SIGSEGV"
        if "SIGABRT" in combined:
            signal = "SIGABRT"
        elif "SIGFPE" in combined:
            signal = "SIGFPE"

        ci = CrashInfo(
            crash_id=crash_id,
            crash_file=crash_file,
            stack_hash=stack_hash,
            crash_type=crash_type,
            signal=signal,
            backtrace=gdb_out[:3000],
            asan_output=asan_out[:4000],
            crash_address=crash_address,
            top_frame=top_frame,
        )
        findings.append(ci)
        print(f"[triage] {crash_id}: {crash_type.value} @ {top_frame} (hash {stack_hash})")

    print(f"[triage] {len(findings)} unique crashes from {len(crash_files)} total")
    return findings
