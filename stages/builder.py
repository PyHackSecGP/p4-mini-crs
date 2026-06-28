"""Compile target with AFL++ instrumentation and AddressSanitizer."""
from __future__ import annotations
import subprocess
import shutil
from pathlib import Path


def find_compiler() -> tuple[str, str]:
    """Return (afl_compiler, asan_compiler) available on system."""
    for afl in ("afl-clang-fast", "afl-clang", "afl-gcc"):
        if shutil.which(afl):
            asan = "clang" if "clang" in afl else "gcc"
            return afl, asan
    raise RuntimeError("No AFL++ compiler found. Install afl++ first.")


def build_afl(source_dir: str, output_dir: str) -> str:
    """Compile all .c files in source_dir with AFL++ instrumentation + ASan.
    Returns path to instrumented binary."""
    src = Path(source_dir)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    afl_cc, _ = find_compiler()
    sources = list(src.glob("*.c"))
    if not sources:
        raise FileNotFoundError(f"No .c files found in {source_dir}")

    binary = out / "target_afl"
    cmd = [
        afl_cc,
        "-fsanitize=address",
        "-g", "-O1",
        "-o", str(binary),
    ] + [str(s) for s in sources]

    print(f"[build] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"AFL build failed:\n{result.stderr}")

    print(f"[build] Instrumented binary: {binary}")
    return str(binary)


def build_asan(source_dir: str, output_dir: str) -> str:
    """Compile with plain ASan (no AFL) for crash reproduction."""
    src = Path(source_dir)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    sources = list(src.glob("*.c"))
    compiler = "clang" if shutil.which("clang") else "gcc"

    binary = out / "target_asan"
    cmd = [
        compiler,
        "-fsanitize=address",
        "-g", "-O0",
        "-o", str(binary),
    ] + [str(s) for s in sources]

    print(f"[build] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ASan build failed:\n{result.stderr}")

    print(f"[build] ASan binary: {binary}")
    return str(binary)


def build_patched(source_dir: str, output_dir: str) -> str:
    """Compile patched source (no instrumentation) to verify fix."""
    src = Path(source_dir)
    out = Path(output_dir)
    sources = list(src.glob("*.c"))
    compiler = "clang" if shutil.which("clang") else "gcc"

    binary = out / "target_patched"
    cmd = [
        compiler,
        "-fsanitize=address",
        "-g", "-O0",
        "-o", str(binary),
    ] + [str(s) for s in sources]

    result = subprocess.run(cmd, capture_output=True, text=True)
    return str(binary) if result.returncode == 0 else ""
