"""AFL++ fuzzing wrapper."""
from __future__ import annotations
import os
import subprocess
import shutil
import time
from pathlib import Path


def run_afl(
    binary: str,
    seeds_dir: str,
    output_dir: str,
    timeout_seconds: int = 60,
) -> dict:
    """Run afl-fuzz for timeout_seconds. Returns stats dict."""
    out = Path(output_dir)
    crashes_dir = out / "default" / "crashes"
    shutil.rmtree(str(out), ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["AFL_NO_UI"] = "1"
    env["AFL_SKIP_CPUFREQ"] = "1"
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_AUTORESUME"] = "1"
    env.setdefault("AFL_MAP_SIZE", "65536")

    cmd = [
        "afl-fuzz",
        "-i", seeds_dir,
        "-o", str(out),
        "-m", "none",
        "--",
        binary, "@@",
    ]

    print(f"[fuzz] Starting AFL++ for {timeout_seconds}s ...")
    print(f"[fuzz] {' '.join(cmd)}")

    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    start = time.time()

    try:
        while time.time() - start < timeout_seconds:
            time.sleep(5)
            crash_count = len(list(crashes_dir.glob("id:*"))) if crashes_dir.exists() else 0
            elapsed = int(time.time() - start)
            print(f"[fuzz] {elapsed}s elapsed — crashes found: {crash_count}", end="\r")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()

    # Parse fuzzer_stats
    stats: dict = {}
    stats_file = out / "default" / "fuzzer_stats"
    if stats_file.exists():
        for line in stats_file.read_text().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                stats[k.strip()] = v.strip()

    crash_files = list(crashes_dir.glob("id:*")) if crashes_dir.exists() else []
    # Filter out README
    crash_files = [c for c in crash_files if not c.name.startswith("README")]

    print(f"[fuzz] Done. Crashes: {len(crash_files)} | "
          f"Execs: {stats.get('execs_done', '?')} | "
          f"Paths: {stats.get('paths_found', stats.get('corpus_count', '?'))}")

    return {
        "crash_files": [str(c) for c in crash_files],
        "stats": stats,
        "output_dir": str(out),
    }
