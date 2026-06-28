#!/usr/bin/env python3
"""
P4 — Mini-CRS: Automated Vulnerability Discovery and Patch Suggestion
Inspired by DARPA AIxCC. Pipeline: AFL++ → ASan/GDB triage → LLM root cause → LLM patch → validate.
"""
from __future__ import annotations
import argparse
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from models import CRSResult, Finding
from stages.builder import build_afl, build_asan
from stages.fuzzer import run_afl
from stages.triage import triage_crashes
from stages.analyzer import analyze_crash
from stages.patcher import generate_patch
from stages.reporter import generate_html
from engine.llm_provider import provider_from_args, get_provider


def main() -> None:
    parser = argparse.ArgumentParser(
        description="P4 Mini-CRS — Autonomous Vulnerability Discovery & Patch Suggestion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline on built-in demo target
  python crs.py --target targets/vulnerable_parser --output output/ --fuzz-time 60

  # Skip fuzzing, triage existing crashes
  python crs.py --target targets/vulnerable_parser --crashes path/to/crashes/ --no-fuzz

  # Disable LLM (analysis + patching still run rule-based)
  python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 30
        """,
    )
    parser.add_argument("--target",   "-t", default="targets/vulnerable_parser",
                        help="Path to target source directory (default: targets/vulnerable_parser)")
    parser.add_argument("--seeds",    "-s", default="",
                        help="Seed corpus directory (default: <target>/seeds/)")
    parser.add_argument("--output",   "-o", default="output",
                        help="Output directory (default: ./output)")
    parser.add_argument("--fuzz-time","-f", type=int, default=60,
                        help="Fuzzing duration in seconds (default: 60)")
    parser.add_argument("--no-fuzz",  action="store_true",
                        help="Skip fuzzing — use --crashes instead")
    parser.add_argument("--crashes",  default="",
                        help="Directory of existing crash files (use with --no-fuzz)")
    parser.add_argument("--no-llm",      action="store_true",
                        help="Skip LLM analysis and patching")
    parser.add_argument("--llm-provider", default="ollama",
                        choices=["ollama", "claude", "openai", "openai-compat"],
                        help="LLM backend (default: ollama)")
    parser.add_argument("--llm-model",   default="",
                        help="Model name override (e.g. claude-sonnet-4-6, gpt-4o, hermes3:70b)")
    parser.add_argument("--llm-endpoint", default="",
                        help="API endpoint URL (ollama default: http://100.126.22.55:11434, "
                             "required for openai-compat)")
    parser.add_argument("--llm-api-key", default="",
                        help="API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY env vars)")
    parser.add_argument("--max-crashes", type=int, default=10,
                        help="Max unique crashes to analyse (default: 10)")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    seeds_dir  = Path(args.seeds).resolve() if args.seeds else target_dir / "seeds"
    output_dir = Path(args.output).resolve()
    afl_out    = output_dir / "afl_output"
    build_out  = output_dir / "build"
    output_dir.mkdir(parents=True, exist_ok=True)

    target_name = target_dir.name
    print(f"\n{'='*60}")
    print(f"  P4 Mini-CRS — {target_name}")
    print(f"{'='*60}\n")

    # ── Stage 1: Build ───────────────────────────────────────────
    print("[*] Stage 1: Building target...")
    try:
        afl_binary  = build_afl(str(target_dir), str(build_out))
        asan_binary = build_asan(str(target_dir), str(build_out))
    except Exception as e:
        print(f"[!] Build failed: {e}")
        sys.exit(1)
    print(f"[+] Build complete\n")

    # ── Stage 2: Fuzz ────────────────────────────────────────────
    crash_files: list[str] = []
    fuzz_stats: dict = {}
    fuzz_duration = 0

    if args.no_fuzz:
        if args.crashes:
            crash_files = [str(p) for p in Path(args.crashes).glob("id:*")]
            print(f"[*] Stage 2: Skipped (using {len(crash_files)} existing crashes)\n")
        else:
            print("[!] --no-fuzz requires --crashes <dir>")
            sys.exit(1)
    else:
        print(f"[*] Stage 2: Fuzzing for {args.fuzz_time}s...")
        import time
        t0 = time.time()
        fuzz_result = run_afl(afl_binary, str(seeds_dir), str(afl_out), args.fuzz_time)
        fuzz_duration = int(time.time() - t0)
        crash_files = fuzz_result["crash_files"]
        fuzz_stats  = fuzz_result["stats"]
        print(f"[+] Fuzzing done: {len(crash_files)} crash file(s)\n")

    if not crash_files:
        print("[!] No crashes found. Try longer --fuzz-time or add more seeds.")
        # Generate empty report
        result = CRSResult(
            target_name=target_name, target_source=str(target_dir),
            binary_path=afl_binary, fuzzing_duration_seconds=fuzz_duration,
            total_executions=int(fuzz_stats.get("execs_done", 0)),
            crashes_found=0, unique_crashes=0, generated_at=_now(),
            llm_provider="" if args.no_llm else args.llm_provider,
        )
        report_path = output_dir / f"{target_name}_crs_report.html"
        generate_html(result, str(report_path))
        print(f"[+] Report: {report_path}")
        return

    # ── Stage 3: Triage ──────────────────────────────────────────
    print(f"[*] Stage 3: Triaging {len(crash_files)} crash file(s)...")
    triage_out = output_dir / "triage"
    crashes = triage_crashes(crash_files, asan_binary, str(triage_out))
    crashes = crashes[:args.max_crashes]
    print(f"[+] {len(crashes)} unique crash(es) after dedup\n")

    # ── Stage 4 & 5: Analyse + Patch ─────────────────────────────
    provider = None
    if not args.no_llm:
        try:
            provider = provider_from_args(args)
            if provider and not provider.is_available():
                print(f"[!] {provider} unreachable — skipping LLM (use --no-llm to suppress)\n")
                provider = None
            elif provider:
                print(f"[+] LLM provider: {provider}\n")
        except Exception as e:
            print(f"[!] LLM setup failed: {e} — skipping\n")
            provider = None

    findings: list[Finding] = []
    for crash in crashes:
        print(f"[*] Processing {crash.crash_id}: {crash.crash_type.value} @ {crash.top_frame}")
        finding = Finding(crash=crash)

        if provider:
            print(f"    → Analysing with {args.llm_provider}...")
            finding.analysis = analyze_crash(crash, str(target_dir), provider)
            print(f"    → {finding.analysis.cwe_id} — {finding.analysis.vulnerability_type}")

            print(f"    → Generating patch...")
            patch_out = output_dir / "patches" / crash.crash_id
            finding.patch = generate_patch(
                crash, finding.analysis, str(target_dir), str(patch_out), provider
            )
            print(f"    → Patch validation: {finding.patch.validation.value}")

        findings.append(finding)
        print()

    # ── Stage 6: Report ──────────────────────────────────────────
    print("[*] Stage 6: Generating report...")
    result = CRSResult(
        target_name=target_name,
        target_source=str(target_dir),
        binary_path=afl_binary,
        fuzzing_duration_seconds=fuzz_duration,
        total_executions=int(fuzz_stats.get("execs_done", 0)),
        crashes_found=len(crash_files),
        unique_crashes=len(crashes),
        findings=findings,
        generated_at=_now(),
        llm_provider="" if args.no_llm else args.llm_provider,
    )

    report_path = output_dir / f"{target_name}_crs_report.html"
    generate_html(result, str(report_path))

    json_path = output_dir / f"{target_name}_crs_report.json"
    import dataclasses
    json_path.write_text(json.dumps(dataclasses.asdict(result), indent=2, default=str))

    print(f"\n{'='*60}")
    print(f"  Results")
    print(f"{'='*60}")
    print(f"  Crashes found    : {result.crashes_found}")
    print(f"  Unique crashes   : {result.unique_crashes}")
    print(f"  Patches generated: {result.patched_count}")
    print(f"  Patches verified : {result.fixed_count}")
    print(f"  HTML report      : {report_path}")
    print(f"  JSON export      : {json_path}")
    print(f"{'='*60}\n")

    print("── Top Findings ────────────────────────────────────")
    for f in findings:
        val_sym = {"Fixed": "✓", "Partial": "~", "Failed": "✗", "Skipped": "—"}.get(f.patch.validation.value, "—")
        cwe = f.analysis.cwe_id or "CWE-?"
        print(f"  [{val_sym}] {f.crash.crash_id} {cwe:10} {f.crash.crash_type.value}")


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    main()
