# Mini-CRS

Automated vulnerability discovery pipeline inspired by [DARPA AIxCC](https://aicyberchallenge.com/). Given a C source directory, Mini-CRS fuzzes the binary with AFL++, triages crashes with AddressSanitizer and GDB, uses an LLM to classify each vulnerability and generate a patch, validates the patch against the original crash input, and produces an HTML report with SARIF 2.1.0 output for the GitHub Security tab.

End-to-end. No human in the loop.

```
targets/vulnerable_parser/main.c
        │
        ▼
  builder.py      — compile with AFL++ instrumentation + ASan
        │
        ▼
  fuzzer.py       — afl-fuzz → crash corpus
        │
        ▼
  triage.py       — ASan + GDB per crash → stack hash dedup → CrashInfo
        │
        ▼
  analyzer.py     — LLM root cause → CWE + severity + attack scenario
        │
        ▼
  patcher.py      — LLM unified diff → apply → recompile → validate
        │
        ▼
  reporter.py     — HTML + JSON + SARIF 2.1.0
```

## Requirements

```
afl++   # apt install afl++
gdb     # apt install gdb
clang   # apt install clang
python  # 3.11+
pip install -r requirements.txt
```

## Quick Start

```bash
# Full pipeline — local Ollama LLM
python crs.py --target targets/vulnerable_parser --fuzz-time 60

# Full pipeline — Claude
ANTHROPIC_API_KEY=sk-ant-... python crs.py \
  --target targets/vulnerable_parser \
  --llm-provider claude \
  --fuzz-time 60

# No LLM — fuzzing + triage only
python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 30

# Skip fuzzing — triage existing crashes
python crs.py --target targets/vulnerable_parser --no-fuzz --crashes output/afl_output/default/crashes/
```

## LLM Providers

| Flag | Provider | Notes |
|---|---|---|
| `--llm-provider ollama` | Ollama (default) | Set `OLLAMA_HOST` or `--llm-endpoint` |
| `--llm-provider claude` | Anthropic Claude | Requires `ANTHROPIC_API_KEY` |
| `--llm-provider openai` | OpenAI | Requires `OPENAI_API_KEY` |
| `--llm-provider openai-compat` | Any OpenAI-compatible API | Requires `--llm-endpoint` |

```bash
# Remote Ollama instance
OLLAMA_HOST=http://192.168.1.100:11434 python crs.py --target targets/vulnerable_parser
```

## Output

```
output/
├── vulnerable_parser_crs_report.html   # executive report with diffs
├── vulnerable_parser_crs_report.json   # machine-readable findings
├── vulnerable_parser_crs_report.sarif  # SARIF 2.1.0 for GitHub Security tab
├── afl_output/                         # raw AFL++ crash corpus
├── build/                              # compiled binaries
├── patches/                            # per-crash patch artifacts
└── triage/                             # per-crash ASan + GDB output
```

SARIF output is consumed by GitHub's Security tab via `github/codeql-action/upload-sarif` — findings appear alongside SAST results in the same Code Scanning interface.

## CI

GitHub Actions runs the pipeline on every push to `stages/`, `engine/`, or `targets/`. Findings upload to the repository Security tab automatically.

```yaml
- name: Run CRS on demo target (no LLM)
  run: python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 30

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: output/vulnerable_parser_crs_report.sarif
```

## Demo Target

`targets/vulnerable_parser/main.c` contains three deliberate vulnerabilities for demonstration:

| Vulnerability | CWE | Function | Trigger |
|---|---|---|---|
| Heap buffer overflow | CWE-122 | `parse_name` | `strcpy` with no bounds check |
| Format string | CWE-134 | `log_record` | `printf(fmt)` with user-controlled format |
| Integer overflow | CWE-190 | `allocate_records` | unchecked count multiplication |

## Crash Deduplication

AFL++ may generate hundreds of crash files for a single underlying bug. `triage.py` deduplicates by:

1. Running each crash input through the ASan binary and GDB
2. Extracting the top 5 user-space stack frames (filtering ASan/libc internals)
3. Computing a SHA1 hash of the frame function names
4. Treating identical hashes as the same root cause

Same approach used by ForAllSecure Mayhem and AFL++'s own `afl-cmin`.

## Patch Validation

Patch validation runs the *exact crash input* that triggered the original bug against the patched binary. A clean exit means the patch fixes that specific input path. Patches that fail validation are still included in the report for manual review — the finding is real even if the generated fix is incomplete.

## Tests

```bash
python -m pytest tests/ -v
```

121 tests covering crash type detection, stack hash deduplication, JSON extraction edge cases, hunk header correction, HTML/SARIF output structure, and LLM provider mocking.

## Architecture Decisions

**Two binaries per target** — the AFL binary (`afl-clang-fast + ASan`) runs fast for coverage-guided mutation. The ASan-only binary (`clang + ASan`) provides detailed crash reports during triage. Combining both into one binary is possible but the performance cost makes large-scale fuzzing impractical — this is the OSS-Fuzz pattern.

**LLM for explanation, not detection** — crashes are found and confirmed by deterministic tools (AFL++, ASan, GDB). The LLM reads that evidence and produces human-readable root cause analysis, CWE classification, and patch suggestions. Hallucinated fixes are caught by patch validation before being marked as verified.

**SARIF over custom formats** — SARIF 2.1.0 is consumed natively by GitHub, GitLab, DefectDojo, and most SAST dashboards. Findings surface in the same Security tab as SAST results without custom integration work.
