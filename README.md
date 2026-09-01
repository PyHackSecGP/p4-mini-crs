# P4 — Mini-CRS: Autonomous Vulnerability Discovery & Patch Suggestion

**Role:** Security Engineer / Vulnerability Research portfolio project  
**Stack:** Python 3.11 · AFL++ · AddressSanitizer · GDB · Ollama / Claude / OpenAI · SARIF 2.1.0

---

## Why I Built This Instead of Using an Existing Tool

**Mayhem** (ForAllSecure), **Fuzzbuzz**, and **CodeSentry** are commercial tools that do automated vulnerability discovery. They cost tens to hundreds of thousands of dollars per year. I didn't build this to compete with them — I built it to understand exactly what they're doing, so that when I'm evaluating one for a security program, or triaging a finding it generated, I know what's actually happening.

Specifically, I needed to understand at a hands-on level:

- How AFL++ instrumentation works — how coverage-guided fuzzing differs from random input generation, and why that matters for finding real vulnerabilities
- What AddressSanitizer actually reports and how to parse it programmatically — not just read it in a terminal
- How GDB batch mode can automate backtrace collection — a technique I'd use when triaging a crash corpus at scale
- Where LLMs add genuine value in a vulnerability pipeline vs. where they hallucinate and break things
- What SARIF 2.1.0 requires for GitHub Security tab integration — this matters when you're setting up a security pipeline for a team

I can now look at output from any of those commercial tools and immediately understand what the fuzzer found, why the triage classified it that way, and whether the severity is calibrated correctly. That's the competence this project was built to develop.

---

## What It Does

Point it at a directory of C source code. Come back to a full vulnerability report.

```
Target C source
      ↓
  builder.py       Compile with AFL++ instrumentation + AddressSanitizer
      ↓
  fuzzer.py        afl-fuzz → crash corpus
      ↓
  triage.py        ASan output + GDB backtrace + stack-hash deduplication
      ↓
  analyzer.py      LLM → CWE classification + root cause + attack scenario (JSON)
      ↓
  patcher.py       LLM → unified diff → apply → recompile → verify against crash input
      ↓
  reporter.py      Executive HTML report + JSON export + SARIF 2.1.0
```

No human touches it between "start" and "report."

---

## Concrete Scenario: C Network Parser Audit

A security team is auditing a C-based network packet parser before it goes into a critical infrastructure deployment. The parser has 4,000 lines of code, written 8 years ago, no existing test suite.

```bash
python crs.py --target /path/to/packet-parser --fuzz-time 300 --output output/
```

**Five minutes later:**
```
[+] Fuzzing done: 18 crash files found

[*] Processing crash-001: Heap Buffer Overflow @ parse_header
    → CWE-122 — Heap-based Buffer Overflow
    → Root cause: strcpy into fixed-size heap buffer without length check
    → Attack scenario: Malformed packet with oversized header field triggers
       heap corruption — potential remote code execution
    → Patch generated and validated ✓

[*] Processing crash-002: Format String @ log_packet
    → CWE-134 — Externally-Controlled Format String
    → Root cause: printf(user_controlled_string) — no format argument
    → Patch generated ✓

══════════════════════════════════
  Crashes found    : 18
  Unique crashes   : 2
  Patches generated: 2
  Patches verified : 2
  HTML report      : output/packet-parser_crs_report.html
  SARIF export     : output/packet-parser_crs_report.sarif
```

Two real vulnerabilities (heap overflow, format string), root cause analysis, working patches, and a SARIF file that uploads directly to the GitHub Security tab — in 5 minutes, with zero human analysis in the loop.

The team now has a concrete, prioritised list before a single human reviews the code. The LLM explains each finding in terms an executive can understand and a developer can act on.

---

## The AFL++ + ASan + GDB Pipeline — What I Had to Learn

**Stage 1 — Build**

Two binaries are compiled from the same source:
- `afl-clang-fast` instrument binary — coverage-guided; AFL tracks which code paths each input exercises
- `clang + ASan` binary — runs crashes to get detailed memory error reports

Building this taught me how compiler instrumentation works at the binary level, and why fuzzing without coverage guidance is dramatically less effective at finding deep code paths.

**Stage 2 — Fuzz**

AFL++ runs `afl-fuzz` against the instrumented binary with a seed corpus. It mutates inputs, tracks new coverage, and saves inputs that reach new code. Every crashing input goes to the crash directory.

The key insight AFL++ uses: inputs that increase code coverage are more valuable than random mutations. This is why AFL finds bugs that manual testing misses — it systematically explores the state space.

**Stage 3 — Triage**

Raw crash files from AFL aren't usable directly — there may be 100 crashes caused by 2 underlying bugs. The triage stage:

1. Runs each crash through the ASan binary to get the memory error report
2. Runs GDB in batch mode (`gdb --batch -ex "run < $crash" -ex "bt"`) to get a backtrace
3. Hashes the top N user-space frames to deduplicate crashes to unique bugs
4. Classifies crash type (heap overflow vs. stack overflow vs. format string vs. UAF) by pattern-matching ASan output

This deduplication logic is the same thing commercial triage tools do. Understanding it means I can evaluate whether a triage system is over-reporting (too few deduplications) or under-reporting (merging distinct bugs).

**Stage 4 — LLM Analysis**

The LLM receives the ASan output, GDB backtrace, and relevant source context. It returns structured JSON:

```json
{
  "cwe_id": "CWE-122",
  "cwe_name": "Heap-based Buffer Overflow",
  "vulnerable_function": "parse_header",
  "vulnerable_lines": "main.c:147",
  "root_cause": "strcpy copies user-supplied header into fixed 256-byte heap buffer...",
  "attack_scenario": "Remote attacker sends packet with header field > 256 bytes...",
  "severity": "Critical",
  "exploitability": "High",
  "fix_approach": "Replace strcpy with strlcpy(buf, input, sizeof(buf))"
}
```

The LLM is used only for *explanation* — not for crash detection, which is deterministic. This is the correct role for LLMs in security tooling: they improve the quality of human-readable output, not the reliability of detection.

**Stage 5 — Patch + Validate**

The LLM generates a unified diff. The patcher applies it, recompiles, and runs the original crash input against the patched binary. If it no longer crashes, validation passes. If it does crash, the patch is marked as failed and the diff is still included in the report for manual review.

This validate-on-the-crash-input approach is sound because it tests the exact input that triggered the original bug — not a new test case that might miss a variant.

---

## SARIF 2.1.0 — Why It Matters

The SARIF exporter (`stages/sarif_exporter.py`) outputs results in the format GitHub, GitLab, and DefectDojo all consume natively.

What a SARIF result contains:
- Rule ID and CWE mapping
- Source file and line number (extracted from ASan output)
- Severity level
- Stack hash fingerprint for deduplication across runs
- Fix suggestions from generated patches
- Exploitability metadata

In a real security program, this means fuzzing results flow directly into the vulnerability management pipeline without manual transcription. The SARIF file from CI uploads to GitHub Security tab on every push via `github/codeql-action/upload-sarif`.

---

## LLM Provider Design

The tool works with any LLM:

```bash
# On-prem Ollama (default — no data leaves the network)
python crs.py --target ... --llm-provider ollama --llm-model hermes3:70b

# Anthropic Claude
python crs.py --target ... --llm-provider claude --llm-model claude-sonnet-4-6

# Any OpenAI-compatible endpoint
python crs.py --target ... --llm-provider openai-compat \
  --llm-endpoint http://localhost:8000 --llm-model my-model
```

The pluggable provider design means the same pipeline runs in an air-gapped environment (Ollama), in a cloud CI pipeline (Claude/OpenAI), or against a self-hosted model server. This is the architecture decision I'd make for any production security tool — never hard-code a specific LLM vendor.

---

## Quick Start

```bash
# Requirements: afl++, gdb (usually pre-installed on Kali)
sudo apt-get install -y afl++ gdb

git clone https://git.greenbladesec.com/gpsingh/p4-mini-crs
cd p4-mini-crs
pip install -r requirements.txt

# Full pipeline on built-in demo target (60s fuzzing, local Ollama)
python crs.py --target targets/vulnerable_parser --fuzz-time 60 --output output/

# No LLM — rule-based triage only
python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 60

# Use existing crash corpus, skip fuzzing
python crs.py --target targets/vulnerable_parser --no-fuzz \
  --crashes output/afl_output/default/crashes/
```

Open `output/vulnerable_parser_crs_report.html` in a browser.

---

## Demo Target

`targets/vulnerable_parser/main.c` — deliberately vulnerable C parser with:

| Vulnerability | CWE | Type |
|---|---|---|
| `strcpy` into heap-allocated struct field | CWE-122 | Heap buffer overflow |
| `printf(user_input)` without format specifier | CWE-134 | Format string |
| Integer overflow in `malloc` size calculation | CWE-190 | Integer overflow |

These match the most common vulnerability classes in real C/C++ codebases. AFL++ reliably finds all three within 60 seconds of fuzzing.
