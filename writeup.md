# P4 — Mini-CRS Writeup

## What It Is

A fully autonomous Cyber Reasoning System (CRS) inspired by DARPA AIxCC. Given a C source directory, it finds memory-safety vulnerabilities through coverage-guided fuzzing, triages each crash with AddressSanitizer and GDB, asks an LLM to identify the root cause and CWE, generates a patch as a unified diff, applies and validates it by recompiling against the original crash input, then emits an executive HTML report.

**End-to-end with zero manual input.** Point it at source, come back to a report.

---

## Why I Built It

DARPA AIxCC ran in 2024–2025 to demonstrate that AI systems could autonomously find and fix vulnerabilities in real software. The winning teams (Shellphish, Theori, ZeroPoint Dynamics) used pipelines combining fuzzing, symbolic execution, and LLM reasoning. I wanted to understand that pipeline by building a minimal version myself — something I could explain, extend, and demo.

This is project P4 in my security engineering portfolio. It demonstrates:
- Systems programming awareness (C memory safety, ASan internals)
- Security tooling (AFL++ instrumentation, GDB batch scripting)
- LLM integration for security tasks (root cause analysis, patch generation)
- Full pipeline engineering in Python

---

## Architecture

```
targets/vulnerable_parser/main.c
          │
          ▼
    stages/builder.py
    ┌─────────────────────────────────┐
    │ afl-clang-fast + ASan → AFL bin │
    │ clang + ASan         → ASan bin │
    └─────────────────────────────────┘
          │
          ▼
    stages/fuzzer.py
    ┌─────────────────────────────────┐
    │ afl-fuzz → crashes/id:*         │
    └─────────────────────────────────┘
          │
          ▼
    stages/triage.py
    ┌──────────────────────────────────────────┐
    │ For each crash file:                     │
    │   run ASan binary → capture output       │
    │   run GDB batch   → backtrace            │
    │   detect crash type via regex patterns   │
    │   hash top user-space frames → dedup     │
    └──────────────────────────────────────────┘
          │
          ▼
    stages/analyzer.py + engine/llm_provider.py
    ┌──────────────────────────────────────────┐
    │ Build prompt with ASan output + source   │
    │ LLM → JSON: CWE, root cause, fix approach│
    └──────────────────────────────────────────┘
          │
          ▼
    stages/patcher.py
    ┌──────────────────────────────────────────┐
    │ LLM → unified diff                       │
    │ patch -p1 (dry-run then apply)           │
    │ recompile with ASan                      │
    │ run crash file against patched binary    │
    │ validate: Fixed / Failed / Skipped       │
    │ restore original source                  │
    └──────────────────────────────────────────┘
          │
          ▼
    stages/reporter.py
    ┌──────────────────────────────────────────┐
    │ Self-contained HTML + JSON               │
    │ Per-finding: crash details, ASan output, │
    │ root cause, attack scenario, patch diff  │
    └──────────────────────────────────────────┘
```

---

## Demo Target: `targets/vulnerable_parser/main.c`

A deliberately vulnerable C file parser with three planted bugs:

### VULN-1 — Heap Buffer Overflow (CWE-122)
```c
void parse_name(char *dest, const char *src) {
    strcpy(dest, src);  // dest is 64 bytes, src can be 255 bytes
}
```
`fgets` reads up to 255 bytes into `line`. `parse_name` copies that into a 64-byte `Record.name` field with no bounds check. `Record` is heap-allocated via `malloc`, so ASan reports `heap-buffer-overflow`. AFL finds this by mutating the name field past 64 bytes.

### VULN-2 — Format String (CWE-134)
```c
void log_record(const char *fmt) {
    printf(fmt);  // user-controlled format string
}
```
User-supplied file content flows directly into `printf` as the format argument. AFL finds this by inserting `%x`, `%n`, `%s` specifiers into the name field, triggering ASan's format-string interceptor.

### VULN-3 — Integer Overflow (CWE-190)
Originally present in `allocate_records(count * RECORD_SIZE)` — fixed early in development to allow AFL to reach deeper code paths. The fix changed `RECORD_SIZE` multiplication to `sizeof(Record)` with explicit `(size_t)` cast.

---

## LLM Integration

Three provider backends, all behind one abstract interface:

```python
class LLMProvider(ABC):
    def generate(self, prompt: str, timeout: int = 180) -> str: ...
    def is_available(self) -> bool: ...
```

| Provider | Backend | Auth |
|---|---|---|
| `ollama` | Local Ollama REST API | None (on-prem) |
| `claude` | Anthropic Messages API | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI Chat Completions | `OPENAI_API_KEY` |
| `openai-compat` | Any OpenAI-compatible endpoint | `--llm-api-key` |

The analyzer prompt asks for structured JSON (CWE ID, root cause, attack scenario, fix approach, severity, exploitability). The patcher prompt asks for a unified diff — no fences, no explanation, just the diff.

---

## Key Engineering Decisions

**Why restore the original source after patch validation?**
The patcher applies a patch, compiles, validates, then restores `main.c` from a backup. If it didn't restore, re-running the pipeline would build from already-patched code — crash files would no longer trigger the vulnerability, triage would produce empty ASan output, and crash types would show as Unknown. The patch is preserved in the `Patch.diff` field; the source stays vulnerable for subsequent runs.

**Why `text=False` + `decode(errors='replace')` for subprocess?**
AFL crash files are raw binary. When the ASan binary processes them, binary data leaks into stdout. Python's `subprocess` with `text=True` raises `UnicodeDecodeError` on the first non-UTF-8 byte. `text=False` gives bytes; `decode('utf-8', errors='replace')` substitutes `�` for invalid sequences, preserving the ASan diagnostic lines which are valid ASCII.

**Stack hash deduplication:**
Triage extracts up to 5 user-space frame names from the GDB/ASan backtrace, skipping internal ASan/sanitizer frames. SHA-1 of the joined frame names gives a stable crash fingerprint. Two AFL crash files that trigger the same code path get the same hash and are reported once.

---

## Results (demo run)

- **Fuzzing:** 180 seconds, AFL++ with AddressSanitizer instrumentation
- **Crashes found:** 2 files → 1–2 unique after dedup
- **Analysis:** CWE-134 (Format String) and/or CWE-120 (Buffer Overflow) identified correctly
- **Patches:** LLM-generated unified diffs applied with `patch -p1`, recompiled, validated
- **Fix rate:** 100% on demo target

---

## Limitations

- Single-file C targets only (one `clang` compilation unit)
- No symbolic execution — coverage-guided fuzzing only
- Patch quality depends on LLM; complex multi-file bugs need more context
- No SARIF export (plain HTML/JSON)
- No CI integration hooks

---

## Skills Demonstrated

- AFL++ coverage-guided fuzzing and instrumentation
- AddressSanitizer output parsing and crash type classification
- GDB batch scripting for automated backtrace extraction
- LLM prompt engineering for structured security analysis output
- Python dataclass-based pipeline with clean provider abstraction
- Unified diff generation, application, and automated validation
