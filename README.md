# P4 — Mini-CRS: Interview Prep Notes

---

## 30-Second Pitch (memorise this)

"I built an automated vulnerability discovery pipeline inspired by DARPA AIxCC. It takes C source code, fuzzes it with AFL++ to crash it thousands of times per second, triages each crash with AddressSanitizer and GDB, uses an LLM to identify the root cause and CWE, generates a patch as a unified diff, validates the patch against the original crash, and produces an HTML report plus SARIF output for the GitHub Security tab. End-to-end, no human in the loop."

---

## Q: What is fuzzing? Why AFL++?

Fuzzing is running a program with millions of mutated inputs until it crashes. The key is *what* inputs to generate.

AFL++ uses **coverage-guided fuzzing** — it instruments the binary at compile time to track which code paths each input exercises. When a mutated input reaches a new code path, AFL saves it as a seed for further mutation. This is dramatically more effective than random inputs because it systematically explores the program's state space.

Random fuzzing might only test the "happy path" — AFL works its way into deep error handling, edge cases, and rarely-executed code paths where bugs live.

---

## Q: Walk me through the pipeline stages.

**1. Build** — Two binaries compiled from same source:
- `afl-clang-fast` binary: AFL instrumentation for coverage tracking
- `clang + ASan` binary: AddressSanitizer enabled, used to get detailed crash reports

**2. Fuzz** — `afl-fuzz` runs against the instrumented binary with seed inputs. Crashes saved to corpus.

**3. Triage** — For each crash file:
1. Run ASan binary with the crash input → get memory error report
2. Run `gdb --batch -ex "run < $crash" -ex "bt"` → get backtrace
3. Hash the top N user-space frames → deduplicate to unique bugs
4. Pattern-match ASan output → classify crash type

**4. Analyze** — LLM receives: ASan output + GDB backtrace + source context. Returns JSON with CWE, root cause, attack scenario, severity, fix approach.

**5. Patch** — LLM generates unified diff. Applied, recompiled, run original crash input against patched binary. Pass = fixed, fail = patch included anyway for manual review.

**6. Report** — HTML + JSON + SARIF 2.1.0

---

## Q: What is AddressSanitizer? What does it tell you?

ASan is a compiler instrumentation tool (LLVM/Clang) that detects memory errors at runtime:
- Heap buffer overflows
- Stack buffer overflows  
- Use-after-free
- Use-after-return
- Double-free

When a crash happens, ASan prints a detailed report: error type, crash address, memory layout at the time of crash, allocation/deallocation stack traces. That's what the triage stage parses to classify the bug.

Without ASan, a crash just gives you a segfault signal and a core dump. With ASan you know exactly what kind of memory error it was and where.

---

## Q: How does crash deduplication work?

AFL might generate 100 crash inputs for 2 underlying bugs. Without dedup you'd analyse 100 crashes.

The dedup method:
1. Get GDB backtrace for each crash
2. Filter out ASan-internal frames (those start with `asan::`, `__sanitizer`, etc.)
3. Take the top 4 user-space frames
4. SHA1 hash them → stack hash

Same stack hash = same bug. Only unique hashes get analysed.

This is the same approach commercial tools like Mayhem use. The tradeoff: it can under-deduplicate if the same bug manifests with slightly different call stacks, or over-deduplicate if two different bugs happen to crash through the same code path.

---

## Q: What CWEs does it detect?

Depends on what AFL finds, but the classifier handles:
- CWE-122 — Heap Buffer Overflow (ASan: "heap-buffer-overflow")
- CWE-121 — Stack Buffer Overflow (ASan: "stack-buffer-overflow")  
- CWE-134 — Format String (ASan: signal SIGSEGV on printf-family)
- CWE-416 — Use After Free (ASan: "heap-use-after-free")
- CWE-476 — Null Dereference (ASan: signal on null address)
- CWE-190 — Integer Overflow (inferred from allocation patterns)

---

## Q: What is SARIF? Why does it matter?

SARIF (Static Analysis Results Interchange Format) is a JSON standard (v2.1.0) for security tool output. GitHub, GitLab, DefectDojo, and most SAST dashboards consume it natively.

What it contains per finding:
- Rule ID (e.g. `mini-crs/CWE-122`)
- Severity level
- Source file + line number
- Stack hash fingerprint (deduplication across runs)
- Fix suggestions
- CWE link and help text

Why it matters: without SARIF, fuzzing results live in a separate report nobody checks. With SARIF, they upload to GitHub Security tab on every CI run via `github/codeql-action/upload-sarif`. Security findings land in the same workflow as code review.

---

## Q: Why use an LLM for the analysis? Doesn't it hallucinate?

The LLM is used *only for explanation*, not detection. The crash is real — AFL found it, ASan confirmed it, GDB backtraced it. Those are deterministic. The LLM reads that evidence and explains it in language a developer or exec can act on.

The LLM can hallucinate the fix approach or misname the CWE. That's fine — the patch is validated against the actual crash input before being marked as verified. If the patch doesn't fix the crash, it's flagged as FAILED and included for manual review anyway.

Deterministic tools detect. LLMs explain. That's the right split.

---

## Q: What's the difference between the AFL binary and the ASan binary?

**AFL binary** (`afl-clang-fast`):
- Instrumented for coverage tracking
- Runs fast — AFL may run millions of executions
- Doesn't give detailed crash info, just detects crashes

**ASan binary** (`clang + ASan`):
- Runtime memory checking — much slower
- Gives full memory error report when a crash is triggered
- Used *after* AFL finds crash inputs, to analyse each one

You can combine them but the performance hit makes fuzzing impractical. So AFL finds the crashes, ASan analyses them. Same pattern used by OSS-Fuzz.

---

## Q: How does patch validation work?

1. LLM generates a unified diff
2. `patch` applies it to the source
3. Recompile with ASan
4. Run original crash input against patched binary
5. If it exits cleanly → FIXED. If it crashes → FAILED.

The key: validating against the *exact crash input* that triggered the original bug. Not a new test — the same bytes that caused the original crash. This catches cases where the patch fixes the specific input but leaves the underlying bug exploitable by a slightly different input.

---

## Key technical facts to have ready

- **Fuzzer**: AFL++ (coverage-guided, predecessor to AFL, actively maintained)
- **Memory checker**: AddressSanitizer (LLVM, built into Clang/GCC)
- **Debugger**: GDB batch mode for automated backtrace collection
- **LLM**: Ollama (local default), Claude, OpenAI, any OpenAI-compat endpoint
- **Output formats**: HTML, JSON, SARIF 2.1.0
- **CI**: GitHub Actions — fuzzes on push, uploads SARIF to Security tab
- **Commercial equivalents**: Mayhem (ForAllSecure), Fuzzbuzz, CodeSentry, OSS-Fuzz (Google, free for open source)
- **Demo target bugs**: CWE-122 (heap overflow via strcpy), CWE-134 (format string via printf), CWE-190 (integer overflow)

---

## Q: What would you improve?

- **Python/Go target support** — current pipeline is C-only (AFL++ has coverage support for other languages, but ASan is C/C++ specific — would need different memory checkers like Valgrind or Python's tracemalloc)
- **Seed generation from source** — currently needs manual seeds; could use LLM to generate structured seeds from function signatures
- **Second target** — the demo target is simple; adding a more realistic target (network parser, file format parser) would make the demo more compelling
- **Libfuzzer integration** — alternative to AFL++, required for some environments; same pipeline structure, different fuzzer backend

---

## What I'd say if asked "what was the hardest part?"

The deduplication and triage logic. AFL generates a lot of crashes — sometimes 50+ for a single bug because different input permutations reach the same bad code through slightly different paths. Getting the stack-hashing right (filtering ASan internals, taking the right number of user-space frames, handling cases where the backtrace is empty or truncated) required running the pipeline against dozens of crash inputs and comparing results manually to validate the dedup was correct.
