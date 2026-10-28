# Mini-CRS

**An autonomous system that finds, explains, and patches memory-corruption bugs in C programs — then publishes the findings to the GitHub Security tab.**

Inspired by [DARPA AIxCC](https://aicyberchallenge.com/). End-to-end. No human in the loop.

---

## In 60 seconds (for anyone)

Imagine a robot that gets handed a C program and does three things on its own:

1. **Breaks it.** Throws millions of random, mutated inputs at the program until something crashes.
2. **Explains the break.** Reads the crash details and writes a plain-English root cause: *"The `parse_name` function copies user input into a 64-byte buffer with no size check — attackers can smash the stack."*
3. **Fixes it.** Writes a code patch, applies it, recompiles, and re-runs the exact input that caused the crash. If the program no longer crashes, the fix is confirmed.

Each confirmed bug is written to a standard security report (SARIF) that shows up as a finding on GitHub's Security tab — the same place professional security scanners put results.

> Think "automated bug bounty" — but instead of a human researcher chaining a fuzzer, debugger, and reverse-engineer, an LLM glues the pieces together and writes the report.

---

## Why this matters (for interviewers / hiring managers)

- **Autonomous security tooling.** DARPA's $7M AI Cyber Challenge is exactly this problem: give an AI a codebase, let it find and patch vulns without humans in the loop. This project is a working one-person implementation of the pattern.
- **LLM used responsibly.** Crashes are **detected deterministically** (AFL++, AddressSanitizer, GDB). The LLM only writes the human-readable explanation and candidate patch — then a deterministic step **validates the patch against the real crash input**. The model never gets to decide what counts as a bug.
- **SARIF-native output.** Findings integrate with the same GitHub Security tab enterprises use for CodeQL and Snyk — no custom dashboard required.
- **Autonomous pipeline layer (`auto/`).** On top of the one-shot CLI, a self-driving loop: cron + file-watcher + persistent job queue + Claude-Haiku-4.5 triage agent decides what to do with each result (file a GitHub issue on CRITICAL, Telegram alert, re-fuzz longer, or ignore).
- **121 unit tests, GitHub Actions CI with Security tab upload, SARIF 2.1.0 compliance.**

---

## The pipeline (for the technical reader)

```
targets/vulnerable_parser/main.c
        │
        ▼
  builder.py    — compile two binaries: AFL++ instrumented (fast) + ASan (detailed)
        │
        ▼
  fuzzer.py     — afl-fuzz mutates seed inputs → generates crash corpus
        │
        ▼
  triage.py     — replay each crash through ASan + GDB
                  → extract top-5 user-space stack frames
                  → SHA1 hash as stack_id → dedup CrashInfo records
        │
        ▼
  analyzer.py   — LLM (Ollama / Claude / OpenAI) reads ASan report + source
                  → emits root cause + CWE + severity + attack scenario
        │
        ▼
  patcher.py    — LLM proposes unified diff
                  → apply → recompile → replay original crash input
                  → mark Verified only on clean exit
        │
        ▼
  reporter.py   — HTML (humans) + JSON (machines) + SARIF 2.1.0 (GitHub)
```

---

## Two ways to run it

### 1. One-shot CLI (manual)

```bash
# Local Ollama LLM (default)
python crs.py --target targets/vulnerable_parser --fuzz-time 60

# Claude API
ANTHROPIC_API_KEY=sk-ant-... python crs.py \
  --target targets/vulnerable_parser --llm-provider claude --fuzz-time 60

# No LLM — fuzzing + triage only
python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 30
```

Output lands in `output/<target>_crs_report.{html,json,sarif}`.

### 2. Autonomous pipeline (`auto/`) — new

A self-driving loop around `crs.py` with three producers feeding one worker:

```
            targets.yaml  (watchlist dirs + github repos)
                 │
     ┌───────────┼─────────────┐
     ▼           ▼             ▼
  scheduler   watcher     (manual
   (daily      (inotify   enqueue)
    cron)     on edits)
     │           │             │
     └─────┬─────┴─────────────┘
           ▼
      SQLite job queue  (dedup, persist across restarts)
           │
           ▼
      agent.py  — Claude Haiku 4.5 (Agent SDK tool runner)
           │
           ▼ picks ONE of four actions per job:
     ┌──────────┬───────────────────┬──────────────┬──────────────┐
     ▼          ▼                   ▼              ▼              ▼
  Telegram   file_github_issue   requeue        mark_ignore
   alert     (gh issue create    (2× fuzz,      (NONE/LOW/
   (HIGH/     + security label    cap 600s)      seen-before
    MEDIUM)   on CRITICAL)                        stack hash)
```

**Design choices:**

- **Severity classification is prompted, not learned** — concrete CWE examples per tier (CRITICAL = CWE-120/121/122/134-controllable/416/415, HIGH = CWE-190 / OOB-write uncertain, MEDIUM = CWE-476 / resource exhaustion / OOB-read, LOW = style).
- **Stack-hash dedup across runs** — before deciding, the agent is given a list of prior findings for the target (`stack_hash + severity + action`) so repeat MEDIUM alerts collapse into one.
- **CRITICAL on a GitHub-sourced target** → files an issue with labels `security`, `p4-crs`, `severity:critical`. Watchlist (local path) targets → Telegram instead.
- **Prompt-cache friendly layout** — system prompt is frozen; dynamic context (prior findings, SARIF payload) goes in the user turn.

**Install:**

```bash
cd auto && cp .env.example .env   # fill ANTHROPIC_API_KEY + TELEGRAM_* + gh auth login
pip install anthropic python-dotenv pyyaml watchdog

# systemd user services
mkdir -p ~/.config/systemd/user
for u in p4-agent.service p4-scheduler.service p4-scheduler.timer p4-watcher.service; do
  ln -sf ~/projects/p4-mini-crs/auto/systemd/$u ~/.config/systemd/user/
done
systemctl --user daemon-reload
systemctl --user enable --now p4-agent.service p4-watcher.service p4-scheduler.timer
```

Full details: [`auto/README.md`](auto/README.md).

---

## Prerequisites

```bash
apt install afl++ gdb clang
python  # 3.11+
pip install -r requirements.txt
```

For the auto layer additionally: `pip install anthropic python-dotenv pyyaml watchdog` plus `gh auth login` for GitHub issue filing.

---

## LLM providers (for the pipeline's own analyzer/patcher)

| Flag | Provider | Notes |
|---|---|---|
| `--llm-provider ollama` | Ollama (default) | Set `OLLAMA_HOST` or `--llm-endpoint` |
| `--llm-provider claude` | Anthropic Claude | Requires `ANTHROPIC_API_KEY` |
| `--llm-provider openai` | OpenAI | Requires `OPENAI_API_KEY` |
| `--llm-provider openai-compat` | Any OpenAI-compatible API | Requires `--llm-endpoint` |

The `auto/` layer's **orchestration agent** always uses `claude-haiku-4-5` via the Anthropic Agent SDK tool runner — orthogonal to the internal analyzer/patcher LLM.

---

## Output

```
output/
├── <target>_crs_report.html   # executive report with diffs + Verified badges
├── <target>_crs_report.json   # machine-readable findings
├── <target>_crs_report.sarif  # SARIF 2.1.0 for GitHub Security tab / DefectDojo
├── afl_output/                # raw AFL++ crash corpus
├── build/                     # compiled binaries (AFL + ASan variants)
├── patches/                   # per-crash patch artifacts
└── triage/                    # per-crash ASan + GDB output
```

The SARIF file uploads to GitHub's Security tab via `github/codeql-action/upload-sarif`, surfacing findings alongside CodeQL and other SAST tools.

---

## CI

GitHub Actions runs the pipeline on every push touching `stages/`, `engine/`, or `targets/`. SARIF output uploads automatically:

```yaml
- name: Run CRS on demo target (no LLM)
  run: python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 30

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: output/vulnerable_parser_crs_report.sarif
```

---

## Demo target

`targets/vulnerable_parser/main.c` ships three deliberate bugs — the pipeline is expected to find all three on a clean run:

| Vulnerability | CWE | Function | Trigger |
|---|---|---|---|
| Heap buffer overflow | CWE-122 | `parse_name` | `strcpy` with no bounds check |
| Format string | CWE-134 | `log_record` | `printf(fmt)` with user-controlled format |
| Integer overflow | CWE-190 | `allocate_records` | unchecked count multiplication |

---

## Crash deduplication

AFL++ can emit hundreds of crash files for one underlying bug. `triage.py` groups them:

1. Replay each crash through the ASan binary under GDB
2. Extract the top 5 user-space stack frames (filtering ASan/libc internals)
3. SHA1 of the frame function names = `stack_id`
4. Same hash → same root cause → one `CrashInfo` record

Same technique used by ForAllSecure Mayhem and AFL++'s own `afl-cmin`.

---

## Patch validation

Patches aren't trusted on sight. Each generated patch is applied, the binary is recompiled, and the **exact crash input that triggered the original bug** is replayed. A clean exit = Verified. Any crash under the patched binary = unverified; the finding still appears in the report (the bug is real), but the fix is flagged for human review.

This is the guardrail that keeps LLM hallucinations out of the "fixed" column.

---

## Tests

```bash
python -m pytest tests/ -v
```

121 tests covering: crash type detection, stack-hash dedup, JSON extraction edge cases, hunk header correction, HTML/SARIF output structure, LLM provider mocking.

---

## Architecture decisions

**Two binaries per target.** AFL++-instrumented (`afl-clang-fast + ASan`) is fast enough for coverage-guided mutation. The ASan-only binary (`clang + ASan`) is slower but produces full crash reports during triage. Combining both into one binary is possible but kills fuzzing throughput — this is the OSS-Fuzz pattern.

**LLM explains, deterministic code decides.** Crashes are found and confirmed by AFL++ + ASan + GDB. The LLM reads that evidence and writes English + CWE + patch — but the patch is only marked Verified after the deterministic replay step. The model never arbitrates whether a bug exists.

**SARIF over custom formats.** SARIF 2.1.0 is consumed natively by GitHub, GitLab, DefectDojo, and most SAST dashboards — findings surface in the same UI as CodeQL / Snyk / Trivy without integration work.

**Auto pipeline split from CLI.** Everything in `auto/` sits beside `crs.py` without modifying it. Removing `auto/` reverts to the pure one-shot tool. Any producer (cron, inotify, manual) feeds the same SQLite queue; any new tool the agent gains (`gh issue`, Telegram, requeue) is a tool-runner function, not pipeline surgery.

---

## Status

| Layer | Status |
|---|---|
| Core pipeline (`crs.py`, `stages/`, `engine/`) | ✅ shipped, 121 tests passing, CI green |
| Auto Phase 1 — queue + runner + Haiku agent + Telegram + systemd | ✅ shipped |
| Auto Phase 2 — cron scheduler + inotify watcher + timer units | ✅ shipped |
| Auto Phase 3 — stack-hash dedup + `file_github_issue` on CRITICAL | ✅ shipped |
| Auto Phase 4 — Flask dashboard (`localhost:5557`) over SQLite jobq | ✅ shipped |
| Auto Phase 5 (deferred) — CVE/NVD-driven target picker + claw-core deploy | ⏸ not planned |
