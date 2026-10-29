# P4 Mini Cyber Reasoning System — DARPA-AIxCC-inspired, local

**An autonomous Cyber Reasoning System (CRS) that fuzzes C programs, finds memory-corruption bugs, writes plain-English root-cause analysis, generates a patch, verifies the patch against the real crash input, and ships the result to the GitHub Security tab — all without a human in the loop.**

![tests](https://img.shields.io/badge/tests-121%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![fuzzer](https://img.shields.io/badge/fuzzer-AFL%2B%2B-orange)
![llm](https://img.shields.io/badge/llm-Claude%20Haiku%204.5-7a4bd3)
![sarif](https://img.shields.io/badge/output-SARIF%202.1.0-lightgrey)
![inspired-by](https://img.shields.io/badge/inspired--by-DARPA%20AIxCC-red)

---

## 60-Second Overview

A **Cyber Reasoning System** is the DARPA AIxCC name for a bot that takes raw source code and, on its own, (1) finds vulnerabilities, (2) explains them, (3) patches them, (4) proves the patch works. Humans used to spend days doing exactly this. CRSs do it in minutes, headless.

**P4 Mini-CRS runs that whole loop on a laptop:**

1. **Breaks it.** AFL++ mutates seed inputs millions of times until the target binary crashes under AddressSanitizer.
2. **Explains it.** For each unique crash, an LLM (default: Claude Haiku 4.5) reads the ASan report plus the source file and emits a structured finding — root cause in English, CWE id, severity, attack scenario.
3. **Patches it.** The same LLM proposes a unified diff. The pipeline applies the diff, recompiles, and **replays the exact crash input**. Clean exit → `Verified`. Still crashes → `unverified`, flagged for human review.
4. **Reports it.** HTML (humans) + JSON (machines) + **SARIF 2.1.0** (GitHub Security tab, DefectDojo, GitLab) — same format CodeQL and Snyk use.

On top of the one-shot CLI there's an `auto/` layer: four systemd user units, a SQLite job queue, a Flask dashboard, a CVE/NVD/KEV poller that re-queues targets when a known-exploited CVE lands against them, and a Claude-Haiku-4.5 agent (Anthropic Agent SDK) that decides per-finding whether to file a GitHub issue, Telegram-alert, re-fuzz longer, or ignore (stack-hash seen before).

> Think "automated bug bounty." A human researcher chains a fuzzer, a debugger, a reverse-engineer, and a report writer. Here the LLM glues the pieces and writes the report; the deterministic tooling owns the ground truth about whether a bug exists.

---

## For Interviewers

### Problem Statement

Memory-safety bugs still dominate the CVE charts — Microsoft and Google both reported ~70% of their critical security bugs trace back to memory unsafety in C/C++. Manual root-cause analysis of a fuzzer crash takes hours per finding, and most teams never get past "we have a corpus of 300 crash files, which are the same bug and which are new?"

DARPA's AI Cyber Challenge (AIxCC, $29.5M prize pool, finals 2025) exists precisely to prove an AI can close this loop end to end. P4 Mini-CRS is a one-person implementation of the AIxCC pattern — not a competitor-scale CRS, but every architectural element is here: deterministic bug discovery, LLM-generated analysis + patch, deterministic patch validation, SARIF output, continuous CVE-driven re-triage.

### Skills Demonstrated

- **Fuzz orchestration** — AFL++ with coverage-guided mutation, dual-build pattern (AFL-instrumented binary for speed + ASan-only binary for detail), seed-corpus discipline.
- **AddressSanitizer parsing** — stack-frame extraction, user-vs-ASan-internal filtering, SHA1 stack hashing for cross-run dedup.
- **GDB post-mortem** — automated replay with scripted stack capture when ASan output is truncated.
- **LLM structured output** — JSON-schema prompts for CWE + severity + patch, defensive JSON extraction, unified-diff hunk-header auto-correction.
- **Prompt caching for cost control** — frozen system prompt (big) + dynamic user turn (small); cache hits on the system prompt drop per-finding Haiku cost from ~$0.015 to ~$0.003.
- **Patch generation + verification loop** — apply → recompile → replay original crash input → mark Verified only on clean exit. The guardrail against hallucinated fixes.
- **SARIF 2.1.0** — correct rule objects, result partialFingerprints (so GitHub dedupes), region+contextRegion snippets, severity → SARIF level mapping.
- **GitHub Actions CI** — SARIF upload via `github/codeql-action/upload-sarif`, findings surface in the Security tab next to CodeQL output.
- **Systemd user services** — `--user` scope, `linger` enabled, four units (`p4-agent`, `p4-watcher`, `p4-scheduler.timer`, `p4-dashboard`).
- **Flask dashboard** — read-only Jinja views over the SQLite queue, routes per target / per finding, severity badges.
- **SQLite job queue** — threaded, with FIFO pop + atomic claim, `pending → running → done/failed` state machine, orphan-resume on restart, dedup on `(target, status in {pending, running})`.
- **CVE/NVD/KEV prioritization** — CISA Known Exploited Vulnerabilities + NVD CVE 2.0 API, product-name match against watchlist, re-queue with elevated priority.
- **Anthropic Agent SDK** — tool-runner pattern (`file_github_issue`, `telegram_alert`, `requeue_longer`, `mark_ignore`), per-call max_tokens caps, prompt-cache-friendly turn layout.

### Architecture

```
                            P4 MINI-CRS
                            ===========

   targets/vulnerable_parser/main.c        (any C source dir)
                 │
                 ▼
     ┌────────────────────────┐
     │ stages/builder.py      │  afl-clang-fast + ASan   → binary.afl
     │                        │  clang -fsanitize=addr   → binary.asan
     └───────────┬────────────┘
                 ▼
     ┌────────────────────────┐
     │ stages/fuzzer.py       │  afl-fuzz on binary.afl, seeds → crash corpus
     └───────────┬────────────┘
                 ▼
     ┌────────────────────────┐
     │ stages/triage.py       │  for each crash: binary.asan + GDB
     │                        │  top-5 user frames → SHA1 = stack_id
     │                        │  dedup → list[CrashInfo]
     └───────────┬────────────┘
                 ▼
     ┌────────────────────────┐
     │ stages/analyzer.py     │  LLM (Claude / Ollama / OpenAI)
     │                        │  reads ASan report + source
     │                        │  emits Finding{cwe, severity, root_cause,
     │                        │                scenario}
     └───────────┬────────────┘
                 ▼
     ┌────────────────────────┐
     │ stages/patcher.py      │  LLM proposes unified diff
     │                        │  apply → recompile → replay crash input
     │                        │  clean exit? → validation = Fixed
     │                        │  still crashes? → Failed  (bug still real)
     └───────────┬────────────┘
                 ▼
     ┌────────────────────────┐
     │ stages/reporter.py     │  HTML (humans)
     │ stages/sarif_exporter  │  JSON (machines) + SARIF 2.1.0 (GitHub)
     └────────────────────────┘


                            auto/  LOOP
                            ===========

   targets.yaml ──► watchlist dirs      github repos
                         │                    │
                         ▼                    ▼
             ┌──────────────────┐   ┌─────────────────────┐
             │ auto/watcher.py  │   │ auto/scheduler.py   │
             │ (inotify, edits) │   │ (daily 03:00 timer) │
             │                  │   │ + auto/cve_poller   │
             │                  │   │ (CISA KEV + NVD)    │
             └────────┬─────────┘   └──────────┬──────────┘
                      │                        │
                      │   manual enqueue       │
                      │   (dashboard /trigger) │
                      ▼                        ▼
             ┌───────────────────────────────────────────┐
             │ auto/jobq.py  —  SQLite job queue         │
             │ pending → running → done | failed         │
             │ dedup (target, status∈{pending,running})  │
             │ orphan-resume on restart                  │
             └───────────────────┬───────────────────────┘
                                 ▼
             ┌───────────────────────────────────────────┐
             │ auto/agent.py   Claude Haiku 4.5          │
             │ Anthropic Agent SDK tool runner           │
             │ input: SARIF + prior stack hashes         │
             │ picks ONE action per job:                 │
             └───────────────────┬───────────────────────┘
                                 │
         ┌───────────────┬───────┼────────────┬───────────────┐
         ▼               ▼       ▼            ▼               ▼
    telegram_alert  file_github  requeue   mark_ignore   (future tool)
    (HIGH/MED       _issue       _longer   (NONE/LOW
     watchlist)     (CRITICAL,   (2× fuzz,  / seen stack
                    GitHub repo) cap 600s)   hash)

                                 │
                                 ▼
                 auto/dashboard.py  (Flask, localhost:5557)
                 read-only Jinja over jobq.db
```

### Design Decisions & Trade-offs

**Why AFL++ and not libFuzzer?**
AFL++ ships a battle-tested fork-server, mutators, and `afl-cmin` corpus minimizer out of the box. libFuzzer is in-process and faster per-exec, but it requires writing a `LLVMFuzzerTestOneInput` harness per target — more code to add a new target. The lazy choice is AFL++: point it at `argv[1]` / stdin and it runs. For a mini CRS the throughput difference doesn't matter; the LLM analysis dominates wall-clock.

**Why Haiku 4.5 as the default agent?**
Agent SDK calls are cheap on Haiku 4.5 (~$1/MTok input, $5/MTok output) and the triage decision ("file issue? telegram? ignore?") is a short-context classification problem — Sonnet is overkill. The internal analyzer and patcher stages can be upgraded to Sonnet via `--llm-model claude-sonnet-4-6` if a target needs more subtle root-cause reasoning. Keeping agent and analyzer orthogonal means you can mix: cheap agent, premium analyzer.

**Why SQLite and not Redis / RabbitMQ?**
One-process queue with threading-lock + `WAL` mode is enough for a laptop-scale pipeline — hundreds of jobs/day, not millions. SQLite also means **zero daemons to run**, the queue is a single file, `sqlite3 jobq.db` is the admin tool, and the Flask dashboard is a read-only cursor over the same file. If throughput ever matters, swap `auto/jobq.py` for a Redis-backed module without touching the agent or dashboard. `ponytail: SQLite single-writer lock, upgrade to Redis if queue depth > 10k`.

**Why Ollama fallback (not Claude-only)?**
Hard requirement to run offline / air-gapped / without an API key. Ollama (default `http://localhost:11434`, override via `OLLAMA_HOST`) with Hermes 3 70B or Llama 3.1 does acceptable triage; patch quality drops but the deterministic verification step catches it (bad patch → `Failed`, bug still reported). Having a non-cloud path is also useful during CI where secret exposure is a risk.

**Why systemd user units (not root / Docker)?**
User-scope services (`systemctl --user`) don't need sudo, don't need a container runtime, and persist across reboots once `loginctl enable-linger $USER` is set. The pipeline runs out of `$HOME/projects/p4-mini-crs/` — same place a developer edits it. One command (`systemctl --user restart p4-agent`) picks up code changes. Docker adds a build step, a networking layer, and a GID-mapping headache for the SARIF file-mount; none of it earns its complexity at this scale.

**Why re-queue on CVE/NVD/KEV match?**
Standing fuzz runs grow stale — a target rooted clean last week might be exploitable today because a new primitive just dropped. `auto/cve_poller.py` pulls CISA KEV (highest signal — actively exploited in the wild) and NVD recent CVEs, substring-matches product names against the watchlist, and re-enqueues with `fuzz_time` doubled. Lazy heuristic: no CPE mapping, just product-name match. Good enough for well-known projects (openssl, curl, libxml2) and dodges the CPE-tangent entirely. `ponytail: product-name substring match, swap for CPE-to-repo mapping if false-positive rate hurts`.

**Why LLM-explains, deterministic-code-decides?**
This is the one place I refuse to be lazy. The LLM never gets to decide whether a bug exists. AFL++ + ASan + GDB find and confirm crashes; the LLM reads that evidence and writes English + CWE + patch — but a patch is only `Verified` after the deterministic replay step re-runs the exact crash input against the patched binary and exits clean. The model is a scribe, not a judge.

### Metrics

| | |
|---|---|
| Pipeline stages | 5 (build → fuzz → triage → analyze → patch) + 1 report fan-out (HTML/JSON/SARIF) |
| Modes | 2 — one-shot CLI (`crs.py`), auto daemon (`auto/`) |
| Systemd units | 4 services (`p4-agent`, `p4-watcher`, `p4-dashboard`, `p4-scheduler.service`) + 1 timer (`p4-scheduler.timer`) |
| LLM providers | 4 — Ollama (default), Claude, OpenAI, any OpenAI-compatible endpoint |
| Agent model | Claude Haiku 4.5 via Anthropic Agent SDK |
| Cost control | Prompt caching (frozen system prompt) + tool-runner caps |
| Tests | 121, pytest, GitHub Actions CI green |
| CVE feeds | CISA KEV + NVD CVE 2.0 (recent window) |
| Output formats | HTML, JSON, SARIF 2.1.0 |
| Lines of Python | ~3.5k (`stages/` + `engine/` + `auto/`) |

---

## Quick Start

### 1. One-shot CLI

```bash
# Clone + install
git clone https://github.com/PyHackSecGP/p4-mini-crs.git
cd p4-mini-crs
sudo apt install -y afl++ gdb clang
pip install -r requirements.txt

# Run against the built-in demo target (Ollama default)
python crs.py --target targets/vulnerable_parser --fuzz-time 60

# Same, with Claude
ANTHROPIC_API_KEY=sk-ant-... python crs.py \
  --target targets/vulnerable_parser --llm-provider claude --fuzz-time 60

# Deterministic only (no LLM) — still finds + reports crashes, skips analysis/patch
python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 30
```

Reports land in `output/<target>_crs_report.{html,json,sarif}`.

### 2. Auto daemon

```bash
cd auto && cp .env.example .env   # fill ANTHROPIC_API_KEY, TELEGRAM_*, (optional NVD_API_KEY)
pip install anthropic python-dotenv pyyaml watchdog requests flask
gh auth login                      # for file_github_issue tool

# Install user units
mkdir -p ~/.config/systemd/user ~/projects/p4-mini-crs/auto/logs
for u in p4-agent.service p4-watcher.service p4-scheduler.service \
         p4-scheduler.timer p4-dashboard.service; do
  ln -sf ~/projects/p4-mini-crs/auto/systemd/$u ~/.config/systemd/user/
done
systemctl --user daemon-reload
systemctl --user enable --now p4-agent.service p4-watcher.service \
                              p4-scheduler.timer p4-dashboard.service
loginctl enable-linger "$USER"     # survive logout

# Open dashboard
xdg-open http://localhost:5557
```

---

## Pipeline Stages

| Stage | Input | Output | Tool / LLM |
|---|---|---|---|
| **1. Build** | `targets/<name>/main.c` + `Makefile` | `binary.afl` (fast, instrumented) + `binary.asan` (detailed) | `afl-clang-fast`, `clang -fsanitize=address` |
| **2. Fuzz** | `binary.afl`, `seeds/*` | `output/afl_output/crashes/id:*` | `afl-fuzz` |
| **3. Triage** | crash files, `binary.asan` | `list[CrashInfo]` (top-5 frames, SHA1 stack_id, deduped) | ASan + GDB, deterministic |
| **4. Analyze** | `CrashInfo` + source | `Finding{cwe_id, severity, root_cause, scenario}` | LLM (Claude Haiku 4.5 / Ollama / OpenAI) |
| **5. Patch** | `Finding` + source | unified diff + `validation ∈ {Fixed, Failed, Skipped}` | LLM proposes → deterministic apply + recompile + replay |
| **6. Report** | `CRSResult` | `<target>_crs_report.{html,json,sarif}` | `stages/reporter.py`, `stages/sarif_exporter.py` |

---

## Examples

### Example 1 — one-shot CLI on the demo target

```bash
$ python crs.py --target targets/vulnerable_parser --llm-provider claude --fuzz-time 60
============================================================
  P4 Mini-CRS — vulnerable_parser
============================================================

[*] Stage 1: Building target...
[+] Build complete

[*] Stage 2: Fuzzing for 60s...
[+] Fuzzing done: 47 crash file(s)

[*] Stage 3: Triaging 47 crash file(s)...
[+] 3 unique crash(es) after dedup

[+] LLM provider: claude (claude-haiku-4-5)

[*] Processing crash_001: heap-buffer-overflow @ parse_name
    → Analysing with claude...
    → CWE-122 — Heap-based Buffer Overflow
    → Generating patch...
    → Patch validation: Fixed

[*] Processing crash_002: format-string @ log_record
    → Analysing with claude...
    → CWE-134 — Uncontrolled Format String
    → Generating patch...
    → Patch validation: Fixed

[*] Processing crash_003: integer-overflow @ allocate_records
    → Analysing with claude...
    → CWE-190 — Integer Overflow or Wraparound
    → Generating patch...
    → Patch validation: Fixed

============================================================
  Results
============================================================
  Crashes found    : 47
  Unique crashes   : 3
  Patches generated: 3
  Patches verified : 3
  HTML report      : output/vulnerable_parser_crs_report.html
  JSON export      : output/vulnerable_parser_crs_report.json
  SARIF export     : output/vulnerable_parser_crs_report.sarif
============================================================

── Top Findings ────────────────────────────────────
  [✓] crash_001 CWE-122    heap-buffer-overflow
  [✓] crash_002 CWE-134    format-string
  [✓] crash_003 CWE-190    integer-overflow
```

### Example 2 — auto daemon + dashboard

Drop a new C file into a watchlist directory. The inotify watcher fires, the agent processes:

```
~ $ echo 'void f(char *s){ char b[8]; strcpy(b,s); }' > ~/code/libfoo/bug.c

$ journalctl --user -u p4-agent -f
Oct 29 14:12:03 kali p4-agent[82431]: [watcher] change at /home/tony/code/libfoo
Oct 29 14:12:03 kali p4-agent[82431]: [jobq] enqueued 8f3a… target=/home/tony/code/libfoo
Oct 29 14:12:08 kali p4-agent[82431]: [agent] picking up 8f3a… libfoo
Oct 29 14:12:14 kali p4-agent[82431]: [crs] 2 unique crashes
Oct 29 14:12:19 kali p4-agent[82431]: [agent] severity=HIGH action=telegram_alert
Oct 29 14:12:19 kali p4-agent[82431]: [telegram] sent to chat 1234567
```

Dashboard view (`http://localhost:5557`, ASCII mock of the rendered Jinja):

```
┌──────────────────────────────────────────────────────────────┐
│  P4 Mini-CRS  —  dashboard                                   │
├──────────────────────────────────────────────────────────────┤
│  Jobs          pending: 0   running: 1   done: 42   fail: 1  │
│  Severity    CRIT: 3   HIGH: 7   MED: 12   LOW: 5   NONE: 15 │
├──────────────────────────────────────────────────────────────┤
│  Recent                                                      │
│  ✓ libfoo              HIGH    telegram_alert      14:12:19  │
│  ✓ vulnerable_parser   CRIT    file_github_issue   13:40:02  │
│  ✓ libxml2             MED     requeue_longer      12:08:47  │
│  ✗ custom_rtsp         —       crs crashed         11:33:10  │
├──────────────────────────────────────────────────────────────┤
│  Targets                                                     │
│  /home/tony/code/libfoo     n=4   last: HIGH                 │
│  targets/vulnerable_parser  n=12  last: CRITICAL             │
│  github:openssl/openssl     n=3   last: NONE                 │
└──────────────────────────────────────────────────────────────┘
```

### Example 3 — CVE/NVD-driven priority re-queue

Scenario: `libxml2` is in `auto/targets.yaml`, last fuzzed clean two days ago. CISA adds CVE-2026-XXXXX for libxml2 to the KEV catalog. At the next `p4-scheduler.timer` fire (03:00 daily), `auto/cve_poller.py` picks it up:

```
$ journalctl --user -u p4-scheduler -b
Oct 29 03:00:01 kali p4-scheduler: [cve_poller] KEV: 3 new, NVD: 47 new (7d window)
Oct 29 03:00:02 kali p4-scheduler: [cve_poller] match: libxml2 vs CVE-2026-XXXXX (KEV, CRITICAL)
Oct 29 03:00:02 kali p4-scheduler: [jobq] enqueued fuzz_time=120 (2× bump) target=libxml2
Oct 29 03:00:02 kali p4-scheduler: [cve_poller] match: openssl vs CVE-2026-YYYYY (NVD, HIGH)
Oct 29 03:00:02 kali p4-scheduler: [jobq] enqueued fuzz_time=120 target=openssl
Oct 29 03:00:02 kali p4-scheduler: done — 2 priority enqueues, 0 regular
```

The agent then processes libxml2 with the longer fuzz budget. If it finds a crash matching the KEV CVE's description, the triage prompt sees `source=KEV` in the context and biases toward `CRITICAL + file_github_issue`.

---

## Technical Reference

### Install

```bash
# System deps
sudo apt install -y afl++ gdb clang python3.11 python3.11-venv

# Python deps
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# For auto/ layer additionally
pip install anthropic python-dotenv pyyaml watchdog requests flask

# For github issue filing
gh auth login
```

### Config — `auto/.env`

```bash
# LLM
ANTHROPIC_API_KEY=sk-ant-...               # required for auto/ agent
OLLAMA_HOST=http://localhost:11434         # optional, Ollama fallback

# Telegram alerts
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=1234567
TELEGRAM_TOPIC_ID=42                       # optional, forum-group topic

# Tunables
P4_POLL_INTERVAL=10                        # agent queue poll (sec)
P4_MAX_FUZZ_TIME=600                       # ceiling for requeue_longer
P4_DASHBOARD_HOST=127.0.0.1
P4_DASHBOARD_PORT=5557
P4_DB_PATH=/absolute/path/to/jobq.db       # override SQLite location

# CVE poller
NVD_API_KEY=                               # optional, raises rate limit
```

### CLI Reference

```
python crs.py [options]

  -t, --target DIR            target source directory
                              (default: targets/vulnerable_parser)
  -s, --seeds DIR             seed corpus (default: <target>/seeds/)
  -o, --output DIR            output root (default: ./output)
  -f, --fuzz-time SEC         fuzz duration (default: 60)
      --no-fuzz               skip stage 2, use --crashes
      --crashes DIR           pre-existing crash corpus
      --no-llm                skip stages 4 + 5
      --llm-provider P        {ollama|claude|openai|openai-compat}
      --llm-model NAME        override model (e.g. claude-sonnet-4-6,
                              gpt-4o, hermes3:70b)
      --llm-endpoint URL      API endpoint
      --llm-api-key KEY       override env var
      --max-crashes N         unique crashes to analyse (default: 10)
```

### Auto Pipeline Deploy (systemd user units)

```bash
# 1. Clone the symlinks
mkdir -p ~/.config/systemd/user ~/projects/p4-mini-crs/auto/logs
cd ~/projects/p4-mini-crs/auto/systemd
for u in p4-agent.service p4-watcher.service p4-scheduler.service \
         p4-scheduler.timer p4-dashboard.service; do
  ln -sf "$PWD/$u" ~/.config/systemd/user/$u
done

# 2. Reload + enable
systemctl --user daemon-reload
systemctl --user enable --now p4-agent.service p4-watcher.service \
                              p4-scheduler.timer p4-dashboard.service

# 3. Survive logout
loginctl enable-linger "$USER"

# 4. Verify
systemctl --user status p4-agent
journalctl --user -u p4-agent -f
```

Unit summary:

| Unit | Type | When |
|---|---|---|
| `p4-agent.service` | `simple`, long-running | always; polls `jobq` every `P4_POLL_INTERVAL` |
| `p4-watcher.service` | `simple`, long-running | always; inotify on watchlist dirs |
| `p4-scheduler.service` | `oneshot` | fired by timer |
| `p4-scheduler.timer` | timer | `OnCalendar=*-*-* 03:00:00`, `Persistent=true` |
| `p4-dashboard.service` | `simple`, long-running | always; binds `127.0.0.1:5557` |

### Dashboard

| Route | What |
|---|---|
| `GET /` | overview: status counts, severity counts, targets, recent jobs |
| `GET /target/<path:target>` | per-target job history + prior stack hashes |
| `GET /findings` | all CRITICAL/HIGH/MEDIUM findings, newest first |
| `GET /trigger` | manual enqueue form |
| `POST /trigger` | enqueue `{target, fuzz_time}` |

SQLite schema (`jobq.db`):

```sql
CREATE TABLE jobs (
    job_id       TEXT PRIMARY KEY,
    status       TEXT NOT NULL,        -- pending | running | done | failed
    target       TEXT NOT NULL,
    source       TEXT NOT NULL,        -- watchlist | github | manual | cve
    fuzz_time    INTEGER NOT NULL DEFAULT 60,
    sarif_path   TEXT,
    severity     TEXT,                 -- CRITICAL | HIGH | MEDIUM | LOW | NONE
    action       TEXT,                 -- file_github_issue | telegram_alert | ...
    stack_hash   TEXT,                 -- SHA1(top-5 frames), for dedup
    error        TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at   DATETIME,
    finished_at  DATETIME
);
CREATE INDEX idx_jobs_status ON jobs(status, created_at);
```

Invariants:

- `enqueue()` dedupes: same `target` with status `pending` or `running` → returns existing job id, no new row.
- `pop_pending()` atomically claims the oldest `pending` → `running` (threading lock + single-writer SQLite).
- On agent restart, `resume_pending()` reverts orphaned `running` rows to `pending`.
- `seen_stack_hash(target, stack_hash)` powers the agent's `mark_ignore` decision for repeat finds.

### LLM Providers

| Flag | Provider | Env | Default model |
|---|---|---|---|
| `--llm-provider ollama` | Ollama (default) | `OLLAMA_HOST` | `hermes3:70b` |
| `--llm-provider claude` | Anthropic Claude | `ANTHROPIC_API_KEY` | `claude-haiku-4-5` |
| `--llm-provider openai` | OpenAI | `OPENAI_API_KEY` | `gpt-4o` |
| `--llm-provider openai-compat` | any OAI-compatible | `--llm-endpoint` required | per `--llm-model` |

The `auto/` **orchestration agent** always uses `claude-haiku-4-5` via the Anthropic Agent SDK — orthogonal to the internal analyzer/patcher LLM. You can mix: cheap Haiku agent + Ollama internal analyzer (fully local) OR Haiku agent + Claude Sonnet analyzer (premium quality).

### Prompt Caching Strategy

The agent's system prompt (~2–3k tokens of severity rubric + tool specs + CWE examples) is **frozen** and marked `cache_control: {type: "ephemeral"}`. Dynamic context — SARIF payload, prior findings for the target — goes in the user turn. On a second finding for the same target within 5 minutes, Anthropic returns a cache hit on the system prompt, dropping cost per decision from ~$0.015 to ~$0.003 and latency from ~2.5s to ~0.9s.

Rule: never put target-specific data in the system prompt. If it varies per job, it goes in the user turn.

### SARIF Export + GitHub Actions

```yaml
- name: Run CRS on demo target (no LLM, deterministic only)
  run: python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 30

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: output/vulnerable_parser_crs_report.sarif
    category: p4-mini-crs
```

Findings surface in the repo's **Security → Code scanning alerts** tab, with correct deduplication (via `partialFingerprints.stackHash`) across runs. Same UI as CodeQL / Snyk / Trivy — no custom dashboard required.

### Targets Directory Layout

```
targets/<name>/
├── main.c            # or any .c sources
├── Makefile          # must honour $(CC) and $(CFLAGS)
├── seeds/            # one file per seed input
│   └── seed.txt
└── README.md         # optional
```

Add a new target:

```bash
mkdir -p targets/mytarget/seeds
cp /path/to/program.c targets/mytarget/main.c
cat > targets/mytarget/Makefile <<'EOF'
CC ?= clang
CFLAGS ?= -O0 -g
all:
	$(CC) $(CFLAGS) main.c -o binary
EOF
echo "hello" > targets/mytarget/seeds/seed.txt
python crs.py --target targets/mytarget --fuzz-time 60
```

Register it with the auto pipeline — append to `auto/targets.yaml`:

```yaml
watchlist:
  - path: /home/tony/projects/p4-mini-crs/targets/mytarget
    enabled: true
    fuzz_time: 120
github:
  - repo: openssl/openssl
    branch: master
    enabled: true
    fuzz_time: 300
```

### Testing

```bash
# All 121 tests
python -m pytest tests/ -v

# Fast subset
python -m pytest tests/test_triage.py tests/test_sarif.py -v

# With coverage
python -m pytest tests/ --cov=stages --cov=engine --cov=auto
```

Coverage areas: crash-type classification, stack-hash dedup, JSON extraction edge cases, unified-diff hunk-header auto-correction, HTML/SARIF output structure, LLM provider mocking, auto-pipeline agent tool dispatch, jobq state machine, dashboard routes.

### Extending

**Add a new stage.** Drop a module in `stages/`, export a function that takes typed dataclasses from `models.py`, call it from `crs.py` between existing stages. No framework, no registry — just a function call.

**Add a new target.** See **Targets Directory Layout** above. The pipeline is target-agnostic; the only contract is `Makefile` honours `$(CC)`/`$(CFLAGS)` and the resulting `binary` reads from `argv[1]` or stdin.

**Add a new LLM provider.** Subclass `engine.llm_provider.LLMProvider` with `.generate()` and `.is_available()`. Register in `provider_from_args()`. All stages call the provider interface, so the new backend works end-to-end for free.

**Add a new agent tool.** In `auto/agent.py`, decorate a function with `@beta_tool` (Anthropic Agent SDK). Add it to the system prompt's tool list. The agent picks it in response to appropriate findings — no scheduler/watcher changes needed.

---

## Why This Was Built

DARPA AIxCC ($29.5M prize pool, finals Aug 2025) is explicitly asking the field: can an AI, unattended, defend real open-source infrastructure against memory-corruption bugs? The winning teams built massive distributed CRSs — multi-GPU, multi-fuzzer, multi-LLM-ensemble. P4 Mini-CRS is the laptop version of the same loop: not competition-scale, but every architectural element (deterministic bug discovery, LLM-glued analysis+patch, deterministic patch validation, SARIF publication, continuous CVE-driven re-triage) is present and testable in isolation.

Career angle: AI × security is where I'm going. Target role is senior cybersec analyst / AI-security engineer in the $200–250k USD range. Projects P1–P5 are each a working artifact at one layer of the AI-security stack:

- **P1** — SAST + DAST triage tool (static)
- **P2** — Threat model generator (design-time)
- **P3** — AI log anomaly detector (runtime)
- **P4** — this project, autonomous vuln discovery + patch (CRS)
- **P5** — ATLAS, autonomous HTB pentest pipeline (offensive)

P4 is the one that proves I can build an end-to-end autonomous security loop, not just a classifier wired to a dashboard.

---

## FAQ

**Q — Doesn't the LLM hallucinate patches that look right but don't work?**
Yes, often. That's why `stages/patcher.py` applies every patch, recompiles, and replays the original crash input against the new binary. A patch is only `Verified` if the replay exits clean. Hallucinated patches land as `Failed` — the bug is still reported, just with the fix flagged for human review.

**Q — What's the difference between the one-shot CLI and the auto pipeline?**
`crs.py` is a batch tool — one target, one run, three output files, done. `auto/` is a daemon loop: it watches target directories + GitHub repos + CVE feeds, enqueues jobs on change, and lets a Claude Haiku 4.5 agent decide what to do with each result (file issue, Telegram, re-fuzz longer, ignore). You can use either or both; `auto/` wraps `crs.py` and doesn't modify it.

**Q — Why Haiku 4.5 for the agent, Sonnet available for the analyzer?**
The agent's job is 4-way classification over a short SARIF payload — Haiku handles that at ~$0.003/decision with prompt caching. The analyzer's job is root-cause reasoning over C source with subtle control-flow — Sonnet pays for itself there if the target is complex. Pass `--llm-model claude-sonnet-4-6` to opt in.

**Q — Can I run this fully offline?**
Yes. Set `--llm-provider ollama` on `crs.py` (point `OLLAMA_HOST` at your local Ollama) and skip the `auto/` layer, which requires Claude API for the agent. Deterministic stages (build, fuzz, triage, SARIF export) have no network dependency at all.

**Q — Where does the SARIF output end up on GitHub?**
Repo → Security tab → Code scanning alerts. Same UI as CodeQL / Snyk / Trivy. The upload step is `github/codeql-action/upload-sarif@v3` — see `.github/workflows/`.

**Q — How many crashes become one finding?**
AFL++ emits lots of crash files (dozens to hundreds) for the same underlying bug. `stages/triage.py` replays each through ASan + GDB, extracts the top 5 **user-space** stack frames (filtering ASan internals and libc), SHA1s the frame-name tuple → `stack_id`. Same `stack_id` → same bug → one `CrashInfo` record. Same technique ForAllSecure Mayhem and `afl-cmin` use.

**Q — What does the CVE/NVD poller actually prioritize?**
At the daily 03:00 scheduler fire, `auto/cve_poller.py` fetches CISA KEV (actively-exploited CVEs, highest signal) + NVD CVE 2.0 recent (7-day window). For each watchlist target, it substring-matches the target name against the CVE's vendor + product fields. Matches are re-enqueued with `fuzz_time` doubled and `source=KEV` or `source=NVD` baked into the agent's context, biasing it toward `CRITICAL + file_github_issue` if a crash lands.

**Q — Is this production-ready?**
It is production-ready for one specific role: continuous fuzzing of a short list of OSS C libraries you track, with triaged findings going to GitHub Security + Telegram. It is **not** a replacement for Mayhem, OSS-Fuzz, or a competition-scale CRS. The `ponytail:` comments in the source call out the known ceilings (SQLite single-writer, product-name CVE match, per-target single-process agent).

---

## License / Credits

MIT. Use it, fork it, run it against your own code — not against targets you don't own.

**Inspiration:** [DARPA AI Cyber Challenge (AIxCC)](https://aicyberchallenge.com/) — the public prize competition that defined the "autonomous Cyber Reasoning System" concept. The architecture here follows the AIxCC pattern (deterministic bug discovery + LLM-generated analysis/patch + deterministic validation + SARIF publication) at a fraction of the scale.

**Prior art acknowledged:**

- [AFL++](https://aflplus.plus/) — the fuzzing engine.
- [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) — the ground-truth bug detector.
- [OSS-Fuzz](https://google.github.io/oss-fuzz/) — the dual-build (fast fuzzer + detailed ASan) pattern.
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — OASIS spec, GitHub Code Scanning consumer.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) + [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) — CVE prioritization feeds.
- [Anthropic Agent SDK](https://docs.anthropic.com/en/docs/agents) — tool-runner pattern for the auto layer.
