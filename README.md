# P4 — Mini-CRS: Autonomous Vulnerability Discovery & Patch Suggestion

Inspired by DARPA AIxCC. Automated pipeline: fuzz → triage → LLM root cause → LLM patch → validate → executive report.

## Pipeline

```
Target C source
      ↓
  builder.py     Compile with AFL++ + AddressSanitizer
      ↓
  fuzzer.py      afl-fuzz → crash corpus
      ↓
  triage.py      ASan output + GDB backtrace + stack hash dedup
      ↓
  analyzer.py    LLM → CWE + root cause + attack scenario (JSON)
      ↓
  patcher.py     LLM → unified diff → apply → recompile → verify → restore
      ↓
  reporter.py    Executive HTML + JSON report
```

## Requirements

```bash
sudo apt-get install -y afl++ gdb
pip install -r requirements.txt
```

## Quick Start

```bash
# Full pipeline — 60s fuzzing, local Ollama
python crs.py --target targets/vulnerable_parser --fuzz-time 60 --output output/

# Use Claude as LLM
python crs.py --target targets/vulnerable_parser --fuzz-time 60 \
  --llm-provider claude --llm-model claude-haiku-4-5-20251001

# Use OpenAI
python crs.py --target targets/vulnerable_parser --fuzz-time 60 \
  --llm-provider openai --llm-model gpt-4o

# Any OpenAI-compatible endpoint (vLLM, LM Studio, etc.)
python crs.py --target targets/vulnerable_parser --fuzz-time 60 \
  --llm-provider openai-compat --llm-endpoint http://localhost:8000 \
  --llm-model my-model --llm-api-key sk-...

# Skip fuzzing, use existing crashes
python crs.py --target targets/vulnerable_parser --no-fuzz \
  --crashes output/afl_output/default/crashes/

# Fuzzing + triage only, no LLM
python crs.py --target targets/vulnerable_parser --no-llm --fuzz-time 60
```

Open `output/vulnerable_parser_crs_report.html` in a browser.

## LLM Providers

| Flag | Backend | Auth |
|---|---|---|
| `--llm-provider ollama` | Local Ollama (default: `http://100.126.22.55:11434`) | None |
| `--llm-provider claude` | Anthropic Messages API | `ANTHROPIC_API_KEY` env var or `--llm-api-key` |
| `--llm-provider openai` | OpenAI Chat Completions | `OPENAI_API_KEY` env var or `--llm-api-key` |
| `--llm-provider openai-compat` | Any OpenAI-compatible endpoint | `--llm-endpoint` + `--llm-api-key` |

## Demo Target

`targets/vulnerable_parser/main.c` — deliberately vulnerable C file parser with:
- **VULN-1:** Heap buffer overflow via `strcpy` into heap-allocated struct field (CWE-122)
- **VULN-2:** Format string bug via `printf(user_input)` (CWE-134)
- **VULN-3:** Integer overflow in allocation (CWE-190, fixed to let AFL reach deeper paths)

## Own Target

```bash
python crs.py --target /path/to/your/c/source/ --seeds /path/to/seeds/ --fuzz-time 300
```

Requirements:
- Source directory contains `.c` files compilable with a single `clang` invocation
- Seeds directory contains at least one valid input sample

## Report Sections

- **Stats bar** — crashes found, unique, patches generated, verified, fix rate
- **Per-finding** — signal, top frame, CWE link, exploitability, root cause, attack scenario, fix approach, ASan output, syntax-highlighted diff, patch validation result

## CLI Reference

```
--target / -t       Path to target source directory
--seeds  / -s       Seed corpus directory (default: <target>/seeds/)
--output / -o       Output directory (default: ./output)
--fuzz-time / -f    Fuzzing duration in seconds (default: 60)
--no-fuzz           Skip fuzzing — requires --crashes
--crashes           Directory of existing crash files
--no-llm            Skip LLM analysis and patching
--llm-provider      ollama | claude | openai | openai-compat
--llm-model         Model name override
--llm-endpoint      API endpoint URL (required for openai-compat)
--llm-api-key       API key (or set env var)
--max-crashes       Max unique crashes to analyse (default: 10)
```

## Stack

- AFL++ — coverage-guided fuzzing
- AddressSanitizer / GDB — crash triage
- Python 3.11+ — pipeline orchestration
- Ollama / Claude / OpenAI — root cause analysis + patch generation
