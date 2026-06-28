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
  triage.py      GDB backtrace + ASan output + stack hash dedup
      ↓
  analyzer.py    Ollama LLM → CWE + root cause + attack scenario
      ↓
  patcher.py     Ollama LLM → unified diff → apply → recompile → verify
      ↓
  reporter.py    Executive HTML report with patch diffs + validation results
```

## Requirements

```bash
sudo apt-get install -y afl++ gdb
pip install -r requirements.txt
```

Ollama endpoint: `http://100.126.22.55:11434` (on-prem, no data egress)
Model: `hermes3:70b`

## Quick Start

```bash
# Full pipeline — 60s fuzzing on demo target
python crs.py --target targets/vulnerable_parser --fuzz-time 60 --output output/

# Longer fuzz for more crashes
python crs.py --target targets/vulnerable_parser --fuzz-time 300

# Skip LLM (fuzzing + triage only)
python crs.py --target targets/vulnerable_parser --no-llm

# Use existing crashes, skip fuzzing
python crs.py --target targets/vulnerable_parser --no-fuzz --crashes output/afl_output/default/crashes/
```

Open `output/vulnerable_parser_crs_report.html` in a browser.

## Demo Target

`targets/vulnerable_parser/main.c` — deliberately vulnerable C file parser with:
- **VULN-1:** Stack buffer overflow via `strcpy` (CWE-121)
- **VULN-2:** Format string bug (CWE-134)
- **VULN-3:** Integer overflow in allocation (CWE-190)

## Own Target

```bash
python crs.py --target /path/to/your/c/source/ --seeds /path/to/seeds/ --fuzz-time 300
```

Requirements:
- Source directory contains `.c` files compilable with a single `clang` invocation
- Seeds directory contains at least one valid input sample

## Report Sections

- **Stats** — crashes found, unique, patches generated, verified, fix rate
- **Per-finding** — crash details, ASan output, LLM root cause, attack scenario, generated diff, patch validation result

## Stack

- AFL++ (fuzzing)
- AddressSanitizer / GDB (crash analysis)
- Python 3.11+ (orchestration)
- Ollama hermes3:70b (root cause analysis + patch generation)
