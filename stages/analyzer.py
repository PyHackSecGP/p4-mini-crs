"""LLM root cause analysis via Ollama."""
from __future__ import annotations
import json
import re
import requests
from models import Analysis, CrashInfo

OLLAMA_BASE = "http://100.126.22.55:11434"
MODEL = "hermes3:70b"
TIMEOUT = 180


def _read_source_context(source_dir: str, function_name: str, window: int = 30) -> str:
    """Extract source lines around the vulnerable function."""
    from pathlib import Path
    context_lines: list[str] = []
    for c_file in Path(source_dir).glob("*.c"):
        lines = c_file.read_text().splitlines()
        for i, line in enumerate(lines):
            if function_name and function_name in line:
                start = max(0, i - 5)
                end = min(len(lines), i + window)
                context_lines.append(f"// {c_file.name}:{start+1}-{end}")
                context_lines.extend(
                    f"{j+1:4d}: {lines[j]}" for j in range(start, end)
                )
                break
    if not context_lines:
        # Return first 80 lines of first source file
        for c_file in Path(source_dir).glob("*.c"):
            lines = c_file.read_text().splitlines()[:80]
            context_lines = [f"{i+1:4d}: {l}" for i, l in enumerate(lines)]
            break
    return "\n".join(context_lines)


def _build_prompt(crash: CrashInfo, source_context: str) -> str:
    return f"""You are a senior vulnerability researcher performing root cause analysis on a crash.

## Crash Information
- Crash ID: {crash.crash_id}
- Signal: {crash.signal}
- Crash Type (detected): {crash.crash_type.value}
- Top Stack Frame: {crash.top_frame}
- Crash Address: {crash.crash_address}

## ASan Output
{crash.asan_output[:2000]}

## Source Code Context
{source_context[:3000]}

## Task
Analyse this crash and respond with a JSON object containing exactly these fields:
{{
  "cwe_id": "CWE-XXX",
  "cwe_name": "Name of the CWE",
  "vulnerability_type": "One-line type description",
  "vulnerable_function": "function_name",
  "vulnerable_lines": "line numbers or range e.g. 18-22",
  "root_cause": "2-3 sentences explaining the exact root cause technically",
  "attack_scenario": "2-3 sentences on how an attacker would exploit this in the real world",
  "severity": "Critical|High|Medium|Low",
  "exploitability": "High|Medium|Low",
  "fix_approach": "1-2 sentences describing the correct fix"
}}

Return only the JSON object. No markdown, no explanation outside the JSON."""


def analyze_crash(
    crash: CrashInfo,
    source_dir: str,
) -> Analysis:
    """Run LLM root cause analysis on a crash."""
    source_context = _read_source_context(source_dir, crash.top_frame)
    prompt = _build_prompt(crash, source_context)

    try:
        resp = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "").strip()
    except Exception as e:
        return Analysis(raw_response=f"LLM error: {e}")

    # Extract JSON from response
    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if not json_match:
        return Analysis(raw_response=raw)

    try:
        data = json.loads(json_match.group(0))
    except json.JSONDecodeError:
        return Analysis(raw_response=raw)

    return Analysis(
        cwe_id=data.get("cwe_id", ""),
        cwe_name=data.get("cwe_name", ""),
        vulnerability_type=data.get("vulnerability_type", ""),
        vulnerable_function=data.get("vulnerable_function", crash.top_frame),
        vulnerable_lines=data.get("vulnerable_lines", ""),
        root_cause=data.get("root_cause", ""),
        attack_scenario=data.get("attack_scenario", ""),
        severity=data.get("severity", "High"),
        exploitability=data.get("exploitability", "Medium"),
        fix_approach=data.get("fix_approach", ""),
        raw_response=raw,
    )


def is_ollama_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False
