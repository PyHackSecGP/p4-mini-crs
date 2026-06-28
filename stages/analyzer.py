"""LLM root cause analysis — provider-agnostic."""
from __future__ import annotations
import json
import re
from pathlib import Path
from models import Analysis, CrashInfo
from engine.llm_provider import LLMProvider


def _read_source_context(source_dir: str, function_name: str, window: int = 40) -> str:
    """Extract source lines around the vulnerable function."""
    context_lines: list[str] = []
    for c_file in Path(source_dir).glob("*.c"):
        lines = c_file.read_text().splitlines()
        for i, line in enumerate(lines):
            if function_name and function_name in line:
                start = max(0, i - 5)
                end = min(len(lines), i + window)
                context_lines.append(f"// {c_file.name}:{start+1}-{end}")
                context_lines.extend(f"{j+1:4d}: {lines[j]}" for j in range(start, end))
                break
    if not context_lines:
        for c_file in Path(source_dir).glob("*.c"):
            lines = c_file.read_text().splitlines()[:100]
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

## ASan / Sanitizer Output
{crash.asan_output[:2500]}

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
  "attack_scenario": "2-3 sentences on how an attacker would exploit this",
  "severity": "Critical|High|Medium|Low",
  "exploitability": "High|Medium|Low",
  "fix_approach": "1-2 sentences describing the correct fix"
}}

Return only the JSON object. No markdown fences, no explanation outside the JSON."""


def analyze_crash(crash: CrashInfo, source_dir: str, provider: LLMProvider) -> Analysis:
    """Run LLM root cause analysis on a crash using the given provider."""
    source_context = _read_source_context(source_dir, crash.top_frame)
    prompt = _build_prompt(crash, source_context)

    try:
        raw = provider.generate(prompt)
    except Exception as e:
        return Analysis(raw_response=f"LLM error: {e}")

    json_match = re.search(r'\{[^{}]*\}', raw, re.DOTALL)
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
