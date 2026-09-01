"""Export CRS findings as SARIF 2.1.0 for GitHub Security tab / DefectDojo import."""
from __future__ import annotations
import json
from pathlib import Path
from models import CRSResult, ValidationResult

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SEV_MAP = {
    "Critical": "error",
    "High":     "error",
    "Medium":   "warning",
    "Low":      "note",
}

_HELP_TEXT = {
    "CWE-120": "Buffer copy without checking size of input. Use safe string functions (snprintf, strlcpy) and validate all buffer bounds before copy.",
    "CWE-121": "Stack-based buffer overflow. Allocate sufficient stack space and validate input length before writing.",
    "CWE-122": "Heap-based buffer overflow. Use bounded allocation and validate size arithmetic before heap writes.",
    "CWE-134": "Format string vulnerability. Never pass user-controlled data as the format argument to printf-family functions. Use printf('%s', input) instead of printf(input).",
    "CWE-190": "Integer overflow in size calculation leads to under-allocated buffer. Validate arithmetic before using result as allocation size.",
    "CWE-416": "Use-after-free. Set pointers to NULL after free and check before dereference.",
    "CWE-476": "Null pointer dereference. Validate pointer before use; check return values from malloc/calloc.",
}

_CWE_URLS = {
    cwe: f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html"
    for cwe in _HELP_TEXT
}


def _build_rule(finding) -> dict:
    a = finding.analysis
    cwe_id = a.cwe_id or "CWE-unknown"
    cwe_num = cwe_id.replace("CWE-", "")
    rule_id = f"mini-crs/{cwe_id}"
    help_text = _HELP_TEXT.get(cwe_id, a.fix_approach or "Review and fix the identified vulnerability.")
    cwe_url = _CWE_URLS.get(cwe_id, f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")

    return {
        "id": rule_id,
        "name": (a.cwe_name or a.vulnerability_type or cwe_id).replace(" ", ""),
        "shortDescription": {"text": a.cwe_name or cwe_id},
        "fullDescription": {"text": a.root_cause or a.cwe_name or cwe_id},
        "helpUri": cwe_url,
        "help": {
            "text": help_text,
            "markdown": f"**{cwe_id}**: {help_text}\n\nSee: [{cwe_url}]({cwe_url})",
        },
        "properties": {
            "tags": ["security", "correctness", cwe_id],
            "precision": "high",
            "problem.severity": _SEV_MAP.get(a.severity or "High", "warning"),
        },
        "defaultConfiguration": {
            "level": _SEV_MAP.get(a.severity or "High", "warning"),
        },
    }


def _parse_vulnerable_line(analysis) -> tuple[str, int]:
    """Extract (filename, line_number) from Analysis.vulnerable_lines field."""
    raw = analysis.vulnerable_lines or ""
    # Common patterns: "main.c:42", "42", "line 42", "src/main.c:42-45"
    import re
    m = re.search(r'([a-zA-Z0-9_./]+\.c)[\s:]+(\d+)', raw)
    if m:
        return m.group(1), int(m.group(2))
    m = re.search(r'(\d+)', raw)
    if m:
        return "unknown", int(m.group(1))
    return "unknown", 1


def _build_result(finding, rule_id: str, target_source: str) -> dict:
    c = finding.crash
    a = finding.analysis
    src_file, line_num = _parse_vulnerable_line(a)

    # Prefer actual source path from target_source
    if src_file == "unknown" and target_source:
        src_file = str(Path(target_source) / "main.c")

    message_lines = [
        f"{a.cwe_id or 'Vulnerability'}: {a.cwe_name or c.crash_type.value}",
        f"Root cause: {a.root_cause}" if a.root_cause else "",
        f"Attack scenario: {a.attack_scenario}" if a.attack_scenario else "",
        f"Crash signal: {c.signal}" if c.signal else "",
        f"Top frame: {c.top_frame}" if c.top_frame else "",
        f"Stack hash: {c.stack_hash}" if c.stack_hash else "",
    ]
    message = " | ".join(l for l in message_lines if l)

    result: dict = {
        "ruleId": rule_id,
        "level": _SEV_MAP.get(a.severity or "High", "warning"),
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": src_file,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": line_num,
                    "startColumn": 1,
                },
            },
            "logicalLocations": [{
                "name": a.vulnerable_function or c.top_frame or "unknown",
                "kind": "function",
            }],
        }],
        "fingerprints": {
            "stackHash/v1": c.stack_hash,
        },
        "properties": {
            "crashId":          c.crash_id,
            "crashType":        c.crash_type.value,
            "exploitability":   a.exploitability,
            "patchStatus":      finding.patch.validation.value,
            "severity":         a.severity or "High",
        },
    }

    # Attach fix if patch was generated
    if finding.patch.diff:
        result["fixes"] = [{
            "description": {"text": a.fix_approach or "Apply generated patch"},
            "artifactChanges": [{
                "artifactLocation": {
                    "uri": src_file,
                    "uriBaseId": "%SRCROOT%",
                },
                "replacements": [{
                    "deletedRegion": {
                        "startLine": line_num,
                        "startColumn": 1,
                    },
                    "insertedContent": {"text": f"# Patch available — see diff:\n{finding.patch.diff[:500]}"},
                }],
            }],
        }]

    return result


def generate_sarif(result: CRSResult, output_path: str) -> None:
    """Write SARIF 2.1.0 file from CRS findings."""
    seen_rule_ids: set[str] = set()
    rules: list[dict] = []
    sarif_results: list[dict] = []

    for finding in result.findings:
        a = finding.analysis
        cwe_id = a.cwe_id or "CWE-unknown"
        rule_id = f"mini-crs/{cwe_id}"

        if rule_id not in seen_rule_ids:
            rules.append(_build_rule(finding))
            seen_rule_ids.add(rule_id)

        sarif_results.append(_build_result(finding, rule_id, result.target_source))

    sarif_doc = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mini-crs",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/PyHackSecGP/p4-mini-crs",
                    "rules": rules,
                    "properties": {
                        "pipeline": "AFL++ → ASan → GDB → LLM analysis → patch validation",
                    },
                }
            },
            "results": sarif_results,
            "artifacts": [{
                "location": {
                    "uri": result.target_source or "target/",
                    "uriBaseId": "%SRCROOT%",
                },
                "description": {"text": f"Fuzz target: {result.target_name}"},
            }],
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [{
                    "message": {
                        "text": (
                            f"Fuzzing: {result.fuzzing_duration_seconds}s | "
                            f"Executions: {result.total_executions:,} | "
                            f"Crashes: {result.crashes_found} | "
                            f"Unique: {result.unique_crashes} | "
                            f"Fixed: {result.fixed_count}/{len(result.findings)} | "
                            f"LLM: {result.llm_provider or 'unknown'}"
                        )
                    },
                    "level": "note",
                }],
            }],
            "columnKind": "utf16CodeUnits",
        }],
    }

    Path(output_path).write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
