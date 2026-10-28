#!/usr/bin/env bash
# runner.sh — invoke crs.py on a target, emit JSON summary.
#
# Usage: runner.sh <target_dir> <fuzz_time> <job_id>
# Output: single-line JSON {sarif,report_html,report_json,exit_code,log} to stdout.
# Logs full crs.py output to auto/logs/<job_id>.log.

set -uo pipefail

TARGET="${1:?target dir required}"
FUZZ_TIME="${2:?fuzz time required}"
JOB_ID="${3:?job id required}"

AUTO_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$AUTO_DIR")"
LOG="$AUTO_DIR/logs/${JOB_ID}.log"
OUT_DIR="$PROJECT_DIR/output/auto_${JOB_ID}"

mkdir -p "$OUT_DIR" "$AUTO_DIR/logs"

TARGET_ABS="$(realpath "$TARGET")"
if [[ ! -d "$TARGET_ABS" ]]; then
  echo "{\"exit_code\":2,\"error\":\"target not found: $TARGET_ABS\"}"
  exit 2
fi

# Prefer Ollama for pipeline-internal LLM calls (triage/analysis).
# Agent orchestration (Claude Haiku) happens in agent.py, not here.
cd "$PROJECT_DIR"
if [[ -d venv ]]; then
  # shellcheck disable=SC1091
  source venv/bin/activate
fi

python3 crs.py \
  --target "$TARGET_ABS" \
  --output "$OUT_DIR" \
  --fuzz-time "$FUZZ_TIME" \
  --llm-provider "${P4_LLM_PROVIDER:-ollama}" \
  >"$LOG" 2>&1
EC=$?

TARGET_NAME="$(basename "$TARGET_ABS")"
SARIF="$OUT_DIR/${TARGET_NAME}_crs_report.sarif"
REPORT_JSON="$OUT_DIR/${TARGET_NAME}_crs_report.json"
REPORT_HTML="$OUT_DIR/${TARGET_NAME}_crs_report.html"

python3 -c "
import json, os
sarif = '$SARIF' if os.path.exists('$SARIF') else None
rj = '$REPORT_JSON' if os.path.exists('$REPORT_JSON') else None
rh = '$REPORT_HTML' if os.path.exists('$REPORT_HTML') else None
print(json.dumps({
    'exit_code': $EC,
    'sarif': sarif,
    'report_json': rj,
    'report_html': rh,
    'log': '$LOG',
    'target': '$TARGET_ABS',
}))
"
exit $EC
