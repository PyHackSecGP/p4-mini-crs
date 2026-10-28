"""P4 Mini-CRS auto-pipeline agent daemon.

Pops jobs from the SQLite queue, runs crs.py via runner.sh, feeds the SARIF
output to Claude Haiku 4.5 via the Agent SDK tool runner, and executes the
agent's chosen action (telegram alert, re-fuzz with longer time, mark ignore).

Env:
    ANTHROPIC_API_KEY  — required for the SDK
    P4_POLL_INTERVAL   — seconds between queue polls (default 10)
    P4_MAX_FUZZ_TIME   — ceiling for re-fuzz escalation (default 600)
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import anthropic
from anthropic import beta_tool

sys.path.insert(0, str(Path(__file__).parent))
import jobq
import notify

AUTO_DIR = Path(__file__).parent
RUNNER = AUTO_DIR / "runner.sh"
POLL_INTERVAL = int(os.getenv("P4_POLL_INTERVAL", "10"))
MAX_FUZZ_TIME = int(os.getenv("P4_MAX_FUZZ_TIME", "600"))
MODEL = "claude-haiku-4-5"

SYSTEM_PROMPT = """You are a security triage agent for a C vulnerability discovery pipeline.

You will receive the SARIF 2.1.0 output of a fuzzing + ASan + LLM analysis run against a C target,
plus a list of PRIOR findings for this target (stack_hash + severity + action from past runs).
Your job: decide what action to take based on the findings.

SEVERITY CLASSIFICATION

- CRITICAL
  * ASan heap-buffer-overflow / stack-buffer-overflow with WRITE and controllable size
  * Use-after-free, double-free, invalid-free
  * Format string with user-controlled fmt and %n or multiple %s
  * CWE-120/121/122, CWE-134 (controllable), CWE-416, CWE-415
- HIGH
  * ASan OOB-WRITE where controllability is uncertain
  * Integer overflow leading to under-allocated buffer (CWE-190)
  * ASan read-oob with reachable sink
- MEDIUM
  * Null-pointer dereference reaching an exploitable sink (CWE-476)
  * Resource exhaustion / infinite loop reachable from input
  * OOB-READ with no sink
- LOW
  * Style / robustness LLM flags with no crash
  * Dead-code warnings
- NONE
  * No SARIF findings, pipeline succeeded cleanly

DECISION RULES — call EXACTLY ONE tool

1. CRITICAL finding
   a. If target source starts with `scheduler_github:` (job.source) → call file_github_issue
   b. Else → call send_telegram
2. HIGH finding → call send_telegram
3. MEDIUM finding
   a. If finding's stack_hash matches ANY entry in PRIOR findings → call mark_ignore ("dedup: already reported")
   b. Else → call send_telegram
4. LOW only → call mark_ignore ("low severity only")
5. NONE
   a. If fuzz_time < 300 → call requeue_longer_fuzz (short fuzz may have missed crashes)
   b. Else → call mark_ignore ("no findings after adequate fuzzing")

STACK_HASH compute from file:line:function of the top finding. We'll re-derive it
inside send_telegram so you don't need to compute it yourself — just report file/line/function
accurately.

Be decisive. Call ONE tool, no preamble, no explanation."""


class AgentContext:
    """Shared state for tool invocations within one job."""

    def __init__(self, job: dict[str, Any], sarif_data: dict[str, Any] | None):
        self.job = job
        self.sarif = sarif_data
        self.chosen_action: str | None = None
        self.severity: str | None = None
        self.stack_hash: str | None = None


_ctx: AgentContext | None = None


@beta_tool
def send_telegram(severity: str, cwe: str, file: str, line: int,
                  function: str, summary: str) -> str:
    """Send a Telegram alert for a high-severity finding.

    Args:
        severity: One of CRITICAL, HIGH, MEDIUM.
        cwe: CWE identifier like CWE-120.
        file: Source file path.
        line: Line number.
        function: Function name.
        summary: One-paragraph description of the vulnerability.
    """
    assert _ctx is not None
    finding = {
        "cwe": cwe, "file": file, "line": line,
        "function": function, "summary": summary,
    }
    ok = notify.send_finding(_ctx.job["target"], severity, finding)
    _ctx.chosen_action = f"telegram:{severity}"
    _ctx.severity = severity
    _ctx.stack_hash = hashlib.sha1(
        f"{file}:{line}:{function}".encode()
    ).hexdigest()[:16]
    return f"Alert sent: {ok}"


@beta_tool
def requeue_longer_fuzz(reason: str) -> str:
    """Re-enqueue the target with a longer fuzz time (2x, capped at P4_MAX_FUZZ_TIME).

    Args:
        reason: Why a longer fuzz is justified.
    """
    assert _ctx is not None
    new_time = min(_ctx.job["fuzz_time"] * 2, MAX_FUZZ_TIME)
    if new_time <= _ctx.job["fuzz_time"]:
        _ctx.chosen_action = "ignore:fuzz_time_at_ceiling"
        _ctx.severity = "NONE"
        return "Already at max fuzz time; not re-queuing."
    jobq.enqueue(_ctx.job["target"], source="agent_requeue", fuzz_time=new_time)
    _ctx.chosen_action = f"requeue:{new_time}s"
    _ctx.severity = "NONE"
    return f"Re-enqueued with fuzz_time={new_time}s. Reason: {reason}"


def _github_repo_from_source(source: str) -> str | None:
    """Extract owner/repo from `scheduler_github:owner/repo`."""
    if source and source.startswith("scheduler_github:"):
        return source.split(":", 1)[1]
    return None


@beta_tool
def file_github_issue(severity: str, cwe: str, file: str, line: int,
                      function: str, summary: str) -> str:
    """File a GitHub issue for a CRITICAL finding on a github-sourced target.

    Only works when job.source starts with `scheduler_github:`. Uses `gh issue create`
    with labels `security,p4-crs,severity:<level>`.

    Args:
        severity: One of CRITICAL, HIGH (file issues only for these).
        cwe: CWE identifier.
        file: Source file path (repo-relative).
        line: Line number.
        function: Function name.
        summary: One-paragraph description.
    """
    assert _ctx is not None
    repo = _github_repo_from_source(_ctx.job.get("source", ""))
    if not repo:
        _ctx.chosen_action = f"issue_skip:not_github_source"
        _ctx.severity = severity
        return "Not a github-sourced target; skipping issue. Call send_telegram instead."

    stack_hash = hashlib.sha1(
        f"{file}:{line}:{function}".encode()
    ).hexdigest()[:16]
    title = f"[P4-CRS/{severity}] {cwe} in {function}() at {file}:{line}"
    body = (
        f"**Severity:** {severity}\n"
        f"**CWE:** {cwe}\n"
        f"**Location:** `{file}:{line}` in `{function}`\n"
        f"**Stack hash:** `{stack_hash}`\n\n"
        f"## Summary\n\n{summary}\n\n"
        f"---\n*Auto-filed by P4 Mini-CRS auto-pipeline. "
        f"Job: `{_ctx.job['job_id']}`.*"
    )
    try:
        import subprocess
        subprocess.run(
            [
                "gh", "issue", "create", "--repo", repo,
                "--title", title, "--body", body,
                "--label", f"security,p4-crs,severity:{severity.lower()}",
            ],
            capture_output=True, text=True, timeout=30, check=True,
        )
        notify.send_finding(_ctx.job["target"], severity,
                            {"cwe": cwe, "file": file, "line": line,
                             "function": function,
                             "summary": f"GH issue filed on {repo}. {summary}"})
        _ctx.chosen_action = f"gh_issue:{repo}"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        _ctx.chosen_action = f"gh_issue_failed:{type(e).__name__}"
        return f"gh issue create failed: {e}"
    _ctx.severity = severity
    _ctx.stack_hash = stack_hash
    return f"Issue filed on {repo} and Telegram sent."


@beta_tool
def mark_ignore(reason: str, severity: str = "NONE") -> str:
    """Mark the job done with no further action.

    Args:
        reason: Why no action is warranted.
        severity: Top severity observed (NONE if nothing found).
    """
    assert _ctx is not None
    _ctx.chosen_action = f"ignore:{reason[:40]}"
    _ctx.severity = severity
    return f"Marked ignore. Reason: {reason}"


def run_pipeline(job: dict[str, Any]) -> dict[str, Any]:
    """Invoke runner.sh. Returns the parsed JSON summary."""
    proc = subprocess.run(
        [str(RUNNER), job["target"], str(job["fuzz_time"]), job["job_id"]],
        capture_output=True, text=True, timeout=job["fuzz_time"] + 300,
    )
    # runner.sh prints a JSON line even on non-zero exit
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"exit_code": proc.returncode, "error": proc.stderr[-500:]}


def load_sarif(path: str | None) -> dict[str, Any] | None:
    if not path or not Path(path).exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def run_agent(client: anthropic.Anthropic, job: dict[str, Any],
              pipeline_result: dict[str, Any], sarif: dict[str, Any] | None) -> AgentContext:
    """Run the Haiku tool-runner loop over the pipeline result."""
    global _ctx
    _ctx = AgentContext(job, sarif)

    sarif_summary = (
        json.dumps(sarif, indent=2)[:12000]
        if sarif else "No SARIF produced."
    )
    prior = jobq.prior_findings(job["target"])
    prior_text = (
        "\n".join(
            f"- stack_hash={p['stack_hash']} severity={p['severity']} "
            f"action={p['action']} at={p['finished_at']}"
            for p in prior
        )
        if prior else "(none — first time seeing this target)"
    )
    user_content = (
        f"Target: {job['target']}\n"
        f"Source: {job.get('source', 'unknown')}\n"
        f"Fuzz time: {job['fuzz_time']}s\n"
        f"Pipeline exit code: {pipeline_result.get('exit_code')}\n"
        f"\nPRIOR findings for this target:\n{prior_text}\n"
        f"\nSARIF output:\n{sarif_summary}\n"
    )

    runner = client.beta.messages.tool_runner(
        model=MODEL,
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        tools=[send_telegram, file_github_issue, requeue_longer_fuzz, mark_ignore],
        messages=[{"role": "user", "content": user_content}],
    )

    for _ in runner:
        pass  # tools mutate _ctx; loop exits when the model stops calling tools

    return _ctx


_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    _shutdown = True
    print(f"agent: caught signal {signum}, draining and shutting down", flush=True)


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    jobq.init()
    jobq.resume_pending()
    client = anthropic.Anthropic()
    print(f"agent: started, polling every {POLL_INTERVAL}s", flush=True)

    while not _shutdown:
        job = jobq.pop_pending()
        if job is None:
            time.sleep(POLL_INTERVAL)
            continue

        print(f"agent: running job {job['job_id'][:8]} target={job['target']}", flush=True)
        try:
            result = run_pipeline(job)
            sarif = load_sarif(result.get("sarif"))
            ctx = run_agent(client, job, result, sarif)
            jobq.finish(
                job["job_id"],
                sarif_path=result.get("sarif"),
                severity=ctx.severity,
                action=ctx.chosen_action,
                stack_hash=ctx.stack_hash,
            )
            print(
                f"agent: done job {job['job_id'][:8]} "
                f"severity={ctx.severity} action={ctx.chosen_action}",
                flush=True,
            )
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            print(f"agent: job {job['job_id'][:8]} failed: {err}", flush=True)
            notify.send_error(job["target"], err)
            jobq.fail(job["job_id"], err)


if __name__ == "__main__":
    main()
