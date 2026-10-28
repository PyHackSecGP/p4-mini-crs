"""Flask dashboard for P4 Mini-CRS auto-pipeline.

Read-only view over the SQLite jobq, plus a manual enqueue form.
No auth — bind to localhost or front with a reverse proxy / Tailscale.

Env:
    P4_DASHBOARD_HOST  bind host (default 127.0.0.1)
    P4_DASHBOARD_PORT  bind port (default 5557)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, url_for

sys.path.insert(0, str(Path(__file__).parent))
import jobq

HOST = os.getenv("P4_DASHBOARD_HOST", "127.0.0.1")
PORT = int(os.getenv("P4_DASHBOARD_PORT", "5557"))

app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))


def _sev_badge_class(sev: str | None) -> str:
    return {
        "CRITICAL": "sev-crit",
        "HIGH": "sev-high",
        "MEDIUM": "sev-med",
        "LOW": "sev-low",
        "NONE": "sev-none",
    }.get((sev or "").upper(), "sev-unknown")


app.jinja_env.globals["sev_class"] = _sev_badge_class


@app.route("/")
def index():
    return render_template(
        "index.html",
        status_counts=jobq.counts_by_status(),
        severity_counts=jobq.counts_by_severity(),
        targets=jobq.distinct_targets(),
        recent=jobq.list_jobs(limit=25),
    )


@app.route("/target/<path:target>")
def target(target: str):
    if not target.startswith("/"):
        target = "/" + target
    jobs = jobq.find_by_target(target)
    if not jobs:
        abort(404)
    return render_template(
        "target.html",
        target=target,
        jobs=jobs,
        prior=jobq.prior_findings(target),
    )


@app.route("/findings")
def findings():
    return render_template(
        "findings.html",
        findings=jobq.critical_findings(limit=200),
    )


@app.route("/trigger", methods=["GET", "POST"])
def trigger():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        fuzz_time = int(request.form.get("fuzz_time", "60"))
        if not target:
            return redirect(url_for("trigger"))
        jid = jobq.enqueue(target, source="dashboard_manual", fuzz_time=fuzz_time)
        return redirect(url_for("target", target=target.lstrip("/")))
    return render_template("trigger.html")


def main() -> None:
    jobq.init()
    print(f"dashboard: serving on http://{HOST}:{PORT}", flush=True)
    app.run(host=HOST, port=PORT, debug=False)


if __name__ == "__main__":
    main()
