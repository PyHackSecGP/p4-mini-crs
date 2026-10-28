"""Cron producer for P4 Mini-CRS auto-pipeline.

Reads targets.yaml. For each enabled entry:
  - watchlist: enqueue the local path
  - github:    `gh api repos/<repo>/commits/<branch>` → compare SHA against
               auto/state.json; clone to /tmp/p4-auto/<slug>/ and enqueue on change

Dedup: jobq.enqueue() skips targets with an existing pending/running job.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import jobq

AUTO_DIR = Path(__file__).parent
TARGETS_FILE = AUTO_DIR / "targets.yaml"
STATE_FILE = AUTO_DIR / "state.json"
GH_CLONE_DIR = Path("/tmp/p4-auto")


def load_targets() -> dict[str, Any]:
    with open(TARGETS_FILE) as f:
        return yaml.safe_load(f) or {}


def load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(state: dict[str, Any]) -> None:
    tmp = STATE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    tmp.replace(STATE_FILE)


def enqueue_watchlist(entries: list[dict], state: dict) -> int:
    n = 0
    for entry in entries:
        if not entry.get("enabled", True):
            continue
        path = os.path.expanduser(entry["path"])
        if not Path(path).exists():
            print(f"scheduler: skip missing {path}", flush=True)
            continue
        jid = jobq.enqueue(path, source="scheduler_watchlist",
                           fuzz_time=entry.get("fuzz_time", 60))
        print(f"scheduler: watchlist {path} → {jid[:8]}", flush=True)
        n += 1
    return n


def gh_latest_sha(repo: str, branch: str) -> str | None:
    """`gh api repos/<repo>/commits/<branch>` → .sha. Requires `gh auth login`."""
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/commits/{branch}", "--jq", ".sha"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        return out.stdout.strip() or None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"scheduler: gh api failed for {repo}@{branch}: {e}", flush=True)
        return None


def clone_repo(repo: str, branch: str, dest: Path) -> bool:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["gh", "repo", "clone", repo, str(dest), "--",
             "--depth=1", "--branch", branch],
            capture_output=True, text=True, timeout=120, check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"scheduler: clone failed for {repo}: {e}", flush=True)
        return False


def enqueue_github(entries: list[dict], state: dict) -> int:
    n = 0
    gh_state = state.setdefault("github", {})
    for entry in entries:
        if not entry.get("enabled", True):
            continue
        repo = entry["repo"]
        branch = entry.get("branch", "main")
        latest = gh_latest_sha(repo, branch)
        if not latest:
            continue
        prev = gh_state.get(repo, {}).get("sha")
        if prev == latest:
            print(f"scheduler: {repo} unchanged ({latest[:8]})", flush=True)
            continue
        slug = repo.replace("/", "__")
        dest = GH_CLONE_DIR / slug
        if not clone_repo(repo, branch, dest):
            continue
        jid = jobq.enqueue(str(dest), source=f"scheduler_github:{repo}",
                           fuzz_time=entry.get("fuzz_time", 300))
        print(f"scheduler: github {repo} {latest[:8]} → {jid[:8]}", flush=True)
        gh_state[repo] = {"sha": latest, "branch": branch}
        n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="Print what would be enqueued without touching the queue.")
    args = ap.parse_args()

    if args.dry_run:
        # Monkey-patch enqueue to log only
        orig = jobq.enqueue
        jobq.enqueue = lambda target, source, fuzz_time=60: (
            print(f"[dry-run] would enqueue {target} ({source}, {fuzz_time}s)"),
            "dry-run-id"
        )[1]

    jobq.init()
    targets = load_targets()
    state = load_state()

    n_watch = enqueue_watchlist(targets.get("watchlist", []) or [], state)
    n_gh = enqueue_github(targets.get("github_repos", []) or [], state)

    if not args.dry_run:
        save_state(state)
    print(f"scheduler: done. watchlist={n_watch} github={n_gh}", flush=True)


if __name__ == "__main__":
    main()
