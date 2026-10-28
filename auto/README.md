# P4 Mini-CRS — Auto Pipeline

Automation layer on top of `crs.py`. One SQLite queue, three producers (phase 2:
cron scheduler + inotify watcher + manual enqueue), one worker daemon
(`agent.py`) that drains the queue, runs the pipeline, and uses the Claude
Agent SDK (Haiku 4.5) to classify SARIF severity and pick a follow-up action.

## Layout

```
auto/
├── targets.yaml       # watchlist + github repo list (edit this)
├── jobq.py            # SQLite queue (import or `python jobq.py list`)
├── jobq.db            # auto-created on first run
├── runner.sh          # crs.py wrapper, emits JSON summary
├── notify.py          # Telegram alert dispatch
├── agent.py           # worker daemon (Claude Agent SDK, Haiku 4.5)
├── scheduler.py       # cron producer (watchlist + github poll)
├── watcher.py         # inotify producer (watchlist dirs)
├── dashboard.py       # Flask dashboard (localhost:5557)
├── templates/         # Jinja templates for dashboard
├── state.json         # scheduler state (github last_sha); auto-created
├── systemd/
│   ├── p4-agent.service
│   ├── p4-scheduler.service
│   ├── p4-scheduler.timer
│   ├── p4-watcher.service
│   └── p4-dashboard.service
├── .env.example       # copy to .env
└── logs/              # agent + per-job runner logs
```

## Setup

```bash
cd ~/projects/p4-mini-crs
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt anthropic python-dotenv pyyaml watchdog flask

cp auto/.env.example auto/.env
$EDITOR auto/.env   # fill ANTHROPIC_API_KEY + TELEGRAM_*

python3 auto/jobq.py   # initializes jobq.db
```

## Manual enqueue (smoke test)

```bash
python3 -c "
import sys; sys.path.insert(0, 'auto')
import jobq; jobq.init()
print(jobq.enqueue('targets/vulnerable_parser', 'manual', 60))
"
python3 auto/agent.py   # Ctrl-C after one job completes
python3 auto/jobq.py list
```

## systemd (user service)

```bash
mkdir -p ~/.config/systemd/user
for u in p4-agent.service p4-scheduler.service p4-scheduler.timer p4-watcher.service p4-dashboard.service; do
  ln -sf ~/projects/p4-mini-crs/auto/systemd/$u ~/.config/systemd/user/
done
systemctl --user daemon-reload
systemctl --user enable --now p4-agent.service p4-watcher.service p4-scheduler.timer p4-dashboard.service
systemctl --user status p4-agent.service p4-watcher.service p4-scheduler.timer
tail -f ~/projects/p4-mini-crs/auto/logs/*.log
```

## Agent decision rules

See the `SYSTEM_PROMPT` constant in `agent.py`. The agent is injected with PRIOR
findings (stack_hash + severity) for the target to dedup across runs.

| Finding          | Action                                                                      |
|------------------|-----------------------------------------------------------------------------|
| CRITICAL (gh)    | `file_github_issue` on target repo + Telegram alert (gh-sourced targets)    |
| CRITICAL / HIGH  | Telegram alert w/ CWE + location (watchlist targets)                        |
| MEDIUM, new hash | Telegram alert                                                              |
| MEDIUM, seen     | Mark ignore (`dedup: already reported`)                                     |
| LOW only         | Mark ignore                                                                 |
| None, <300s fuzz | Re-queue with 2× fuzz time (cap `P4_MAX_FUZZ_TIME` = 600s)                  |
| None, ≥300s      | Mark ignore                                                                 |

### GitHub issue filing requirements

For `file_github_issue` to work, `gh` must be authed (`gh auth login`) with
repo-write scope on the target repos. Labels `security`, `p4-crs`, and
`severity:<level>` are created on first use (gh does this automatically).

## Phase status

- [x] Phase 1: core worker + Telegram + systemd daemon
- [x] Phase 2: cron scheduler (daily 03:00) + inotify watcher + systemd timer/service units
- [x] Phase 3: expanded SARIF rubric + prior-findings injection + stack-hash dedup + `file_github_issue` tool for gh-sourced CRITICAL findings
- [x] Phase 4: Flask dashboard (localhost:5557) — queue stats, severity histogram, per-target history, manual trigger form

## Dashboard

Starts on `http://127.0.0.1:5557` by default. Override with `P4_DASHBOARD_HOST` /
`P4_DASHBOARD_PORT` env vars (set in `auto/.env` or the systemd unit). Front with
a reverse proxy or Tailscale ACL — no auth built in.

Routes:

| Route                 | Shows                                              |
|-----------------------|----------------------------------------------------|
| `/`                   | queue counts, severity histogram, targets, recent jobs |
| `/target/<path>`      | prior findings + full job history for one target  |
| `/findings`           | all CRITICAL/HIGH/MEDIUM findings, newest first    |
| `/trigger`            | manual enqueue form (dedup against pending/running)|
