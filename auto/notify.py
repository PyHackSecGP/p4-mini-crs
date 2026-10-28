"""Telegram alert dispatch for P4 Mini-CRS auto-pipeline.

Reads TELEGRAM_TOKEN + TELEGRAM_CHAT_ID from env (or .env file).
Call send_finding(target, severity, finding_dict) from agent.py.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

TOKEN = os.getenv("TELEGRAM_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


def _send(html: str) -> bool:
    if not TOKEN or not CHAT_ID:
        print("notify: TELEGRAM_TOKEN or TELEGRAM_CHAT_ID missing — skipping", flush=True)
        return False
    resp = requests.post(
        f"https://api.telegram.org/bot{TOKEN}/sendMessage",
        json={
            "chat_id": CHAT_ID,
            "text": html,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        },
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"notify: telegram failed {resp.status_code} {resp.text}", flush=True)
        return False
    return True


def send_finding(target: str, severity: str, finding: dict[str, Any]) -> bool:
    """Alert for a single high-severity CRS finding."""
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
        severity.upper(), "⚪"
    )
    cwe = finding.get("cwe", "?")
    func = finding.get("function", "?")
    file_ = finding.get("file", "?")
    line = finding.get("line", "?")
    summary = finding.get("summary", "")[:400]
    html = (
        f"{emoji} <b>P4 CRS — {severity}</b>\n"
        f"<b>Target:</b> <code>{target}</code>\n"
        f"<b>CWE:</b> {cwe}\n"
        f"<b>Location:</b> <code>{file_}:{line}</code> in <code>{func}</code>\n"
        f"\n{summary}"
    )
    return _send(html)


def send_run_summary(target: str, severity: str, action: str, n_findings: int) -> bool:
    html = (
        f"✅ <b>P4 CRS run complete</b>\n"
        f"<b>Target:</b> <code>{target}</code>\n"
        f"<b>Findings:</b> {n_findings} (top: {severity})\n"
        f"<b>Agent action:</b> {action}"
    )
    return _send(html)


def send_error(target: str, error: str) -> bool:
    html = (
        f"⚠️ <b>P4 CRS failed</b>\n"
        f"<b>Target:</b> <code>{target}</code>\n"
        f"<b>Error:</b> <code>{error[:300]}</code>"
    )
    return _send(html)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        ok = _send("🧪 P4 Mini-CRS notify.py test")
        print("sent" if ok else "failed")
