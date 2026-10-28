"""Inotify producer for P4 Mini-CRS auto-pipeline.

Watches watchlist directories from targets.yaml. On create/modify of a C/H
source file (or new subdir), enqueues the containing target. A debounce window
collapses burst edits (e.g. editor saves) into one job.

Dedup against pending/running jobs is handled by jobq.enqueue().
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

sys.path.insert(0, str(Path(__file__).parent))
import jobq

AUTO_DIR = Path(__file__).parent
TARGETS_FILE = AUTO_DIR / "targets.yaml"

C_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}
DEBOUNCE_SECONDS = 5.0


def load_watchlist() -> list[dict]:
    with open(TARGETS_FILE) as f:
        data = yaml.safe_load(f) or {}
    return [e for e in (data.get("watchlist") or []) if e.get("enabled", True)]


class TargetHandler(FileSystemEventHandler):
    """Debounces events per-target and enqueues after the quiet window."""

    def __init__(self, target_path: str, fuzz_time: int):
        self.target_path = os.path.expanduser(target_path)
        self.fuzz_time = fuzz_time
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def _should_handle(self, event_path: str) -> bool:
        if Path(event_path).suffix.lower() in C_SUFFIXES:
            return True
        # Also fire on new subdir within target
        return Path(event_path).is_dir()

    def _enqueue(self) -> None:
        jid = jobq.enqueue(
            self.target_path,
            source="watcher_inotify",
            fuzz_time=self.fuzz_time,
        )
        print(f"watcher: enqueued {self.target_path} → {jid[:8]}", flush=True)

    def _trigger(self, event_path: str) -> None:
        if not self._should_handle(event_path):
            return
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(DEBOUNCE_SECONDS, self._enqueue)
            self._timer.daemon = True
            self._timer.start()

    def on_created(self, event):
        self._trigger(event.src_path)

    def on_modified(self, event):
        self._trigger(event.src_path)

    def on_moved(self, event):
        self._trigger(event.dest_path)


_shutdown = threading.Event()


def _handle_signal(signum, frame):
    print(f"watcher: caught signal {signum}, shutting down", flush=True)
    _shutdown.set()


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    jobq.init()
    entries = load_watchlist()
    if not entries:
        print("watcher: no enabled watchlist entries, exiting", flush=True)
        return

    observer = Observer()
    for entry in entries:
        path = os.path.expanduser(entry["path"])
        if not Path(path).exists():
            print(f"watcher: skip missing {path}", flush=True)
            continue
        handler = TargetHandler(path, entry.get("fuzz_time", 60))
        observer.schedule(handler, path, recursive=True)
        print(f"watcher: watching {path}", flush=True)

    observer.start()
    try:
        while not _shutdown.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        observer.join(timeout=5)
    print("watcher: stopped", flush=True)


if __name__ == "__main__":
    main()
