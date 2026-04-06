"""
realtime_watcher.py — Real-time file system protection using watchdog.

Monitors critical user directories for newly created or modified executables
and triggers scans in the background. Incorporates event debouncing with
automatic cache pruning to prevent memory leaks.
"""

import os
import time
import threading
from typing import List, Set
from PyQt6.QtCore import QObject, pyqtSignal

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config import SCAN_EXTENSIONS


# ────────────────────────────── Constants ────────────────────────────

_MAX_CACHE_SIZE = 5000         # Prune when cache exceeds this
_STALE_THRESHOLD_SECS = 60.0   # Entries older than this are pruned
_DEBOUNCE_SECS = 3.0           # Min interval between scans for same file


class DebouncingEventHandler(FileSystemEventHandler):
    """Watches for file creations/modifications and debounces events."""

    def __init__(
        self,
        callback: callable,
        extensions: Set[str],
        debounce_seconds: float = _DEBOUNCE_SECS,
    ):
        super().__init__()
        self._callback = callback
        self._extensions = set(ext.lower() for ext in extensions)
        self._debounce_seconds = debounce_seconds
        self._recent_events: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune_stale_entries(self, now: float) -> None:
        """Remove entries older than _STALE_THRESHOLD_SECS (called under lock)."""
        stale_keys = [
            k for k, v in self._recent_events.items()
            if now - v > _STALE_THRESHOLD_SECS
        ]
        for k in stale_keys:
            del self._recent_events[k]

    def _process(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self._extensions:
            return

        now = time.time()

        with self._lock:
            # Prune if cache has grown too large
            if len(self._recent_events) > _MAX_CACHE_SIZE:
                self._prune_stale_entries(now)

            last_time = self._recent_events.get(file_path, 0)

            # Debounce: skip if same file was scanned recently
            if now - last_time <= self._debounce_seconds:
                return

            self._recent_events[file_path] = now

        # Invoke callback outside the lock to avoid blocking watchdog threads
        self._callback(file_path)

    def on_created(self, event):
        self._process(event)

    def on_modified(self, event):
        self._process(event)


class RealtimeWatcher(QObject):
    """
    QObject wrapper for watchdog.Observer.
    Emits a signal whenever a scannable file is created/modified.
    """
    file_detected = pyqtSignal(str)

    def __init__(self, excluded_paths: List[str] = None):
        super().__init__()
        self._observer = Observer()
        self._excluded_paths = [os.path.abspath(p) for p in (excluded_paths or [])]

        self._handler = DebouncingEventHandler(
            self._on_file_changed,
            SCAN_EXTENSIONS,
            debounce_seconds=_DEBOUNCE_SECS,
        )
        self._is_running = False

        # Common directories to monitor
        user_home = os.path.expanduser("~")
        self._watch_dirs = [
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Desktop"),
            os.environ.get("TEMP"),
        ]

        # Filter None and non-existent paths
        self._watch_dirs = [d for d in self._watch_dirs if d]

    def _on_file_changed(self, file_path: str):
        # Check exclusions
        abs_path = os.path.abspath(file_path)
        for excluded in self._excluded_paths:
            if abs_path.startswith(excluded):
                return

        print(f"[watcher] Detected file event: {file_path}")
        self.file_detected.emit(file_path)

    def start(self):
        """Start the watchdog observer."""
        if self._is_running:
            return

        for directory in self._watch_dirs:
            if os.path.exists(directory):
                try:
                    self._observer.schedule(self._handler, directory, recursive=True)
                    print(f"[watcher] Monitoring: {directory}")
                except Exception as e:
                    print(f"[watcher] Failed to monitor {directory}: {e}")

        try:
            self._observer.start()
            self._is_running = True
            print("[watcher] Real-time file system protection enabled.")
        except Exception as e:
            print(f"[watcher] Failed to start observer: {e}")

    def stop(self):
        """Stop the watchdog observer."""
        if not self._is_running:
            return

        try:
            self._observer.stop()
            self._observer.join(timeout=2.0)
            self._is_running = False

            # Recreate observer object for next start
            self._observer = Observer()
            print("[watcher] Real-time protection disabled.")
        except Exception as e:
            print(f"[watcher] Error stopping observer: {e}")
