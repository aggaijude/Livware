"""
system_scanner.py — Full system scan engine.

Supports two modes:
  - Quick Scan: common user directories (Desktop, Downloads, AppData, etc.)
  - Full Scan: all available drives recursively

Uses multithreading for performance and emits Qt signals for real-time UI updates.
"""

from __future__ import annotations

import os
import string
import time
from dataclasses import dataclass
from typing import Optional

from PyQt6.QtCore import QObject, pyqtSignal

from config import SCAN_EXTENSIONS


# ────────────────────────────── Constants ───────────────────────────

SKIP_DIRS = {
    "windows", "$recycle.bin", "system volume information",
    "$windows.~bt", "$windows.~ws", "recovery",
    "perflogs", "programdata", "config.msi",
    "__pycache__", ".git", "node_modules",
}

QUICK_SCAN_DIRS = [
    os.path.expanduser("~\\Desktop"),
    os.path.expanduser("~\\Downloads"),
    os.path.expanduser("~\\Documents"),
    os.path.expanduser("~\\AppData\\Local\\Temp"),
    os.path.expanduser("~\\AppData\\Roaming"),
    "C:\\ProgramData",
]


# ────────────────────────────── Helpers ─────────────────────────────

def get_all_drives() -> list[str]:
    """Detect all available drive letters on Windows."""
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            drives.append(drive)
    return drives


def collect_scannable_files(
    roots: list[str],
    extensions: set[str] | None = None,
    skip_dirs: set[str] | None = None,
    progress_callback=None,
) -> list[str]:
    """
    Recursively collect scannable files from multiple root paths.

    Args:
        roots: List of root directories to scan.
        extensions: Set of file extensions to include (e.g. {'.exe', '.dll'}).
        skip_dirs: Set of directory names to skip (case-insensitive).
        progress_callback: Optional callable(files_found: int) for updates.
    """
    if extensions is None:
        extensions = SCAN_EXTENSIONS
    if skip_dirs is None:
        skip_dirs = SKIP_DIRS

    files: list[str] = []
    seen = set()

    for root_path in roots:
        if not os.path.isdir(root_path):
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
                # Skip excluded directories
                dirnames[:] = [
                    d for d in dirnames
                    if d.lower() not in skip_dirs
                ]

                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in extensions:
                        full = os.path.join(dirpath, fname)
                        real = os.path.normcase(os.path.abspath(full))
                        if real not in seen:
                            seen.add(real)
                            files.append(full)

                            if progress_callback and len(files) % 50 == 0:
                                progress_callback(len(files))
        except PermissionError:
            continue
        except Exception:
            continue

    return files


# ────────────────────────────── Workers ─────────────────────────────

class SystemScanWorker(QObject):
    """
    Background worker for full / quick system scans.

    Emits signals for:
      - collection progress (file discovery phase)
      - scan progress (per-file scanning phase)
      - individual results
      - completion
    """

    collecting = pyqtSignal(int)                # files found so far
    progress = pyqtSignal(int, int, object)     # current, total, ScanResult
    finished = pyqtSignal(list)                 # list[ScanResult]
    error = pyqtSignal(str)

    def __init__(self, scanner, mode: str = "quick") -> None:
        """
        Args:
            scanner: engine.scanner.Scanner instance
            mode: 'quick' or 'full'
        """
        super().__init__()
        self._scanner = scanner
        self._mode = mode
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            # Phase 1: Collect files
            if self._mode == "full":
                drives = get_all_drives()
                roots = drives
            else:
                roots = [d for d in QUICK_SCAN_DIRS if os.path.isdir(d)]

            files = collect_scannable_files(
                roots,
                progress_callback=lambda n: self.collecting.emit(n),
            )

            if not files:
                self.finished.emit([])
                return

            self.collecting.emit(len(files))

            # Phase 2: Scan each file
            total = len(files)
            results = []

            for i, fp in enumerate(files):
                if self._cancelled:
                    break
                try:
                    result = self._scanner.scan_file(fp)
                    results.append(result)
                    self.progress.emit(i + 1, total, result)
                except Exception:
                    continue

            self.finished.emit(results)

        except Exception as e:
            self.error.emit(str(e))
