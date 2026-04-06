"""
updater.py — Auto-Updater for Engine Definitions.

Runs freshclam in a background thread to fetch ClamAV signatures,
and downloads the latest YARA rules from a public GitHub repository.
"""

import os
import subprocess
import shutil
import time
import tempfile
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

from config import CLAMAV_INSTALL_DIR, YARA_RULES_PATH, RULES_DIR

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[updater] requests library not installed — YARA auto-update disabled")


# ──────────────────────────── Constants ──────────────────────────────

# Public YARA rule sources (GitHub raw URLs)
YARA_RULE_SOURCES = [
    {
        "name": "EICAR Test Signature",
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/antidebug_antivm/antidebug_antivm.yar",
    },
    {
        "name": "Packers Detection",
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer.yar",
    },
]

# Fallback: a single consolidated rules index
YARA_INDEX_URL = "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar"


# ──────────────────────────── ClamAV Updater ────────────────────────

class ClamAVUpdaterThread(QThread):
    """Background thread that runs freshclam to update ClamAV databases."""

    finished_update = pyqtSignal(bool, str)  # success, message

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        freshclam_path = os.path.join(CLAMAV_INSTALL_DIR, "freshclam.exe")

        print(f"[updater] Starting ClamAV signature update using {freshclam_path}")

        if not os.path.exists(freshclam_path):
            path = shutil.which("freshclam")
            if path:
                freshclam_path = path

        if not freshclam_path or not os.path.exists(freshclam_path):
            self.finished_update.emit(False, "freshclam.exe not found on system.")
            return

        try:
            creationflags = 0
            if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                creationflags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                [freshclam_path],
                capture_output=True,
                text=True,
                timeout=180,
                creationflags=creationflags,
            )

            if result.returncode == 0:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                self.finished_update.emit(
                    True,
                    f"ClamAV definitions updated successfully at {timestamp}.",
                )
            else:
                self.finished_update.emit(
                    False,
                    f"ClamAV update failed: {result.stderr or result.stdout}",
                )

        except subprocess.TimeoutExpired:
            self.finished_update.emit(False, "ClamAV update timed out after 180s.")
        except Exception as e:
            self.finished_update.emit(False, f"ClamAV update error: {e}")


# ──────────────────────────── YARA Updater ──────────────────────────

class YARAUpdaterThread(QThread):
    """Background thread that downloads latest YARA rules from GitHub."""

    finished_update = pyqtSignal(bool, str)  # success, message

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        if not REQUESTS_AVAILABLE:
            self.finished_update.emit(
                False, "requests library not installed — cannot update YARA rules."
            )
            return

        print("[updater] Starting YARA rules update...")

        try:
            # Download the main EICAR / malware rule as an append
            new_rules: list[str] = []

            for source in YARA_RULE_SOURCES:
                try:
                    resp = requests.get(source["url"], timeout=30)
                    if resp.status_code == 200:
                        new_rules.append(
                            f"// ── Auto-downloaded: {source['name']} ──\n"
                            f"{resp.text}\n"
                        )
                        print(f"[updater] Downloaded YARA rules: {source['name']}")
                    else:
                        print(
                            f"[updater] Failed to fetch {source['name']}: "
                            f"HTTP {resp.status_code}"
                        )
                except requests.RequestException as e:
                    print(f"[updater] Network error fetching {source['name']}: {e}")
                    continue

            if not new_rules:
                self.finished_update.emit(
                    False, "Could not download any YARA rules — network may be down."
                )
                return

            # ── Safe atomic write ───────────────────────────────────
            # 1. Read existing local rules (user-written ones we must preserve)
            existing_content = ""
            marker = "// ═══ AUTO-UPDATED RULES BELOW — DO NOT EDIT ═══"

            if os.path.isfile(YARA_RULES_PATH):
                with open(YARA_RULES_PATH, "r", encoding="utf-8") as f:
                    existing_content = f.read()

            # Split at marker — keep everything above it (user rules)
            if marker in existing_content:
                user_section = existing_content.split(marker)[0].rstrip()
            else:
                user_section = existing_content.rstrip()

            # 2. Combine user rules + auto-updated rules
            combined = (
                f"{user_section}\n\n"
                f"{marker}\n"
                f"// Last updated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                + "\n".join(new_rules)
            )

            # 3. Write to temp file first, then replace (atomic-ish on Windows)
            os.makedirs(RULES_DIR, exist_ok=True)
            tmp_path = os.path.join(RULES_DIR, "rules_update.tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(combined)

            # 4. Replace the live rules file
            if os.path.isfile(YARA_RULES_PATH):
                backup_path = YARA_RULES_PATH + ".bak"
                shutil.copy2(YARA_RULES_PATH, backup_path)

            shutil.move(tmp_path, YARA_RULES_PATH)

            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            self.finished_update.emit(
                True,
                f"YARA rules updated successfully at {timestamp}.",
            )

        except Exception as e:
            self.finished_update.emit(False, f"YARA update error: {e}")


# ──────────────────────────── Combined Updater ──────────────────────

class FullUpdaterThread(QThread):
    """
    Runs ClamAV + YARA updates sequentially in one background thread.
    Emits per-engine results and an overall completion signal.
    """

    clamav_done = pyqtSignal(bool, str)  # success, message
    yara_done = pyqtSignal(bool, str)    # success, message
    all_done = pyqtSignal(bool, str)     # overall success, summary

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        results = []

        # ── ClamAV ──────────────────────────────────────────────────
        clamav_ok, clamav_msg = self._update_clamav()
        self.clamav_done.emit(clamav_ok, clamav_msg)
        results.append(("ClamAV", clamav_ok, clamav_msg))

        # ── YARA ────────────────────────────────────────────────────
        yara_ok, yara_msg = self._update_yara()
        self.yara_done.emit(yara_ok, yara_msg)
        results.append(("YARA", yara_ok, yara_msg))

        # ── Summary ─────────────────────────────────────────────────
        all_ok = all(ok for _, ok, _ in results)
        summary_parts = [f"{name}: {'✓' if ok else '✗'}" for name, ok, _ in results]
        summary = " | ".join(summary_parts)
        self.all_done.emit(all_ok, summary)

    # ── Internal engine runners ─────────────────────────────────────

    def _update_clamav(self) -> tuple[bool, str]:
        freshclam_path = os.path.join(CLAMAV_INSTALL_DIR, "freshclam.exe")

        if not os.path.exists(freshclam_path):
            path = shutil.which("freshclam")
            if path:
                freshclam_path = path

        if not freshclam_path or not os.path.exists(freshclam_path):
            return False, "freshclam.exe not found."

        try:
            creationflags = 0
            if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                creationflags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                [freshclam_path],
                capture_output=True,
                text=True,
                timeout=180,
                creationflags=creationflags,
            )
            if result.returncode == 0:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                return True, f"Definitions updated at {ts}."
            else:
                return False, f"Failed: {result.stderr or result.stdout}"
        except subprocess.TimeoutExpired:
            return False, "Timed out after 180s."
        except Exception as e:
            return False, f"Error: {e}"

    def _update_yara(self) -> tuple[bool, str]:
        if not REQUESTS_AVAILABLE:
            return False, "requests library not available."

        try:
            new_rules: list[str] = []
            for source in YARA_RULE_SOURCES:
                try:
                    resp = requests.get(source["url"], timeout=30)
                    if resp.status_code == 200:
                        new_rules.append(
                            f"// ── Auto-downloaded: {source['name']} ──\n"
                            f"{resp.text}\n"
                        )
                except requests.RequestException:
                    continue

            if not new_rules:
                return False, "Could not download any rules."

            # Preserve user rules
            existing_content = ""
            marker = "// ═══ AUTO-UPDATED RULES BELOW — DO NOT EDIT ═══"
            if os.path.isfile(YARA_RULES_PATH):
                with open(YARA_RULES_PATH, "r", encoding="utf-8") as f:
                    existing_content = f.read()

            if marker in existing_content:
                user_section = existing_content.split(marker)[0].rstrip()
            else:
                user_section = existing_content.rstrip()

            combined = (
                f"{user_section}\n\n"
                f"{marker}\n"
                f"// Last updated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                + "\n".join(new_rules)
            )

            os.makedirs(RULES_DIR, exist_ok=True)
            tmp_path = os.path.join(RULES_DIR, "rules_update.tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(combined)

            if os.path.isfile(YARA_RULES_PATH):
                shutil.copy2(YARA_RULES_PATH, YARA_RULES_PATH + ".bak")

            shutil.move(tmp_path, YARA_RULES_PATH)

            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            return True, f"Rules updated at {ts}."

        except Exception as e:
            return False, f"Error: {e}"
