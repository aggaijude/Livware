"""
quarantine.py — Quarantine management system.

Moves detected malware to an isolated directory, tracks metadata,
and supports restore / permanent delete operations.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from typing import Optional

from config import QUARANTINE_DIR, QUARANTINE_META_PATH


class QuarantineManager:
    """Manages quarantined files with metadata tracking."""

    def __init__(self) -> None:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        self._meta = self._load_meta()

    # ── Metadata I/O ────────────────────────────────────────────────

    def _load_meta(self) -> dict:
        """Load quarantine metadata from disk."""
        if os.path.isfile(QUARANTINE_META_PATH):
            try:
                with open(QUARANTINE_META_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"items": []}

    def _save_meta(self) -> None:
        """Persist quarantine metadata to disk."""
        try:
            with open(QUARANTINE_META_PATH, "w", encoding="utf-8") as f:
                json.dump(self._meta, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[quarantine] Failed to save metadata: {e}")

    # ── File hash ───────────────────────────────────────────────────

    @staticmethod
    def _file_hash(file_path: str) -> str:
        """Compute SHA-256 hash of a file."""
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except Exception:
            return uuid.uuid4().hex

    # ── Public API ──────────────────────────────────────────────────

    def quarantine(
        self,
        file_path: str,
        reason: str = "Unknown",
        source: str = "Unknown",
        risk: float = 0.0,
    ) -> Optional[str]:
        """
        Move a file to quarantine.

        Args:
            file_path: Absolute path to the file to quarantine.
            reason: Detection reason / label.
            source: Detection engine (ML / ClamAV / YARA).
            risk: Risk score 0.0–1.0.

        Returns:
            Quarantine ID on success, None on failure.
        """
        if not os.path.isfile(file_path):
            print(f"[quarantine] File not found: {file_path}")
            return None

        try:
            q_id = uuid.uuid4().hex[:12]
            file_hash = self._file_hash(file_path)
            original_name = os.path.basename(file_path)
            safe_name = f"{q_id}_{file_hash[:16]}.quarantined"
            dest_path = os.path.join(QUARANTINE_DIR, safe_name)

            # Move the file
            shutil.move(file_path, dest_path)

            # Record metadata
            entry = {
                "id": q_id,
                "original_path": os.path.abspath(file_path),
                "original_name": original_name,
                "quarantine_name": safe_name,
                "quarantine_path": dest_path,
                "file_hash": file_hash,
                "reason": reason,
                "source": source,
                "risk": risk,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._meta["items"].append(entry)
            self._save_meta()

            print(f"[quarantine] Quarantined: {original_name} → {safe_name}")
            return q_id

        except Exception as e:
            print(f"[quarantine] Failed to quarantine {file_path}: {e}")
            return None

    def get_quarantined(self) -> list[dict]:
        """Return list of all quarantined file entries."""
        self._meta = self._load_meta()
        return list(self._meta.get("items", []))

    def restore(self, quarantine_id: str) -> bool:
        """
        Restore a quarantined file to its original location.

        Returns True on success.
        """
        entry = self._find_entry(quarantine_id)
        if not entry:
            print(f"[quarantine] ID not found: {quarantine_id}")
            return False

        src = entry["quarantine_path"]
        dst = entry["original_path"]

        if not os.path.isfile(src):
            print(f"[quarantine] Quarantined file missing: {src}")
            return False

        try:
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)
            self._remove_entry(quarantine_id)
            print(f"[quarantine] Restored: {entry['original_name']}")
            return True
        except Exception as e:
            print(f"[quarantine] Restore failed: {e}")
            return False

    def delete(self, quarantine_id: str) -> bool:
        """
        Permanently delete a quarantined file.

        Returns True on success.
        """
        entry = self._find_entry(quarantine_id)
        if not entry:
            return False

        src = entry["quarantine_path"]
        try:
            if os.path.isfile(src):
                os.remove(src)
            self._remove_entry(quarantine_id)
            print(f"[quarantine] Deleted permanently: {entry['original_name']}")
            return True
        except Exception as e:
            print(f"[quarantine] Delete failed: {e}")
            return False

    def get_count(self) -> int:
        """Return number of quarantined files."""
        return len(self._meta.get("items", []))

    # ── Internal helpers ────────────────────────────────────────────

    def _find_entry(self, q_id: str) -> Optional[dict]:
        for item in self._meta.get("items", []):
            if item["id"] == q_id:
                return item
        return None

    def _remove_entry(self, q_id: str) -> None:
        self._meta["items"] = [
            item for item in self._meta.get("items", []) if item["id"] != q_id
        ]
        self._save_meta()
