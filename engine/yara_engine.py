"""
yara_engine.py — YARA rule-based malware detection engine.

Compiles and matches YARA rules against target files.
Gracefully disables itself if yara-python is not installed
or rule files are missing.
"""

from __future__ import annotations

import os
from typing import Optional

from config import YARA_RULES_PATH

# yara-python may not be installed on all systems
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[yara_engine] yara-python not installed — rule-based scanning disabled")


class YARAEngine:
    """Wrapper around yara-python for rule-based file scanning."""

    def __init__(self) -> None:
        self._rules = None
        self._available = False

        if not YARA_AVAILABLE:
            return

        if not os.path.isfile(YARA_RULES_PATH):
            print(f"[yara_engine] Rule file not found: {YARA_RULES_PATH}")
            return

        try:
            self._rules = yara.compile(filepath=YARA_RULES_PATH)
            self._available = True
            print(f"[yara_engine] Rules compiled from {YARA_RULES_PATH}")
        except yara.SyntaxError as e:
            print(f"[yara_engine] Syntax error in rules: {e}")
        except yara.Error as e:
            print(f"[yara_engine] Failed to compile rules: {e}")
        except Exception as e:
            print(f"[yara_engine] Unexpected error: {e}")

    def is_available(self) -> bool:
        """Return True if YARA rules are compiled and ready."""
        return self._available

    def scan(self, file_path: str) -> dict:
        """
        Scan a single file against compiled YARA rules.

        Returns:
            {
                "matched": bool,
                "rules": list[str],      # Names of matched rules
                "details": list[dict],    # Full match info
                "source": "YARA"
            }
        """
        if not self._available or self._rules is None:
            return {
                "matched": False,
                "rules": [],
                "details": [],
                "source": "YARA",
            }

        try:
            matches = self._rules.match(filepath=file_path, timeout=30)

            if matches:
                rule_names = [m.rule for m in matches]
                details = []
                for m in matches:
                    detail = {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "tags": list(m.tags) if m.tags else [],
                        "meta": dict(m.meta) if m.meta else {},
                    }
                    details.append(detail)

                return {
                    "matched": True,
                    "rules": rule_names,
                    "details": details,
                    "source": "YARA",
                }
            else:
                return {
                    "matched": False,
                    "rules": [],
                    "details": [],
                    "source": "YARA",
                }

        except Exception as e:
            print(f"[yara_engine] Scan error on {file_path}: {e}")
            return {
                "matched": False,
                "rules": [],
                "details": [],
                "source": "YARA",
            }

    def reload_rules(self) -> bool:
        """Re-compile rules from disk (e.g. after user edits the .yar file)."""
        if not YARA_AVAILABLE:
            return False
        if not os.path.isfile(YARA_RULES_PATH):
            return False
        try:
            self._rules = yara.compile(filepath=YARA_RULES_PATH)
            self._available = True
            return True
        except Exception as e:
            print(f"[yara_engine] Reload failed: {e}")
            self._available = False
            return False
