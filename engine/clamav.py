"""
clamav.py — ClamAV signature-based scanning integration.

Uses the local ClamAV command-line scanner (clamscan.exe) via subprocess.
Gracefully disables itself if ClamAV is not installed.
"""

from __future__ import annotations

import os
import subprocess
import re
from typing import Optional

from config import CLAMAV_PATH, CLAMAV_TIMEOUT, CLAMAV_DB_PATH


class ClamAVScanner:
    """Wrapper around the ClamAV clamscan CLI."""

    def __init__(self) -> None:
        self._path = CLAMAV_PATH
        if self._path:
            print(f"[clamav] Found ClamAV at: {self._path}")
        else:
            print("[clamav] ClamAV not found — signature scanning disabled")

    def is_available(self) -> bool:
        """Return True if clamscan is accessible."""
        return self._path is not None

    def scan(self, file_path: str) -> dict:
        """
        Scan a single file with ClamAV.

        Returns:
            {
                "detected": bool,
                "threat_name": str | None,
                "source": "ClamAV",
                "raw_output": str
            }
        """
        if not self.is_available():
            return {
                "detected": False,
                "threat_name": None,
                "source": "ClamAV",
                "raw_output": "ClamAV not available",
            }

        try:
            cmd = [self._path, "--no-summary", "--infected"]
            # Point to our local virus database if available
            if CLAMAV_DB_PATH and os.path.isdir(CLAMAV_DB_PATH):
                cmd.extend(["--database", CLAMAV_DB_PATH])
            cmd.append(file_path)

            # Prevent console window from popping up on Windows
            creationflags = 0
            if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                creationflags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=CLAMAV_TIMEOUT,
                creationflags=creationflags,
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            # Return code: 0 = clean, 1 = virus found, 2 = error
            if result.returncode == 1:
                # Parse threat name from output like:
                # /path/to/file: Win.Malware.Agent-12345 FOUND
                threat_name = self._parse_threat(stdout)
                return {
                    "detected": True,
                    "threat_name": threat_name,
                    "source": "ClamAV",
                    "raw_output": stdout,
                }
            elif result.returncode == 0:
                return {
                    "detected": False,
                    "threat_name": None,
                    "source": "ClamAV",
                    "raw_output": stdout or "OK",
                }
            else:
                # Error
                return {
                    "detected": False,
                    "threat_name": None,
                    "source": "ClamAV",
                    "raw_output": f"Error: {stderr or stdout}",
                }

        except subprocess.TimeoutExpired:
            return {
                "detected": False,
                "threat_name": None,
                "source": "ClamAV",
                "raw_output": f"Scan timed out after {CLAMAV_TIMEOUT}s",
            }
        except FileNotFoundError:
            self._path = None  # Disable for future calls
            return {
                "detected": False,
                "threat_name": None,
                "source": "ClamAV",
                "raw_output": "clamscan executable not found",
            }
        except Exception as e:
            return {
                "detected": False,
                "threat_name": None,
                "source": "ClamAV",
                "raw_output": f"Error: {e}",
            }

    @staticmethod
    def _parse_threat(output: str) -> Optional[str]:
        """Extract the threat/signature name from ClamAV output."""
        # Typical: /path/file: ThreatName FOUND
        match = re.search(r":\s*(.+?)\s+FOUND", output)
        if match:
            return match.group(1).strip()
        return "Unknown Threat"
