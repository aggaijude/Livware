"""
scanner.py — Unified scan orchestrator.

Combines ML, ClamAV, and YARA engines with priority-based decision logic.
Emits Qt signals for real-time UI updates and handles threaded scanning.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from config import SCAN_EXTENSIONS, SCAN_LOG_PATH
from engine.feature_extractor import extract_features
from engine.ml_model import MLModel
from engine.clamav import ClamAVScanner
from engine.yara_engine import YARAEngine
from engine.quarantine import QuarantineManager
from engine.sandbox import SandboxAnalyzer, SandboxReport


# ────────────────────────────── Data Classes ────────────────────────

@dataclass
class ScanResult:
    """Result of scanning a single file."""
    file_path: str
    file_name: str
    status: str           # SAFE | WARNING | MALWARE | SUSPICIOUS | ERROR
    risk: float           # 0.0 – 1.0
    source: str           # ML | ClamAV | YARA | Combined
    details: str          # Human-readable description
    timestamp: str = ""
    clamav_result: dict = field(default_factory=dict)
    yara_result: dict = field(default_factory=dict)
    ml_result: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")


# ────────────────────────────── Scan Logger ─────────────────────────

class ScanLogger:
    """Appends scan results to the log file."""

    @staticmethod
    def log(result: ScanResult) -> None:
        try:
            os.makedirs(os.path.dirname(SCAN_LOG_PATH), exist_ok=True)
            with open(SCAN_LOG_PATH, "a", encoding="utf-8") as f:
                line = (
                    f"[{result.timestamp}] | "
                    f"{result.file_path} | "
                    f"{result.status} | "
                    f"Risk: {result.risk:.2%} | "
                    f"Source: {result.source} | "
                    f"{result.details}\n"
                )
                f.write(line)
        except Exception as e:
            print(f"[logger] Failed to write log: {e}")

    @staticmethod
    def read_logs() -> str:
        try:
            if os.path.isfile(SCAN_LOG_PATH):
                with open(SCAN_LOG_PATH, "r", encoding="utf-8") as f:
                    return f.read()
        except Exception:
            pass
        return ""

    @staticmethod
    def clear_logs() -> None:
        try:
            if os.path.isfile(SCAN_LOG_PATH):
                with open(SCAN_LOG_PATH, "w", encoding="utf-8") as f:
                    f.write("")
        except Exception:
            pass


# ────────────────────────────── Scanner ─────────────────────────────

class Scanner:
    """
    Unified scanner that orchestrates ML, ClamAV, and YARA engines.

    Decision priority:
        1. ClamAV detects  → MALWARE  (highest authority)
        2. YARA matches    → SUSPICIOUS
        3. ML prediction   → MALWARE / WARNING / SAFE
    """

    def __init__(self) -> None:
        self.ml = MLModel()
        self.clamav = ClamAVScanner()
        self.yara = YARAEngine()
        self.sandbox = SandboxAnalyzer()
        self.quarantine = QuarantineManager()
        self.logger = ScanLogger()

    def engine_status(self) -> dict:
        """Return availability of each engine."""
        return {
            "ml": self.ml.is_available(),
            "clamav": self.clamav.is_available(),
            "yara": self.yara.is_available(),
        }

    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a single file through all available engines.

        Returns a ScanResult with the combined verdict.
        """
        file_name = os.path.basename(file_path)

        if not os.path.isfile(file_path):
            return ScanResult(
                file_path=file_path,
                file_name=file_name,
                status="ERROR",
                risk=0.0,
                source="System",
                details="File not found",
            )

        # ── 1. ClamAV ──────────────────────────────────────────────
        clamav_result = self.clamav.scan(file_path)

        # ── 2. YARA ────────────────────────────────────────────────
        yara_result = self.yara.scan(file_path)

        # ── 3. ML ──────────────────────────────────────────────────
        ml_result = {"risk": 0.0, "label": "UNKNOWN", "source": "ML"}
        features = extract_features(file_path)
        if features is not None and self.ml.is_available():
            ml_result = self.ml.predict(features)

        # ── 4. Sandbox (Conditional for suspicious files) ──────────
        sandbox_report = None
        if ml_result.get("risk", 0.0) > 0.6 and self.sandbox.is_available():
            sandbox_report = self.sandbox.analyze(file_path)

        # ── Decision Logic ─────────────────────────────────────────
        result = self._decide(
            file_path, file_name, clamav_result, yara_result, ml_result, sandbox_report
        )

        # ── Log ────────────────────────────────────────────────────
        self.logger.log(result)

        return result

    def _decide(
        self,
        file_path: str,
        file_name: str,
        clamav_result: dict,
        yara_result: dict,
        ml_result: dict,
        sandbox_report: Optional[SandboxReport] = None,
    ) -> ScanResult:
        """Apply priority-based decision logic."""

        # Priority 1: ClamAV
        if clamav_result.get("detected"):
            threat = clamav_result.get("threat_name", "Unknown")
            return ScanResult(
                file_path=file_path,
                file_name=file_name,
                status="MALWARE",
                risk=1.0,
                source="ClamAV",
                details=f"Signature match: {threat}",
                clamav_result=clamav_result,
                yara_result=yara_result,
                ml_result=ml_result,
            )

        # Priority 2: YARA
        if yara_result.get("matched"):
            rules = ", ".join(yara_result.get("rules", []))
            return ScanResult(
                file_path=file_path,
                file_name=file_name,
                status="SUSPICIOUS",
                risk=0.65,
                source="YARA",
                details=f"Rule matches: {rules}",
                clamav_result=clamav_result,
                yara_result=yara_result,
                ml_result=ml_result,
            )

        # Priority 3: ML + Sandbox
        risk = ml_result.get("risk", 0.0)
        label = ml_result.get("label", "SAFE")
        source = "ML" if self.ml.is_available() else "Heuristic"

        # Integrate sandbox findings
        sandbox_details = ""
        if sandbox_report is not None:
            source = "ML + Sandbox"
            if sandbox_report.risk_score >= 0.7:
                label = "MALWARE"
                risk = max(risk, sandbox_report.risk_score)
                sandbox_details = " [Sandbox: Critical Behaviors]"
            elif sandbox_report.risk_score >= 0.4:
                if label != "MALWARE":
                    label = "WARNING"
                risk = max(risk, sandbox_report.risk_score)
                sandbox_details = " [Sandbox: Suspicious]"
            else:
                sandbox_details = " [Sandbox: Verified Safe]"

        if label == "MALWARE":
            status = "MALWARE"
            details = f"Prediction: {risk:.1%} malware probability{sandbox_details}"
        elif label == "WARNING":
            status = "WARNING"
            details = f"Prediction: {risk:.1%} risk — review recommended{sandbox_details}"
        elif label == "ERROR" or label == "UNKNOWN":
            status = "SAFE"
            details = "ML engine unavailable — no threats found by other engines"
            risk = 0.0
        else:
            status = "SAFE"
            details = f"Prediction: {risk:.1%} risk — file appears clean{sandbox_details}"

        return ScanResult(
            file_path=file_path,
            file_name=file_name,
            status=status,
            risk=risk,
            source=source,
            details=details,
            clamav_result=clamav_result,
            yara_result=yara_result,
            ml_result=ml_result,
        )

    def collect_files(self, folder_path: str) -> list[str]:
        """Recursively collect scannable files from a folder (legacy)."""
        return list(self.yield_files(folder_path))

    def yield_files(self, folder_path: str):
        """
        Lazily yield scannable files from a folder.

        Uses a generator to avoid building a full file list in memory,
        allowing the caller to begin scanning immediately during traversal.
        """
        try:
            for root, _dirs, filenames in os.walk(folder_path):
                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in SCAN_EXTENSIONS:
                        yield os.path.join(root, fname)
        except Exception as e:
            print(f"[scanner] Error traversing {folder_path}: {e}")


# ────────────────────────── Threaded Workers ────────────────────────

class FileScanWorker(QObject):
    """Worker for scanning a single file in a background thread."""

    finished = pyqtSignal(object)       # ScanResult
    error = pyqtSignal(str)

    def __init__(self, scanner: Scanner, file_path: str) -> None:
        super().__init__()
        self._scanner = scanner
        self._file_path = file_path

    def run(self) -> None:
        try:
            result = self._scanner.scan_file(self._file_path)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class FolderScanWorker(QObject):
    """
    Worker for scanning all files in a folder in a background thread.

    Uses generator-based file traversal to start scanning immediately
    instead of waiting for the full directory tree to be enumerated.
    """

    progress = pyqtSignal(int, int, object)   # current, total, ScanResult
    finished = pyqtSignal(list)               # list[ScanResult]
    error = pyqtSignal(str)

    def __init__(self, scanner: Scanner, folder_path: str) -> None:
        super().__init__()
        self._scanner = scanner
        self._folder_path = folder_path
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            results: list[ScanResult] = []
            scanned = 0

            for fp in self._scanner.yield_files(self._folder_path):
                if self._cancelled:
                    break
                result = self._scanner.scan_file(fp)
                results.append(result)
                scanned += 1
                # Total is unknown during traversal; emit 0 to signal
                # indeterminate mode. The UI handles this gracefully.
                self.progress.emit(scanned, 0, result)

            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))
