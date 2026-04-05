"""
sandbox.py — Static behavioral analysis sandbox.

Performs safe, host-isolated analysis of PE files by examining:
  - Import table (API calls)
  - Embedded strings
  - Section entropy
  - Resource anomalies

Classifies observed behaviors into risk categories without executing the file.
This is a simulation-based sandbox — no code is ever run on the host.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from PyQt6.QtCore import QObject, pyqtSignal

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ────────────────────────────── Behavior DB ─────────────────────────

SUSPICIOUS_APIS = {
    # Keylogging
    "GetAsyncKeyState":       ("Keylogging", "high"),
    "SetWindowsHookExA":      ("Keylogging", "high"),
    "SetWindowsHookExW":      ("Keylogging", "high"),
    "GetKeyState":            ("Keylogging", "medium"),
    "GetKeyboardState":       ("Keylogging", "medium"),

    # Process injection
    "VirtualAllocEx":         ("Process Injection", "critical"),
    "WriteProcessMemory":     ("Process Injection", "critical"),
    "CreateRemoteThread":     ("Process Injection", "critical"),
    "NtCreateThreadEx":       ("Process Injection", "critical"),
    "QueueUserAPC":           ("Process Injection", "high"),

    # Code execution
    "ShellExecuteA":          ("Code Execution", "medium"),
    "ShellExecuteW":          ("Code Execution", "medium"),
    "WinExec":                ("Code Execution", "high"),
    "CreateProcessA":         ("Code Execution", "medium"),
    "CreateProcessW":         ("Code Execution", "medium"),

    # File operations
    "DeleteFileA":            ("File Manipulation", "medium"),
    "DeleteFileW":            ("File Manipulation", "medium"),
    "MoveFileExA":            ("File Manipulation", "low"),
    "CopyFileA":              ("File Manipulation", "low"),

    # Registry
    "RegSetValueExA":         ("Registry Modification", "high"),
    "RegSetValueExW":         ("Registry Modification", "high"),
    "RegCreateKeyExA":        ("Registry Modification", "high"),
    "RegDeleteKeyA":          ("Registry Modification", "high"),

    # Network
    "InternetOpenA":          ("Network Activity", "high"),
    "InternetOpenW":          ("Network Activity", "high"),
    "InternetConnectA":       ("Network Activity", "high"),
    "HttpOpenRequestA":       ("Network Activity", "high"),
    "URLDownloadToFileA":     ("Network Download", "critical"),
    "URLDownloadToFileW":     ("Network Download", "critical"),
    "WSAStartup":             ("Network Socket", "medium"),
    "connect":                ("Network Socket", "medium"),
    "send":                   ("Network Socket", "low"),
    "recv":                   ("Network Socket", "low"),

    # Anti-debug / evasion
    "IsDebuggerPresent":      ("Anti-Debug", "high"),
    "CheckRemoteDebuggerPresent": ("Anti-Debug", "high"),
    "NtQueryInformationProcess":  ("Anti-Debug", "high"),
    "GetTickCount":           ("Anti-Analysis", "low"),
    "Sleep":                  ("Anti-Analysis", "low"),

    # Crypto
    "CryptEncrypt":           ("Cryptographic API", "high"),
    "CryptDecrypt":           ("Cryptographic API", "medium"),
    "CryptGenKey":            ("Cryptographic API", "high"),
    "CryptAcquireContextA":   ("Cryptographic API", "medium"),

    # Privilege
    "AdjustTokenPrivileges":  ("Privilege Escalation", "critical"),
    "OpenProcessToken":       ("Privilege Escalation", "high"),

    # Service
    "CreateServiceA":         ("Service Installation", "critical"),
    "CreateServiceW":         ("Service Installation", "critical"),
    "StartServiceA":          ("Service Control", "high"),
}

SUSPICIOUS_STRINGS_PATTERNS = [
    (r"https?://\d+\.\d+\.\d+\.\d+", "Hardcoded IP URL", "high"),
    (r"https?://[a-z0-9\-]+\.[a-z]{2,}", "Embedded URL", "medium"),
    (r"cmd\.exe|powershell\.exe|wscript\.exe", "Shell Reference", "high"),
    (r"\\\\CurrentVersion\\\\Run", "Autorun Registry Path", "critical"),
    (r"\\\\CurrentVersion\\\\RunOnce", "Autorun Registry Path", "critical"),
    (r"HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER", "Registry Hive Reference", "medium"),
    (r"\.encrypted|\.locked|\.crypto|\.crypt", "Ransomware Extension", "critical"),
    (r"bitcoin|wallet|ransom|decrypt", "Ransom Keyword", "critical"),
    (r"password|passwd|login|credential", "Credential Keyword", "medium"),
    (r"taskkill|net stop", "Process/Service Kill", "high"),
    (r"vssadmin.*delete", "Shadow Copy Deletion", "critical"),
]


# ────────────────────────────── Data Model ──────────────────────────

@dataclass
class BehaviorFlag:
    """A single observed suspicious behavior."""
    category: str          # e.g. "Keylogging", "Network Activity"
    detail: str            # e.g. "Imports GetAsyncKeyState"
    severity: str          # "low", "medium", "high", "critical"


@dataclass
class SandboxReport:
    """Complete sandbox analysis report for a file."""
    file_path: str
    file_name: str
    file_size: int = 0
    is_pe: bool = False

    # Analysis results
    behaviors: list[BehaviorFlag] = field(default_factory=list)
    imported_apis: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)

    # Scores
    risk_score: float = 0.0      # 0.0 – 1.0
    risk_level: str = "SAFE"     # SAFE / LOW / MEDIUM / HIGH / CRITICAL

    # Metadata
    analysis_time: float = 0.0
    error: str = ""

    @property
    def behavior_summary(self) -> dict:
        """Count behaviors by category."""
        cats: dict[str, int] = {}
        for b in self.behaviors:
            cats[b.category] = cats.get(b.category, 0) + 1
        return cats

    @property
    def severity_counts(self) -> dict:
        """Count behaviors by severity."""
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for b in self.behaviors:
            counts[b.severity] = counts.get(b.severity, 0) + 1
        return counts


# ────────────────────────────── Sandbox Engine ──────────────────────

class SandboxAnalyzer:
    """
    Static behavioral analysis engine.

    Performs safe analysis of PE files without execution:
      1. Import table analysis → flags suspicious API usage
      2. String analysis → detects embedded URLs, paths, commands
      3. Entropy analysis → detects packed/encrypted sections
      4. Structure analysis → checks for anomalies
    """

    def __init__(self) -> None:
        self._available = PEFILE_AVAILABLE
        if not self._available:
            print("[sandbox] pefile not available — sandbox analysis disabled")

    def is_available(self) -> bool:
        return self._available

    def analyze(self, file_path: str) -> SandboxReport:
        """
        Run full static sandbox analysis on a file.

        Returns a SandboxReport with all findings.
        """
        import time as _time
        start = _time.monotonic()

        file_name = os.path.basename(file_path)
        report = SandboxReport(file_path=file_path, file_name=file_name)

        if not os.path.isfile(file_path):
            report.error = "File not found"
            return report

        report.file_size = os.path.getsize(file_path)

        try:
            pe = pefile.PE(file_path, fast_load=False)
            report.is_pe = True
        except pefile.PEFormatError:
            report.error = "Not a valid PE file"
            report.analysis_time = _time.monotonic() - start
            self._calculate_risk(report)
            return report
        except Exception as e:
            report.error = f"Parse error: {e}"
            report.analysis_time = _time.monotonic() - start
            return report

        try:
            # ── 1. Import Analysis ──────────────────────────────────
            self._analyze_imports(pe, report)

            # ── 2. String Analysis ──────────────────────────────────
            self._analyze_strings(file_path, report)

            # ── 3. Entropy Analysis ─────────────────────────────────
            self._analyze_entropy(pe, report)

            # ── 4. Structure Analysis ───────────────────────────────
            self._analyze_structure(pe, report)

            pe.close()
        except Exception as e:
            report.error = f"Analysis error: {e}"
            try:
                pe.close()
            except Exception:
                pass

        report.analysis_time = _time.monotonic() - start
        self._calculate_risk(report)
        return report

    # ── Analysis Modules ────────────────────────────────────────────

    def _analyze_imports(self, pe, report: SandboxReport) -> None:
        """Analyze import table for suspicious API calls."""
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode("utf-8", errors="ignore")
                    report.imported_apis.append(api_name)

                    if api_name in SUSPICIOUS_APIS:
                        category, severity = SUSPICIOUS_APIS[api_name]
                        report.behaviors.append(BehaviorFlag(
                            category=category,
                            detail=f"Imports {api_name} from {entry.dll.decode('utf-8', errors='ignore')}",
                            severity=severity,
                        ))

    def _analyze_strings(self, file_path: str, report: SandboxReport) -> None:
        """Search for suspicious embedded strings."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(min(os.path.getsize(file_path), 5 * 1024 * 1024))  # Max 5MB

            # Extract printable ASCII strings (length >= 6)
            text = data.decode("ascii", errors="ignore")

            for pattern, desc, severity in SUSPICIOUS_STRINGS_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches[:3]:  # Limit to 3 per pattern
                    report.suspicious_strings.append(f"{desc}: {match}")
                    report.behaviors.append(BehaviorFlag(
                        category="Suspicious String",
                        detail=f"{desc}: {match[:80]}",
                        severity=severity,
                    ))
        except Exception:
            pass

    def _analyze_entropy(self, pe, report: SandboxReport) -> None:
        """Analyze section entropy for packing/encryption indicators."""
        for section in pe.sections:
            try:
                name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                raw = section.get_data()
                entropy = self._shannon_entropy(raw)
                size = len(raw)

                section_info = {
                    "name": name,
                    "entropy": round(entropy, 3),
                    "size": size,
                    "virtual_size": section.Misc_VirtualSize,
                    "characteristics": hex(section.Characteristics),
                }
                report.sections.append(section_info)

                # High entropy → likely packed or encrypted
                if entropy > 7.2:
                    report.behaviors.append(BehaviorFlag(
                        category="Packed/Encrypted",
                        detail=f"Section '{name}' has very high entropy ({entropy:.2f})",
                        severity="high",
                    ))
                elif entropy > 6.8:
                    report.behaviors.append(BehaviorFlag(
                        category="Suspicious Entropy",
                        detail=f"Section '{name}' has elevated entropy ({entropy:.2f})",
                        severity="medium",
                    ))

                # Size anomaly
                if section.Misc_VirtualSize > 0 and size > 0:
                    ratio = section.Misc_VirtualSize / size
                    if ratio > 10:
                        report.behaviors.append(BehaviorFlag(
                            category="Memory Inflation",
                            detail=f"Section '{name}' virtual size is {ratio:.0f}x raw size",
                            severity="medium",
                        ))
            except Exception:
                continue

    def _analyze_structure(self, pe, report: SandboxReport) -> None:
        """Check PE structure for anomalies."""
        # Too many sections
        num_sections = pe.FILE_HEADER.NumberOfSections
        if num_sections > 8:
            report.behaviors.append(BehaviorFlag(
                category="Structure Anomaly",
                detail=f"Unusual number of sections: {num_sections}",
                severity="medium",
            ))

        # Entry point outside first section
        if pe.sections:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            first = pe.sections[0]
            if ep < first.VirtualAddress or ep > first.VirtualAddress + first.Misc_VirtualSize:
                report.behaviors.append(BehaviorFlag(
                    category="Structure Anomaly",
                    detail="Entry point is outside the first section",
                    severity="high",
                ))

        # No imports at all (suspicious for a PE)
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT") or not pe.DIRECTORY_ENTRY_IMPORT:
            report.behaviors.append(BehaviorFlag(
                category="Structure Anomaly",
                detail="PE has no import table — may be packed or obfuscated",
                severity="medium",
            ))

        # Very small file
        if report.file_size < 5120:
            report.behaviors.append(BehaviorFlag(
                category="Structure Anomaly",
                detail=f"Very small PE file ({report.file_size} bytes)",
                severity="low",
            ))

    # ── Scoring ─────────────────────────────────────────────────────

    def _calculate_risk(self, report: SandboxReport) -> None:
        """Calculate overall risk score from behavior flags."""
        if not report.behaviors:
            report.risk_score = 0.0
            report.risk_level = "SAFE"
            return

        severity_weights = {
            "low": 0.05,
            "medium": 0.12,
            "high": 0.22,
            "critical": 0.35,
        }

        score = 0.0
        for b in report.behaviors:
            score += severity_weights.get(b.severity, 0.05)

        # Cap at 1.0
        report.risk_score = min(1.0, round(score, 4))

        if report.risk_score >= 0.7:
            report.risk_level = "CRITICAL"
        elif report.risk_score >= 0.5:
            report.risk_level = "HIGH"
        elif report.risk_score >= 0.3:
            report.risk_level = "MEDIUM"
        elif report.risk_score >= 0.1:
            report.risk_level = "LOW"
        else:
            report.risk_level = "SAFE"

    # ── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        ent = 0.0
        for count in freq:
            if count:
                p = count / length
                ent -= p * math.log2(p)
        return ent


# ────────────────────────────── Worker ──────────────────────────────

class SandboxWorker(QObject):
    """Background worker for sandbox analysis."""

    finished = pyqtSignal(object)   # SandboxReport
    error = pyqtSignal(str)

    def __init__(self, analyzer: SandboxAnalyzer, file_path: str) -> None:
        super().__init__()
        self._analyzer = analyzer
        self._file_path = file_path

    def run(self) -> None:
        try:
            report = self._analyzer.analyze(self._file_path)
            self.finished.emit(report)
        except Exception as e:
            self.error.emit(str(e))
