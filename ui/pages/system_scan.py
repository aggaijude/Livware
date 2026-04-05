"""
system_scan.py — Full system scan page.

Provides quick scan and full scan modes with real-time progress,
confirmation dialogs, and scan summary.
"""

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QProgressBar, QScrollArea, QMessageBox, QSizePolicy,
)

from engine.scanner import Scanner, ScanResult
from engine.system_scanner import SystemScanWorker, get_all_drives, QUICK_SCAN_DIRS
from ui.widgets.result_card import ResultCard

import os


class SystemScanPage(QWidget):
    """Full / Quick system scan page."""

    quarantine_requested = pyqtSignal(object)
    scan_batch_completed = pyqtSignal(list)

    def __init__(self, scanner: Scanner, parent=None) -> None:
        super().__init__(parent)
        self._scanner = scanner
        self._thread: QThread | None = None
        self._worker: SystemScanWorker | None = None
        self._results: list[ScanResult] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        # ── Title ───────────────────────────────────────────────────
        title = QLabel("System Scan")
        title.setProperty("class", "heading")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel("Scan your entire system or common directories for threats")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(subtitle)

        layout.addSpacing(4)

        # ── Mode Cards ──────────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(14)

        # Quick Scan Card
        quick_card = QFrame()
        quick_card.setObjectName("card")
        qc_layout = QVBoxLayout(quick_card)
        qc_layout.setContentsMargins(20, 16, 20, 16)
        qc_layout.setSpacing(8)

        qc_icon = QLabel("⚡")
        qc_icon.setFont(QFont("Segoe UI Emoji", 28))
        qc_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qc_icon.setStyleSheet("background: transparent;")
        qc_layout.addWidget(qc_icon)

        qc_title = QLabel("Quick Scan")
        qc_title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        qc_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qc_title.setStyleSheet("background: transparent;")
        qc_layout.addWidget(qc_title)

        qc_desc = QLabel("Scans Desktop, Downloads,\nDocuments, AppData, Temp")
        qc_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qc_desc.setStyleSheet("color: #94a3b8; font-size: 11px; background: transparent;")
        qc_layout.addWidget(qc_desc)

        self._quick_btn = QPushButton("🔍  Start Quick Scan")
        self._quick_btn.setProperty("class", "primary")
        self._quick_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._quick_btn.setFixedHeight(40)
        self._quick_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
        self._quick_btn.clicked.connect(lambda: self._start_scan("quick"))
        qc_layout.addWidget(self._quick_btn)

        cards_row.addWidget(quick_card)

        # Full Scan Card
        full_card = QFrame()
        full_card.setObjectName("card")
        fc_layout = QVBoxLayout(full_card)
        fc_layout.setContentsMargins(20, 16, 20, 16)
        fc_layout.setSpacing(8)

        fc_icon = QLabel("🖥️")
        fc_icon.setFont(QFont("Segoe UI Emoji", 28))
        fc_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        fc_icon.setStyleSheet("background: transparent;")
        fc_layout.addWidget(fc_icon)

        fc_title = QLabel("Full System Scan")
        fc_title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        fc_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        fc_title.setStyleSheet("background: transparent;")
        fc_layout.addWidget(fc_title)

        drives = get_all_drives()
        drive_str = ", ".join(drives[:6]) if drives else "No drives"
        fc_desc = QLabel(f"Scans all drives:\n{drive_str}")
        fc_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        fc_desc.setStyleSheet("color: #94a3b8; font-size: 11px; background: transparent;")
        fc_layout.addWidget(fc_desc)

        self._full_btn = QPushButton("🛡️  Start Full Scan")
        self._full_btn.setProperty("class", "danger")
        self._full_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._full_btn.setFixedHeight(40)
        self._full_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
        self._full_btn.setStyleSheet(
            "background-color: #7c3aed; color: white; border: none; "
            "border-radius: 8px; font-weight: 600;"
        )
        self._full_btn.clicked.connect(lambda: self._start_scan("full"))
        fc_layout.addWidget(self._full_btn)

        cards_row.addWidget(full_card)
        layout.addLayout(cards_row)

        # ── Cancel Button ───────────────────────────────────────────
        self._cancel_btn = QPushButton("⏹  Cancel Scan")
        self._cancel_btn.setProperty("class", "danger")
        self._cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._cancel_btn.setFixedHeight(40)
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.setVisible(False)
        self._cancel_btn.clicked.connect(self._cancel_scan)
        layout.addWidget(self._cancel_btn)

        # ── Progress ────────────────────────────────────────────────
        self._progress_bar = QProgressBar()
        self._progress_bar.setValue(0)
        self._progress_bar.setVisible(False)
        layout.addWidget(self._progress_bar)

        self._progress_label = QLabel("")
        self._progress_label.setFont(QFont("Segoe UI", 11))
        self._progress_label.setStyleSheet("color: #94a3b8;")
        self._progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._progress_label)

        # ── Summary Card ────────────────────────────────────────────
        self._summary_card = QFrame()
        self._summary_card.setObjectName("card")
        self._summary_card.setVisible(False)
        summary_layout = QHBoxLayout(self._summary_card)
        summary_layout.setContentsMargins(16, 12, 16, 12)
        summary_layout.setSpacing(20)

        self._sum_total = QLabel("Total: 0")
        self._sum_total.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
        self._sum_total.setStyleSheet("background: transparent;")
        summary_layout.addWidget(self._sum_total)

        self._sum_safe = QLabel("Safe: 0")
        self._sum_safe.setStyleSheet("color: #22c55e; font-weight: 600; background: transparent;")
        summary_layout.addWidget(self._sum_safe)

        self._sum_warn = QLabel("Warning: 0")
        self._sum_warn.setStyleSheet("color: #eab308; font-weight: 600; background: transparent;")
        summary_layout.addWidget(self._sum_warn)

        self._sum_mal = QLabel("Malware: 0")
        self._sum_mal.setStyleSheet("color: #ef4444; font-weight: 600; background: transparent;")
        summary_layout.addWidget(self._sum_mal)

        summary_layout.addStretch()
        layout.addWidget(self._summary_card)

        # ── Results Scroll ──────────────────────────────────────────
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)

        self._results_widget = QWidget()
        self._results_layout = QVBoxLayout(self._results_widget)
        self._results_layout.setContentsMargins(0, 0, 0, 0)
        self._results_layout.setSpacing(6)
        self._results_layout.addStretch()

        self._scroll.setWidget(self._results_widget)
        layout.addWidget(self._scroll, 1)

    def _start_scan(self, mode: str) -> None:
        if mode == "full":
            reply = QMessageBox.question(
                self, "Full System Scan",
                "This will scan ALL drives on your system.\n"
                "This may take a very long time.\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self._clear_results()
        self._results = []
        self._quick_btn.setEnabled(False)
        self._full_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._cancel_btn.setVisible(True)
        self._progress_bar.setVisible(True)
        self._progress_bar.setMaximum(0)
        self._progress_bar.setValue(0)
        self._summary_card.setVisible(False)

        mode_label = "Quick" if mode == "quick" else "Full System"
        self._progress_label.setText(f"⏳ {mode_label} Scan — Collecting files...")
        self._progress_label.setStyleSheet("color: #3b82f6;")

        self._thread = QThread()
        self._worker = SystemScanWorker(self._scanner, mode)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.collecting.connect(self._on_collecting)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _cancel_scan(self) -> None:
        if self._worker:
            self._worker.cancel()
        self._cancel_btn.setEnabled(False)
        self._progress_label.setText("🛑 Cancelling...")

    def _on_collecting(self, count: int) -> None:
        self._progress_label.setText(f"📂 Discovering files... {count} found")

    def _on_progress(self, current: int, total: int, result: ScanResult) -> None:
        self._progress_bar.setMaximum(total)
        self._progress_bar.setValue(current)
        self._progress_label.setText(f"Scanning {current}/{total} — {result.file_name}")

        self._results.append(result)

        # Only show non-SAFE results to keep UI lean during system scans
        if result.status != "SAFE":
            card = ResultCard(
                file_name=result.file_name,
                file_path=result.file_path,
                status=result.status,
                risk=result.risk,
                source=result.source,
                details=result.details,
            )
            card.quarantine_clicked.connect(
                lambda fp: self.quarantine_requested.emit(result)
            )
            idx = self._results_layout.count() - 1
            self._results_layout.insertWidget(max(0, idx), card)

            sb = self._scroll.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _on_finished(self, results: list) -> None:
        self._quick_btn.setEnabled(True)
        self._full_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.setVisible(False)
        self._progress_bar.setVisible(False)

        total = len(results)
        safe = sum(1 for r in results if r.status == "SAFE")
        warn = sum(1 for r in results if r.status in ("WARNING", "SUSPICIOUS"))
        mal = sum(1 for r in results if r.status == "MALWARE")

        self._progress_label.setText(f"✅ System scan complete — {total} files scanned")
        self._progress_label.setStyleSheet("color: #22c55e; font-weight: 600;")

        self._sum_total.setText(f"Total: {total}")
        self._sum_safe.setText(f"Safe: {safe}")
        self._sum_warn.setText(f"Warning: {warn}")
        self._sum_mal.setText(f"Malware: {mal}")
        self._summary_card.setVisible(True)

        self.scan_batch_completed.emit(results)

    def _on_error(self, msg: str) -> None:
        self._quick_btn.setEnabled(True)
        self._full_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.setVisible(False)
        self._progress_bar.setVisible(False)
        self._progress_label.setText(f"❌ Error: {msg}")
        self._progress_label.setStyleSheet("color: #ef4444;")

    def _clear_results(self) -> None:
        while self._results_layout.count():
            child = self._results_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self._results_layout.addStretch()
        self._progress_label.setText("")
        self._progress_label.setStyleSheet("color: #94a3b8;")
