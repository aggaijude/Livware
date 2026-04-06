"""
scan_folder.py — Folder scan page.

Provides a folder picker, progress bar, real-time scrolling results,
and a scan summary with batch quarantine option.
"""

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QFileDialog, QProgressBar, QScrollArea, QSizePolicy,
)

from engine.scanner import Scanner, ScanResult, FolderScanWorker
from ui.widgets.result_card import ResultCard


class ScanFolderPage(QWidget):
    """Folder scan page with progress and real-time results."""

    quarantine_requested = pyqtSignal(object)   # ScanResult
    scan_batch_completed = pyqtSignal(list)     # list[ScanResult]

    def __init__(self, scanner: Scanner, parent=None) -> None:
        super().__init__(parent)
        self._scanner = scanner
        self._selected_folder: str | None = None
        self._thread: QThread | None = None
        self._worker: FolderScanWorker | None = None
        self._results: list[ScanResult] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        # ── Title ───────────────────────────────────────────────────
        title = QLabel("Scan Folder")
        title.setProperty("class", "heading")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel("Recursively scan all executable files in a folder")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(subtitle)

        # ── Folder Selection ────────────────────────────────────────
        pick_row = QHBoxLayout()
        pick_row.setSpacing(12)

        self._folder_label = QLabel("No folder selected")
        self._folder_label.setFont(QFont("Segoe UI", 12))
        self._folder_label.setStyleSheet("color: #64748b;")
        self._folder_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        pick_row.addWidget(self._folder_label)

        browse_btn = QPushButton("📂  Browse")
        browse_btn.setProperty("class", "primary")
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.setFixedHeight(40)
        browse_btn.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
        browse_btn.clicked.connect(self._browse_folder)
        pick_row.addWidget(browse_btn)

        layout.addLayout(pick_row)

        # ── Scan / Cancel Buttons ───────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self._scan_btn = QPushButton("🔍  Start Scan")
        self._scan_btn.setProperty("class", "primary")
        self._scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._scan_btn.setFixedHeight(46)
        self._scan_btn.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self._scan_btn.setEnabled(False)
        self._scan_btn.clicked.connect(self._start_scan)
        btn_row.addWidget(self._scan_btn)

        self._cancel_btn = QPushButton("⏹  Cancel")
        self._cancel_btn.setProperty("class", "danger")
        self._cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._cancel_btn.setFixedHeight(46)
        self._cancel_btn.setFont(QFont("Segoe UI", 13, QFont.Weight.DemiBold))
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel_scan)
        btn_row.addWidget(self._cancel_btn)

        layout.addLayout(btn_row)

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

        # ── Results Scroll Area ─────────────────────────────────────
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

    def _browse_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if path:
            self._selected_folder = path
            display = path if len(path) < 60 else "..." + path[-57:]
            self._folder_label.setText(f"📁 {display}")
            self._folder_label.setStyleSheet("color: #e2e8f0; font-weight: 600;")
            self._scan_btn.setEnabled(True)

    def _start_scan(self) -> None:
        if not self._selected_folder:
            return

        self._clear_results()
        self._results = []
        self._scan_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._summary_card.setVisible(False)
        self._progress_label.setText("⏳ Collecting files...")

        self._thread = QThread()
        self._worker = FolderScanWorker(self._scanner, self._selected_folder)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
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

    def _on_progress(self, current: int, total: int, result: ScanResult) -> None:
        if total > 0:
            # Known total — normal progress bar
            self._progress_bar.setMaximum(total)
            self._progress_bar.setValue(current)
            self._progress_label.setText(f"Scanning {current}/{total} — {result.file_name}")
        else:
            # Generator mode — indeterminate bar with file count
            self._progress_bar.setMaximum(0)  # Indeterminate / pulsing
            self._progress_label.setText(f"Scanning file #{current} — {result.file_name}")

        self._results.append(result)

        # Add card — insert before the stretch
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
        idx = self._results_layout.count() - 1  # Before stretch
        self._results_layout.insertWidget(max(0, idx), card)

        # Auto scroll to bottom
        sb = self._scroll.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_finished(self, results: list) -> None:
        self._scan_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._progress_bar.setVisible(False)

        total = len(results)
        safe = sum(1 for r in results if r.status == "SAFE")
        warn = sum(1 for r in results if r.status in ("WARNING", "SUSPICIOUS"))
        mal = sum(1 for r in results if r.status == "MALWARE")

        self._progress_label.setText(f"✅ Scan complete — {total} files scanned")
        self._progress_label.setStyleSheet("color: #22c55e; font-weight: 600;")

        self._sum_total.setText(f"Total: {total}")
        self._sum_safe.setText(f"Safe: {safe}")
        self._sum_warn.setText(f"Warning: {warn}")
        self._sum_mal.setText(f"Malware: {mal}")
        self._summary_card.setVisible(True)

        self.scan_batch_completed.emit(results)

    def _on_error(self, msg: str) -> None:
        self._scan_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
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
