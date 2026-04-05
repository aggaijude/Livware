"""
scan_file.py — Single file scan page.

Provides a file picker, scan button, animated progress indicator,
and result display for scanning individual files.
"""

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QFileDialog, QSizePolicy, QScrollArea,
)

from engine.scanner import Scanner, ScanResult, FileScanWorker
from ui.widgets.result_card import ResultCard


class ScanFilePage(QWidget):
    """Single file scan page."""

    quarantine_requested = pyqtSignal(object)    # ScanResult
    scan_completed = pyqtSignal(object)          # ScanResult

    def __init__(self, scanner: Scanner, parent=None) -> None:
        super().__init__(parent)
        self._scanner = scanner
        self._selected_file: str | None = None
        self._thread: QThread | None = None
        self._worker: FileScanWorker | None = None
        self._last_result: ScanResult | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # ── Title ───────────────────────────────────────────────────
        title = QLabel("Scan File")
        title.setProperty("class", "heading")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel("Select an executable file to scan for malware")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(subtitle)

        layout.addSpacing(8)

        # ── File Selection Card ─────────────────────────────────────
        file_card = QFrame()
        file_card.setObjectName("card")
        file_card_layout = QVBoxLayout(file_card)
        file_card_layout.setContentsMargins(20, 20, 20, 20)
        file_card_layout.setSpacing(12)

        pick_row = QHBoxLayout()
        pick_row.setSpacing(12)

        self._file_label = QLabel("No file selected")
        self._file_label.setFont(QFont("Segoe UI", 12))
        self._file_label.setStyleSheet("color: #64748b; background: transparent;")
        self._file_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        pick_row.addWidget(self._file_label)

        browse_btn = QPushButton("📂  Browse")
        browse_btn.setProperty("class", "primary")
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.setFixedHeight(40)
        browse_btn.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
        browse_btn.clicked.connect(self._browse_file)
        pick_row.addWidget(browse_btn)

        file_card_layout.addLayout(pick_row)
        layout.addWidget(file_card)

        # ── Scan Button ─────────────────────────────────────────────
        self._scan_btn = QPushButton("🔍  Start Scan")
        self._scan_btn.setProperty("class", "primary")
        self._scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._scan_btn.setFixedHeight(48)
        self._scan_btn.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._scan_btn.setEnabled(False)
        self._scan_btn.clicked.connect(self._start_scan)
        layout.addWidget(self._scan_btn)

        # ── Status ──────────────────────────────────────────────────
        self._status_label = QLabel("")
        self._status_label.setFont(QFont("Segoe UI", 12))
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setStyleSheet("color: #94a3b8;")
        layout.addWidget(self._status_label)

        # ── Result Area ─────────────────────────────────────────────
        self._result_container = QVBoxLayout()
        self._result_container.setSpacing(8)
        layout.addLayout(self._result_container)

        layout.addStretch()

        scroll.setWidget(content)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Scan",
            "",
            "Executable Files (*.exe *.dll *.scr *.sys *.com);;All Files (*.*)",
        )
        if path:
            self._selected_file = path
            fname = path.split("/")[-1].split("\\")[-1]
            self._file_label.setText(f"📄 {fname}")
            self._file_label.setStyleSheet("color: #e2e8f0; background: transparent; font-weight: 600;")
            self._scan_btn.setEnabled(True)

    def _start_scan(self) -> None:
        if not self._selected_file:
            return

        # Clear previous results
        self._clear_results()
        self._scan_btn.setEnabled(False)
        self._status_label.setText("⏳ Scanning... Please wait")
        self._status_label.setStyleSheet("color: #3b82f6;")

        # Run in thread
        self._thread = QThread()
        self._worker = FileScanWorker(self._scanner, self._selected_file)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_scan_done)
        self._worker.error.connect(self._on_scan_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _on_scan_done(self, result: ScanResult) -> None:
        self._last_result = result
        self._scan_btn.setEnabled(True)

        status_msg = {
            "SAFE": "✅ File is clean — no threats detected",
            "WARNING": "⚠️ File is suspicious — review recommended",
            "MALWARE": "🚨 MALWARE DETECTED — quarantine recommended",
            "SUSPICIOUS": "⚠️ Suspicious activity detected",
            "ERROR": "❌ Scan error occurred",
        }
        status_color = {
            "SAFE": "#22c55e",
            "WARNING": "#eab308",
            "MALWARE": "#ef4444",
            "SUSPICIOUS": "#eab308",
            "ERROR": "#94a3b8",
        }

        self._status_label.setText(status_msg.get(result.status, "Scan complete"))
        self._status_label.setStyleSheet(
            f"color: {status_color.get(result.status, '#94a3b8')}; font-weight: 600;"
        )

        card = ResultCard(
            file_name=result.file_name,
            file_path=result.file_path,
            status=result.status,
            risk=result.risk,
            source=result.source,
            details=result.details,
        )
        card.quarantine_clicked.connect(
            lambda fp: self.quarantine_requested.emit(self._last_result)
        )
        self._result_container.addWidget(card)
        self.scan_completed.emit(result)

    def _on_scan_error(self, error_msg: str) -> None:
        self._scan_btn.setEnabled(True)
        self._status_label.setText(f"❌ Error: {error_msg}")
        self._status_label.setStyleSheet("color: #ef4444;")

    def _clear_results(self) -> None:
        while self._result_container.count():
            child = self._result_container.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
