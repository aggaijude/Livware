"""
logs_view.py — Scan log viewer page.

Displays scan logs in a monospace text viewer with status filtering
and a clear logs button.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QPlainTextEdit, QComboBox, QFrame,
)

from engine.scanner import ScanLogger


class LogsViewPage(QWidget):
    """Scan logs viewer page."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._all_logs = ""
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        # ── Title Row ──────────────────────────────────────────────
        title_row = QHBoxLayout()

        title = QLabel("Scan Logs")
        title.setProperty("class", "heading")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title_row.addWidget(title)
        title_row.addStretch()

        # Filter combo
        self._filter = QComboBox()
        self._filter.addItems(["All", "SAFE", "WARNING", "MALWARE", "SUSPICIOUS", "ERROR"])
        self._filter.setFixedWidth(140)
        self._filter.currentTextChanged.connect(self._apply_filter)
        title_row.addWidget(self._filter)

        # Refresh
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_btn.setFixedHeight(36)
        refresh_btn.clicked.connect(self.refresh)
        title_row.addWidget(refresh_btn)

        # Clear
        clear_btn = QPushButton("🗑 Clear")
        clear_btn.setProperty("class", "danger")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.setFixedHeight(36)
        clear_btn.clicked.connect(self._clear_logs)
        title_row.addWidget(clear_btn)

        layout.addLayout(title_row)

        self._count_label = QLabel("0 log entries")
        self._count_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        layout.addWidget(self._count_label)

        # ── Log Text Area ──────────────────────────────────────────
        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Cascadia Code", 11))
        self._text.setPlaceholderText("No scan logs yet. Run a scan to generate logs.")
        layout.addWidget(self._text, 1)

    def refresh(self) -> None:
        """Reload logs from disk."""
        self._all_logs = ScanLogger.read_logs()
        self._apply_filter(self._filter.currentText())

    def _apply_filter(self, filter_text: str) -> None:
        if not self._all_logs:
            self._text.setPlainText("")
            self._count_label.setText("0 log entries")
            return

        lines = self._all_logs.strip().split("\n")

        if filter_text and filter_text != "All":
            lines = [l for l in lines if f"| {filter_text} |" in l]

        self._text.setPlainText("\n".join(lines))
        self._count_label.setText(f"{len(lines)} log entries")

        # Scroll to bottom
        sb = self._text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _clear_logs(self) -> None:
        ScanLogger.clear_logs()
        self._all_logs = ""
        self._text.setPlainText("")
        self._count_label.setText("0 log entries")

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh()
