"""
result_card.py — Scan result card widget.

Displays a single file scan result with color-coded status,
risk percentage, detection source, and optional action buttons.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QWidget, QSizePolicy,
)

from ui.styles import get_status_color


class ResultCard(QFrame):
    """Card widget for displaying a scan result."""

    quarantine_clicked = pyqtSignal(str)   # file_path

    def __init__(
        self,
        file_name: str,
        file_path: str,
        status: str,
        risk: float,
        source: str,
        details: str = "",
        dark: bool = True,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._file_path = file_path
        self._status = status
        self._dark = dark
        self.setObjectName("result_card")
        self._setup_ui(file_name, status, risk, source, details)

    def _setup_ui(
        self, file_name: str, status: str, risk: float, source: str, details: str
    ) -> None:
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Color bar (left edge) ───────────────────────────────────
        color_bar = QFrame()
        color_bar.setFixedWidth(4)
        color = get_status_color(status, self._dark)
        color_bar.setStyleSheet(
            f"background-color: {color}; border-radius: 2px; "
            f"margin: 4px 0px;"
        )
        main_layout.addWidget(color_bar)

        # ── Content area ────────────────────────────────────────────
        content = QVBoxLayout()
        content.setContentsMargins(14, 10, 14, 10)
        content.setSpacing(4)

        # Row 1: filename + status badge
        row1 = QHBoxLayout()
        row1.setSpacing(10)

        name_label = QLabel(file_name)
        name_label.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
        name_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        row1.addWidget(name_label)

        # Status badge
        badge = QLabel(f"  {status}  ")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        badge.setStyleSheet(
            f"background-color: {color}; color: white; "
            f"border-radius: 4px; padding: 2px 10px; font-size: 11px;"
        )
        row1.addWidget(badge)
        content.addLayout(row1)

        # Row 2: risk + source + details
        row2 = QHBoxLayout()
        row2.setSpacing(16)

        risk_pct = f"{risk:.0%}"
        risk_label = QLabel(f"Risk: {risk_pct}")
        risk_label.setStyleSheet(f"color: {color}; font-weight: 600; font-size: 12px; background: transparent;")
        row2.addWidget(risk_label)

        source_label = QLabel(f"Source: {source}")
        source_label.setStyleSheet(f"color: #94a3b8; font-size: 12px; background: transparent;")
        row2.addWidget(source_label)

        if details:
            detail_label = QLabel(details)
            detail_label.setStyleSheet("color: #64748b; font-size: 11px; background: transparent;")
            detail_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            detail_label.setWordWrap(True)
            row2.addWidget(detail_label)

        row2.addStretch()
        content.addLayout(row2)

        main_layout.addLayout(content, 1)

        # ── Action button ───────────────────────────────────────────
        if status in ("MALWARE", "SUSPICIOUS"):
            btn = QPushButton("🔒 Quarantine")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFixedHeight(32)
            btn.setStyleSheet(
                f"background-color: {get_status_color('MALWARE', self._dark)};"
                f"color: white; border: none; border-radius: 6px; "
                f"padding: 4px 14px; font-size: 11px; font-weight: 600;"
            )
            btn.clicked.connect(lambda: self.quarantine_clicked.emit(self._file_path))
            action_layout = QVBoxLayout()
            action_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            action_layout.addWidget(btn)
            main_layout.addLayout(action_layout)

        self.setMinimumHeight(64)
