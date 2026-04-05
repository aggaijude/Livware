"""
quarantine_view.py — Quarantine manager page.

Displays all quarantined files with restore and delete actions.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QSizePolicy,
)

from engine.quarantine import QuarantineManager


class QuarantineItemCard(QFrame):
    """Card representing a single quarantined file."""

    restore_clicked = pyqtSignal(str)   # q_id
    delete_clicked = pyqtSignal(str)    # q_id

    def __init__(self, item: dict, parent=None) -> None:
        super().__init__(parent)
        self._q_id = item["id"]
        self.setObjectName("result_card")
        self._setup_ui(item)

    def _setup_ui(self, item: dict) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Color bar ──────────────────────────────────────────────
        bar = QFrame()
        bar.setFixedWidth(4)
        bar.setStyleSheet("background-color: #ef4444; border-radius: 2px; margin: 4px 0px;")
        layout.addWidget(bar)

        # ── Info ───────────────────────────────────────────────────
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(14, 10, 14, 10)
        info_layout.setSpacing(4)

        row1 = QHBoxLayout()
        name_label = QLabel(f"🔒  {item.get('original_name', 'Unknown')}")
        name_label.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
        name_label.setStyleSheet("background: transparent;")
        row1.addWidget(name_label)
        row1.addStretch()

        badge = QLabel(f"  {item.get('source', 'N/A')}  ")
        badge.setStyleSheet(
            "background-color: #ef4444; color: white; border-radius: 4px; "
            "padding: 2px 10px; font-size: 11px; font-weight: 600;"
        )
        row1.addWidget(badge)
        info_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(16)

        reason_label = QLabel(f"Reason: {item.get('reason', 'N/A')}")
        reason_label.setStyleSheet("color: #94a3b8; font-size: 11px; background: transparent;")
        row2.addWidget(reason_label)

        date_label = QLabel(f"Date: {item.get('timestamp', 'N/A')}")
        date_label.setStyleSheet("color: #64748b; font-size: 11px; background: transparent;")
        row2.addWidget(date_label)

        path_label = QLabel(f"Path: {item.get('original_path', 'N/A')}")
        path_label.setStyleSheet("color: #475569; font-size: 10px; background: transparent;")
        path_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        path_label.setWordWrap(True)
        row2.addWidget(path_label)

        row2.addStretch()
        info_layout.addLayout(row2)

        layout.addLayout(info_layout, 1)

        # ── Actions ────────────────────────────────────────────────
        actions = QVBoxLayout()
        actions.setContentsMargins(8, 8, 12, 8)
        actions.setSpacing(6)

        restore_btn = QPushButton("🔄 Restore")
        restore_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        restore_btn.setFixedHeight(28)
        restore_btn.setStyleSheet(
            "background-color: #3b82f6; color: white; border: none; "
            "border-radius: 6px; padding: 2px 12px; font-size: 11px; font-weight: 600;"
        )
        restore_btn.clicked.connect(lambda: self.restore_clicked.emit(self._q_id))
        actions.addWidget(restore_btn)

        delete_btn = QPushButton("🗑 Delete")
        delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        delete_btn.setFixedHeight(28)
        delete_btn.setStyleSheet(
            "background-color: #ef4444; color: white; border: none; "
            "border-radius: 6px; padding: 2px 12px; font-size: 11px; font-weight: 600;"
        )
        delete_btn.clicked.connect(lambda: self.delete_clicked.emit(self._q_id))
        actions.addWidget(delete_btn)

        layout.addLayout(actions)
        self.setMinimumHeight(68)


class QuarantineViewPage(QWidget):
    """Quarantine viewer page."""

    items_changed = pyqtSignal()

    def __init__(self, quarantine: QuarantineManager, parent=None) -> None:
        super().__init__(parent)
        self._quarantine = quarantine
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        # ── Title Row ──────────────────────────────────────────────
        title_row = QHBoxLayout()
        title = QLabel("Quarantine")
        title.setProperty("class", "heading")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title_row.addWidget(title)
        title_row.addStretch()

        refresh_btn = QPushButton("🔄  Refresh")
        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_btn.setFixedHeight(36)
        refresh_btn.clicked.connect(self.refresh)
        title_row.addWidget(refresh_btn)

        layout.addLayout(title_row)

        self._count_label = QLabel("0 files quarantined")
        self._count_label.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(self._count_label)

        # ── Scroll Area ────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self._list_widget = QWidget()
        self._list_layout = QVBoxLayout(self._list_widget)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(6)
        self._list_layout.addStretch()

        scroll.setWidget(self._list_widget)
        layout.addWidget(scroll, 1)

        # ── Empty State ────────────────────────────────────────────
        self._empty_label = QLabel("🔓  No files in quarantine")
        self._empty_label.setFont(QFont("Segoe UI", 14))
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet("color: #64748b; padding: 40px;")
        self._list_layout.insertWidget(0, self._empty_label)

    def refresh(self) -> None:
        """Reload quarantine list from disk."""
        # Clear list
        while self._list_layout.count():
            child = self._list_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        items = self._quarantine.get_quarantined()
        self._count_label.setText(f"{len(items)} file{'s' if len(items) != 1 else ''} quarantined")

        if not items:
            self._empty_label = QLabel("🔓  No files in quarantine")
            self._empty_label.setFont(QFont("Segoe UI", 14))
            self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._empty_label.setStyleSheet("color: #64748b; padding: 40px;")
            self._list_layout.addWidget(self._empty_label)
        else:
            for item in items:
                card = QuarantineItemCard(item)
                card.restore_clicked.connect(self._on_restore)
                card.delete_clicked.connect(self._on_delete)
                self._list_layout.addWidget(card)

        self._list_layout.addStretch()

    def _on_restore(self, q_id: str) -> None:
        self._quarantine.restore(q_id)
        self.refresh()
        self.items_changed.emit()

    def _on_delete(self, q_id: str) -> None:
        self._quarantine.delete(q_id)
        self.refresh()
        self.items_changed.emit()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh()
