"""
sidebar.py — Navigation sidebar with app branding and page buttons.

Fixed-width left panel with icon+text navigation buttons,
an active indicator, and a bottom settings button.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QSpacerItem, QSizePolicy,
    QFrame,
)

from config import APP_NAME, APP_VERSION, SIDEBAR_WIDTH


class SidebarButton(QPushButton):
    """A single sidebar navigation button."""

    def __init__(self, icon: str, text: str, parent=None) -> None:
        super().__init__(f"  {icon}   {text}", parent)
        self.setObjectName("sidebar_btn")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(44)
        self.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))

    def set_active(self, active: bool) -> None:
        self.setProperty("active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)


class Sidebar(QWidget):
    """Application sidebar with navigation buttons."""

    page_changed = pyqtSignal(int)

    PAGE_ITEMS = [
        ("🏠", "Dashboard"),
        ("📄", "Scan File"),
        ("📁", "Scan Folder"),
        ("🖥️", "System Scan"),
        ("🧪", "Sandbox"),
        ("🔒", "Quarantine"),
        ("📋", "Logs"),
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(SIDEBAR_WIDTH)
        self._buttons: list[SidebarButton] = []
        self._current_index = 0
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 16, 12, 16)
        layout.setSpacing(4)

        # ── App Branding ────────────────────────────────────────────
        brand_frame = QWidget()
        brand_frame.setStyleSheet("background: transparent;")
        brand_layout = QVBoxLayout(brand_frame)
        brand_layout.setContentsMargins(8, 0, 8, 0)
        brand_layout.setSpacing(2)

        shield_label = QLabel("🛡️")
        shield_label.setFont(QFont("Segoe UI Emoji", 28))
        shield_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        shield_label.setStyleSheet("background: transparent;")
        brand_layout.addWidget(shield_label)

        name_label = QLabel(APP_NAME)
        name_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label.setStyleSheet("background: transparent;")
        brand_layout.addWidget(name_label)

        ver_label = QLabel(f"v{APP_VERSION}")
        ver_label.setFont(QFont("Segoe UI", 9))
        ver_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver_label.setStyleSheet("color: #64748b; background: transparent;")
        brand_layout.addWidget(ver_label)

        layout.addWidget(brand_frame)

        # ── Separator ───────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #334155; margin: 12px 0px;")
        layout.addWidget(sep)
        layout.addSpacing(8)

        # ── Navigation Buttons ──────────────────────────────────────
        for i, (icon, text) in enumerate(self.PAGE_ITEMS):
            btn = SidebarButton(icon, text)
            btn.clicked.connect(lambda checked, idx=i: self._on_click(idx))
            self._buttons.append(btn)
            layout.addWidget(btn)
            layout.addSpacing(2)

        # ── Spacer ──────────────────────────────────────────────────
        layout.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

        # ── Separator ───────────────────────────────────────────────
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background-color: #334155;")
        layout.addWidget(sep2)
        layout.addSpacing(4)

        # ── Settings Button ─────────────────────────────────────────
        self._settings_btn = SidebarButton("⚙️", "Settings")
        self._settings_btn.clicked.connect(lambda: self._on_click(7))
        self._buttons.append(self._settings_btn)
        layout.addWidget(self._settings_btn)

        # Set initial active
        self._update_active(0)

    def _on_click(self, index: int) -> None:
        if index != self._current_index:
            self._current_index = index
            self._update_active(index)
            self.page_changed.emit(index)

    def _update_active(self, active_index: int) -> None:
        for i, btn in enumerate(self._buttons):
            btn.set_active(i == active_index)

    def set_page(self, index: int) -> None:
        """Programmatically change the active page."""
        self._current_index = index
        self._update_active(index)
