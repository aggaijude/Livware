"""
settings.py — Settings page.

Dark/Light theme toggle, auto-quarantine mode toggle,
engine status display, and app info.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea,
)

from config import APP_NAME, APP_VERSION, load_settings, save_settings
from ui.widgets.toggle_switch import ToggleSwitch


class SettingRow(QFrame):
    """A single settings row with label, description, and toggle."""

    def __init__(
        self,
        title: str,
        description: str,
        checked: bool = False,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("card")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(16)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 13, QFont.Weight.DemiBold))
        title_label.setStyleSheet("background: transparent;")
        text_layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setFont(QFont("Segoe UI", 11))
        desc_label.setStyleSheet("color: #94a3b8; background: transparent;")
        desc_label.setWordWrap(True)
        text_layout.addWidget(desc_label)

        layout.addLayout(text_layout, 1)

        self.toggle = ToggleSwitch(checked)
        layout.addWidget(self.toggle)


class SettingsPage(QWidget):
    """Application settings page."""

    theme_changed = pyqtSignal(bool)     # True = dark
    mode_changed = pyqtSignal(bool)      # True = auto quarantine

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._settings = load_settings()
        self._setup_ui()

    def _setup_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # ── Title ──────────────────────────────────────────────────
        title = QLabel("Settings")
        title.setProperty("class", "heading")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel("Configure application behavior and appearance")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(subtitle)

        layout.addSpacing(8)

        # ── Appearance ─────────────────────────────────────────────
        appearance_label = QLabel("Appearance")
        appearance_label.setProperty("class", "subheading")
        appearance_label.setFont(QFont("Segoe UI", 15, QFont.Weight.DemiBold))
        layout.addWidget(appearance_label)

        self._theme_row = SettingRow(
            "🌙  Dark Mode",
            "Switch between dark and light themes. Dark mode is easier on the eyes.",
            checked=self._settings.get("dark_mode", True),
        )
        self._theme_row.toggle.toggled.connect(self._on_theme_toggle)
        layout.addWidget(self._theme_row)

        layout.addSpacing(12)

        # ── Scanning ───────────────────────────────────────────────
        scan_label = QLabel("Scanning")
        scan_label.setProperty("class", "subheading")
        scan_label.setFont(QFont("Segoe UI", 15, QFont.Weight.DemiBold))
        layout.addWidget(scan_label)

        self._auto_row = SettingRow(
            "⚡  Auto Quarantine",
            "Automatically quarantine detected malware without asking. "
            "When disabled, you will be prompted before quarantine.",
            checked=self._settings.get("auto_quarantine", False),
        )
        self._auto_row.toggle.toggled.connect(self._on_mode_toggle)
        layout.addWidget(self._auto_row)

        layout.addSpacing(16)

        # ── About ──────────────────────────────────────────────────
        about_label = QLabel("About")
        about_label.setProperty("class", "subheading")
        about_label.setFont(QFont("Segoe UI", 15, QFont.Weight.DemiBold))
        layout.addWidget(about_label)

        about_card = QFrame()
        about_card.setObjectName("card")
        about_layout = QVBoxLayout(about_card)
        about_layout.setContentsMargins(20, 16, 20, 16)
        about_layout.setSpacing(6)

        app_title = QLabel(f"🛡️  {APP_NAME}")
        app_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        app_title.setStyleSheet("background: transparent;")
        about_layout.addWidget(app_title)

        ver = QLabel(f"Version {APP_VERSION}")
        ver.setStyleSheet("color: #94a3b8; font-size: 12px; background: transparent;")
        about_layout.addWidget(ver)

        desc = QLabel(
            "AI Hybrid Antivirus System combining Machine Learning, "
            "ClamAV signature scanning, and YARA rule-based detection "
            "for comprehensive malware protection."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #64748b; font-size: 12px; background: transparent;")
        about_layout.addWidget(desc)

        stack_label = QLabel(
            "Tech Stack: Python · PyQt6 · LightGBM · pefile · ClamAV · YARA"
        )
        stack_label.setStyleSheet("color: #475569; font-size: 11px; background: transparent; margin-top: 8px;")
        about_layout.addWidget(stack_label)

        layout.addWidget(about_card)

        layout.addStretch()
        scroll.setWidget(content)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _on_theme_toggle(self, checked: bool) -> None:
        self._settings["dark_mode"] = checked
        save_settings(self._settings)
        self.theme_changed.emit(checked)

    def _on_mode_toggle(self, checked: bool) -> None:
        self._settings["auto_quarantine"] = checked
        save_settings(self._settings)
        self.mode_changed.emit(checked)

    def is_dark_mode(self) -> bool:
        return self._settings.get("dark_mode", True)

    def is_auto_quarantine(self) -> bool:
        return self._settings.get("auto_quarantine", False)
