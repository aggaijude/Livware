"""
dashboard.py — Dashboard / home page.

Shows system protection status, last scan summary, quick action buttons,
and engine availability indicators.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGridLayout, QSizePolicy, QScrollArea,
)


class EngineIndicator(QFrame):
    """Small widget showing an engine name and its status."""

    def __init__(self, name: str, available: bool, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(8)

        icon = "✅" if available else "❌"
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji", 12))
        icon_label.setStyleSheet("background: transparent;")
        layout.addWidget(icon_label)

        name_label = QLabel(name)
        name_label.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
        name_label.setStyleSheet("background: transparent;")
        layout.addWidget(name_label)

        status_text = "Active" if available else "Unavailable"
        status_color = "#22c55e" if available else "#ef4444"
        status_label = QLabel(status_text)
        status_label.setFont(QFont("Segoe UI", 10))
        status_label.setStyleSheet(f"color: {status_color}; background: transparent;")
        layout.addWidget(status_label)

        layout.addStretch()


class StatCard(QFrame):
    """Small stat card with a number and label."""

    def __init__(self, value: str, label: str, color: str = "#3b82f6", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        val_label = QLabel(value)
        val_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        val_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_label.setStyleSheet(f"color: {color}; background: transparent;")
        layout.addWidget(val_label)

        txt_label = QLabel(label)
        txt_label.setFont(QFont("Segoe UI", 10))
        txt_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        txt_label.setStyleSheet("color: #94a3b8; background: transparent;")
        layout.addWidget(txt_label)

        self._val_label = val_label

    def set_value(self, value: str) -> None:
        self._val_label.setText(value)


class DashboardPage(QWidget):
    """Main dashboard page."""

    scan_file_requested = pyqtSignal()
    scan_folder_requested = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._threats_detected = False
        self._setup_ui()

    def _setup_ui(self) -> None:
        # Scroll wrapper
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)

        # ── Page title ──────────────────────────────────────────────
        title = QLabel("Dashboard")
        title.setProperty("class", "heading")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        # ── Status Card ─────────────────────────────────────────────
        self._status_card = QFrame()
        self._status_card.setObjectName("status_card_safe")
        status_layout = QHBoxLayout(self._status_card)
        status_layout.setContentsMargins(24, 20, 24, 20)
        status_layout.setSpacing(16)

        self._status_icon = QLabel("🛡️")
        self._status_icon.setFont(QFont("Segoe UI Emoji", 36))
        self._status_icon.setStyleSheet("background: transparent;")
        status_layout.addWidget(self._status_icon)

        status_text_layout = QVBoxLayout()
        status_text_layout.setSpacing(4)

        self._status_title = QLabel("System Protected")
        self._status_title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        self._status_title.setStyleSheet("color: #22c55e; background: transparent;")
        status_text_layout.addWidget(self._status_title)

        self._status_sub = QLabel("All engines are running. No threats detected.")
        self._status_sub.setFont(QFont("Segoe UI", 12))
        self._status_sub.setStyleSheet("color: #94a3b8; background: transparent;")
        status_text_layout.addWidget(self._status_sub)

        status_layout.addLayout(status_text_layout, 1)
        layout.addWidget(self._status_card)

        # ── Stats Grid ──────────────────────────────────────────────
        stats_grid = QHBoxLayout()
        stats_grid.setSpacing(14)

        self._stat_total = StatCard("0", "Total Scans", "#3b82f6")
        self._stat_malware = StatCard("0", "Threats Found", "#ef4444")
        self._stat_quarantined = StatCard("0", "Quarantined", "#eab308")
        self._stat_safe = StatCard("—", "Last Scan", "#22c55e")

        stats_grid.addWidget(self._stat_total)
        stats_grid.addWidget(self._stat_malware)
        stats_grid.addWidget(self._stat_quarantined)
        stats_grid.addWidget(self._stat_safe)

        layout.addLayout(stats_grid)

        # ── Quick Actions ───────────────────────────────────────────
        actions_label = QLabel("Quick Actions")
        actions_label.setProperty("class", "subheading")
        actions_label.setFont(QFont("Segoe UI", 15, QFont.Weight.DemiBold))
        layout.addWidget(actions_label)

        actions_row = QHBoxLayout()
        actions_row.setSpacing(14)

        btn_file = QPushButton("📄  Scan File")
        btn_file.setProperty("class", "primary")
        btn_file.setFont(QFont("Segoe UI", 13, QFont.Weight.DemiBold))
        btn_file.setFixedHeight(50)
        btn_file.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_file.clicked.connect(self.scan_file_requested.emit)

        btn_folder = QPushButton("📁  Scan Folder")
        btn_folder.setProperty("class", "primary")
        btn_folder.setFont(QFont("Segoe UI", 13, QFont.Weight.DemiBold))
        btn_folder.setFixedHeight(50)
        btn_folder.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_folder.clicked.connect(self.scan_folder_requested.emit)

        actions_row.addWidget(btn_file)
        actions_row.addWidget(btn_folder)
        layout.addLayout(actions_row)

        # ── Engine Status ───────────────────────────────────────────
        engine_label = QLabel("Detection Engines")
        engine_label.setProperty("class", "subheading")
        engine_label.setFont(QFont("Segoe UI", 15, QFont.Weight.DemiBold))
        layout.addWidget(engine_label)

        self._engines_layout = QVBoxLayout()
        self._engines_layout.setSpacing(6)
        layout.addLayout(self._engines_layout)

        layout.addStretch()

        scroll.setWidget(content)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def update_engine_status(self, status: dict) -> None:
        """Update engine availability indicators."""
        # Clear existing
        while self._engines_layout.count():
            child = self._engines_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        engine_names = {
            "ml": "Machine Learning Engine",
            "clamav": "ClamAV Signature Scanner",
            "yara": "YARA Rule Engine",
        }
        for key, name in engine_names.items():
            indicator = EngineIndicator(name, status.get(key, False))
            self._engines_layout.addWidget(indicator)

    def update_stats(self, stats: dict) -> None:
        """Update dashboard statistics."""
        self._stat_total.set_value(str(stats.get("total_scans", 0)))
        self._stat_malware.set_value(str(stats.get("malware_found", 0)))
        self._stat_quarantined.set_value(str(stats.get("files_quarantined", 0)))
        last_scan = stats.get("last_scan_date", "—")
        if last_scan:
            # Show just the date part
            self._stat_safe.set_value(last_scan[:10] if len(last_scan) > 10 else last_scan)
        else:
            self._stat_safe.set_value("—")

    def set_threat_status(self, threats: bool) -> None:
        """Toggle between protected and threat-detected states."""
        self._threats_detected = threats
        if threats:
            self._status_card.setObjectName("status_card_danger")
            self._status_title.setText("⚠ Threats Detected")
            self._status_title.setStyleSheet("color: #ef4444; background: transparent;")
            self._status_sub.setText("Malware has been detected. Review and quarantine threats.")
            self._status_icon.setText("🚨")
        else:
            self._status_card.setObjectName("status_card_safe")
            self._status_title.setText("System Protected")
            self._status_title.setStyleSheet("color: #22c55e; background: transparent;")
            self._status_sub.setText("All engines are running. No threats detected.")
            self._status_icon.setText("🛡️")
        # Force re-style
        self._status_card.style().unpolish(self._status_card)
        self._status_card.style().polish(self._status_card)
