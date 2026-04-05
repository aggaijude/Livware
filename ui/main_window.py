"""
main_window.py — Main application window.

Assembles sidebar navigation with a QStackedWidget of all pages.
Handles theme switching, inter-page navigation, quarantine actions,
and manages the scan engine + memory system.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QStackedWidget,
    QMessageBox,
)

from config import (
    APP_TITLE, WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT,
    WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT, load_settings,
)
from engine.scanner import Scanner
from memory.memory_manager import load_memory, update_scan_stats

from ui.sidebar import Sidebar
from ui.styles import DARK_THEME, LIGHT_THEME
from ui.widgets.toast import Toast
from ui.pages.dashboard import DashboardPage
from ui.pages.scan_file import ScanFilePage
from ui.pages.scan_folder import ScanFolderPage
from ui.pages.system_scan import SystemScanPage
from ui.pages.sandbox_view import SandboxViewPage
from ui.pages.quarantine_view import QuarantineViewPage
from ui.pages.logs_view import LogsViewPage
from ui.pages.settings import SettingsPage


class MainWindow(QMainWindow):
    """Main application window for Livware."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT)
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)

        # ── Core systems ────────────────────────────────────────────
        self._scanner = Scanner()
        self._settings = load_settings()
        self._dark_mode = self._settings.get("dark_mode", True)
        self._auto_quarantine = self._settings.get("auto_quarantine", False)

        # ── Build UI ────────────────────────────────────────────────
        self._setup_ui()
        self._connect_signals()
        self._apply_theme()
        self._refresh_dashboard()

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Sidebar ─────────────────────────────────────────────────
        self._sidebar = Sidebar()
        main_layout.addWidget(self._sidebar)

        # ── Stacked Widget for pages ────────────────────────────────
        self._stack = QStackedWidget()

        # Page 0: Dashboard
        self._dashboard = DashboardPage()
        self._stack.addWidget(self._dashboard)

        # Page 1: Scan File
        self._scan_file = ScanFilePage(self._scanner)
        self._stack.addWidget(self._scan_file)

        # Page 2: Scan Folder
        self._scan_folder = ScanFolderPage(self._scanner)
        self._stack.addWidget(self._scan_folder)

        # Page 3: System Scan
        self._system_scan = SystemScanPage(self._scanner)
        self._stack.addWidget(self._system_scan)

        # Page 4: Sandbox
        self._sandbox_view = SandboxViewPage()
        self._stack.addWidget(self._sandbox_view)

        # Page 5: Quarantine
        self._quarantine_view = QuarantineViewPage(self._scanner.quarantine)
        self._stack.addWidget(self._quarantine_view)

        # Page 6: Logs
        self._logs_view = LogsViewPage()
        self._stack.addWidget(self._logs_view)

        # Page 7: Settings
        self._settings_page = SettingsPage()
        self._stack.addWidget(self._settings_page)

        main_layout.addWidget(self._stack, 1)

    def _connect_signals(self) -> None:
        # Sidebar navigation
        self._sidebar.page_changed.connect(self._on_page_changed)

        # Dashboard quick actions
        self._dashboard.scan_file_requested.connect(lambda: self._navigate_to(1))
        self._dashboard.scan_folder_requested.connect(lambda: self._navigate_to(2))

        # Scan file signals
        self._scan_file.quarantine_requested.connect(self._handle_quarantine)
        self._scan_file.scan_completed.connect(self._on_file_scan_done)

        # Scan folder signals
        self._scan_folder.quarantine_requested.connect(self._handle_quarantine)
        self._scan_folder.scan_batch_completed.connect(self._on_folder_scan_done)

        # System scan signals
        self._system_scan.quarantine_requested.connect(self._handle_quarantine)
        self._system_scan.scan_batch_completed.connect(self._on_system_scan_done)

        # Quarantine view
        self._quarantine_view.items_changed.connect(self._refresh_dashboard)

        # Settings
        self._settings_page.theme_changed.connect(self._on_theme_changed)
        self._settings_page.mode_changed.connect(self._on_mode_changed)

    # ── Navigation ──────────────────────────────────────────────────

    def _on_page_changed(self, index: int) -> None:
        self._stack.setCurrentIndex(index)

    def _navigate_to(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        self._sidebar.set_page(index)

    # ── Theme ───────────────────────────────────────────────────────

    def _apply_theme(self) -> None:
        qss = DARK_THEME if self._dark_mode else LIGHT_THEME
        self.setStyleSheet(qss)

    def _on_theme_changed(self, dark: bool) -> None:
        self._dark_mode = dark
        self._apply_theme()

    def _on_mode_changed(self, auto: bool) -> None:
        self._auto_quarantine = auto

    # ── Scan result handlers ────────────────────────────────────────

    def _on_file_scan_done(self, result) -> None:
        malware = 1 if result.status == "MALWARE" else 0
        update_scan_stats(total_delta=1, malware_delta=malware)

        if result.status == "MALWARE":
            self._dashboard.set_threat_status(True)
            if self._auto_quarantine:
                self._do_quarantine(result)
        else:
            self._dashboard.set_threat_status(False)

        self._refresh_dashboard()
        self._show_toast(result)

    def _on_folder_scan_done(self, results: list) -> None:
        malware_count = sum(1 for r in results if r.status == "MALWARE")
        update_scan_stats(
            total_delta=len(results),
            malware_delta=malware_count,
        )

        if malware_count > 0:
            self._dashboard.set_threat_status(True)
            if self._auto_quarantine:
                for r in results:
                    if r.status == "MALWARE":
                        self._do_quarantine(r)
        else:
            self._dashboard.set_threat_status(False)

        self._refresh_dashboard()

    def _on_system_scan_done(self, results: list) -> None:
        """Handle system scan completion — same logic as folder scan."""
        self._on_folder_scan_done(results)

    # ── Quarantine ──────────────────────────────────────────────────

    def _handle_quarantine(self, result) -> None:
        if self._auto_quarantine:
            self._do_quarantine(result)
        else:
            reply = QMessageBox.question(
                self,
                "Quarantine File",
                f"Quarantine the file?\n\n"
                f"File: {result.file_name}\n"
                f"Status: {result.status}\n"
                f"Risk: {result.risk:.0%}\n"
                f"Source: {result.source}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._do_quarantine(result)

    def _do_quarantine(self, result) -> None:
        q_id = self._scanner.quarantine.quarantine(
            result.file_path,
            reason=result.details,
            source=result.source,
            risk=result.risk,
        )
        if q_id:
            update_scan_stats(quarantine_delta=1)
            self._refresh_dashboard()
            toast = Toast("File quarantined successfully", "success", 3000, self)
            toast.show_toast(self)
        else:
            toast = Toast("Failed to quarantine file", "error", 3000, self)
            toast.show_toast(self)

    # ── Dashboard ───────────────────────────────────────────────────

    def _refresh_dashboard(self) -> None:
        # Engine status
        engine_status = self._scanner.engine_status()
        # Add sandbox to engine status
        from engine.sandbox import SandboxAnalyzer
        sandbox = SandboxAnalyzer()
        engine_status["sandbox"] = sandbox.is_available()
        self._dashboard.update_engine_status(engine_status)

        # Stats from memory
        mem = load_memory()
        stats = mem.get("scan_stats", {})
        self._dashboard.update_stats(stats)

    # ── Toast ───────────────────────────────────────────────────────

    def _show_toast(self, result) -> None:
        type_map = {
            "SAFE": "success",
            "WARNING": "warning",
            "MALWARE": "error",
            "SUSPICIOUS": "warning",
            "ERROR": "info",
        }
        msg_map = {
            "SAFE": f"{result.file_name} is clean",
            "WARNING": f"{result.file_name} — review recommended",
            "MALWARE": f"MALWARE: {result.file_name}",
            "SUSPICIOUS": f"Suspicious: {result.file_name}",
            "ERROR": f"Error scanning {result.file_name}",
        }
        toast = Toast(
            msg_map.get(result.status, "Scan complete"),
            type_map.get(result.status, "info"),
            3500,
            self,
        )
        toast.show_toast(self)
