"""
main_window.py — Main application window.

Assembles sidebar navigation with a QStackedWidget of all pages.
Handles theme switching, inter-page navigation, quarantine actions,
and manages the scan engine + memory system.
"""

from PyQt6.QtCore import Qt, QThread
from PyQt6.QtGui import QFont, QIcon, QCloseEvent
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QStackedWidget,
    QMessageBox,
)
import os

from config import (
    APP_TITLE, WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT,
    WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT, load_settings, BUNDLE_DIR
)
from engine.scanner import Scanner, FileScanWorker
from engine.realtime_watcher import RealtimeWatcher
from engine.updater import FullUpdaterThread
from ui.tray_manager import TrayManager
from memory.memory_manager import load_memory, save_memory, update_scan_stats

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
        self._real_time_protection = self._settings.get("real_time_protection", True)
        self._auto_update = self._settings.get("auto_update", False)
        self._bg_workers = []

        # ── Build UI ────────────────────────────────────────────────
        self._setup_ui()
        self._setup_tray()
        self._setup_watcher()
        self._setup_updater()
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
        self._settings_page.realtime_changed.connect(self._apply_realtime_state)
        self._settings_page.auto_update_changed.connect(self._on_update_changed)

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

    # ── Background Features ─────────────────────────────────────────

    def _setup_tray(self) -> None:
        icon_path = os.path.join(BUNDLE_DIR, "logo.png")
        if not os.path.exists(icon_path):
            icon = QIcon()
        else:
            icon = QIcon(icon_path)
            
        self._tray_manager = TrayManager(icon, self)
        self._tray_manager.show_ui_requested.connect(self.showNormal)
        self._tray_manager.show_ui_requested.connect(self.activateWindow)
        self._tray_manager.quick_scan_requested.connect(lambda: self._navigate_to(2))
        self._tray_manager.toggle_protection_requested.connect(self._toggle_real_time_protection)
        self._tray_manager.exit_requested.connect(self._force_exit)
        self._tray_manager.update_protection_action(self._real_time_protection)

    def _setup_watcher(self) -> None:
        self._watcher = RealtimeWatcher()
        self._watcher.file_detected.connect(self._on_realtime_file_detected)
        
        if self._real_time_protection:
            self._watcher.start()
            
    def _setup_updater(self) -> None:
        self._updater_thread = None
        if self._auto_update:
            self._run_full_update()

    def _run_full_update(self) -> None:
        """Launch the combined ClamAV + YARA updater in a background thread."""
        if self._updater_thread is not None and self._updater_thread.isRunning():
            return  # Already running

        self._updater_thread = FullUpdaterThread(self)
        self._updater_thread.clamav_done.connect(self._on_clamav_update_done)
        self._updater_thread.yara_done.connect(self._on_yara_update_done)
        self._updater_thread.all_done.connect(self._on_all_updates_done)
        self._updater_thread.start()

    def _on_clamav_update_done(self, success: bool, message: str) -> None:
        if success:
            print(f"[main_window] ClamAV update: {message}")
            self._store_update_timestamp("clamav_last_updated")
        else:
            print(f"[main_window] ClamAV update failed: {message}")

    def _on_yara_update_done(self, success: bool, message: str) -> None:
        if success:
            print(f"[main_window] YARA update: {message}")
            self._store_update_timestamp("yara_last_updated")
            # Hot-reload YARA rules in memory without restart
            reloaded = self._scanner.yara.reload_rules()
            if reloaded:
                print("[main_window] YARA rules reloaded in memory.")
        else:
            print(f"[main_window] YARA update failed: {message}")

    def _on_all_updates_done(self, success: bool, summary: str) -> None:
        if success:
            toast = Toast("✅ Definitions updated successfully", "success", 4000, self)
        else:
            toast = Toast(f"⚠ Update partial: {summary}", "warning", 4000, self)
        toast.show_toast(self)
        self._refresh_dashboard()

    def _store_update_timestamp(self, key: str) -> None:
        """Persist an update timestamp into memory.json."""
        import time
        mem = load_memory()
        mem[key] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_memory(mem)

    def _toggle_real_time_protection(self):
        new_state = not self._real_time_protection
        self._settings_page._realtime_row.toggle.setChecked(new_state)

    def _apply_realtime_state(self, enabled: bool):
        self._real_time_protection = enabled
        self._tray_manager.update_protection_action(enabled)
        if enabled:
            self._watcher.start()
        else:
            self._watcher.stop()

    def _on_update_changed(self, enabled: bool):
        self._auto_update = enabled

    def _on_realtime_file_detected(self, file_path: str):
        thread = QThread()
        worker = FileScanWorker(self._scanner, file_path)
        worker.moveToThread(thread)
        
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_realtime_scan_done)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        
        self._bg_workers.append(thread)
        thread.finished.connect(lambda: self._remove_bg_worker(thread))
        thread.start()

    def _remove_bg_worker(self, thread):
        if thread in self._bg_workers:
            self._bg_workers.remove(thread)

    def _on_realtime_scan_done(self, result):
        self._on_file_scan_done(result)
        if result.status == "MALWARE":
            self._tray_manager.show_notification(
                "Threat Detected!", 
                f"Livware blocked a threat: {result.file_name}",
                is_threat=True
            )
        elif result.status == "WARNING" or result.status == "SUSPICIOUS":
            self._tray_manager.show_notification(
                "Suspicious File", 
                f"Livware flagged a file for review: {result.file_name}",
                is_threat=True
            )

    def closeEvent(self, event: QCloseEvent) -> None:
        """Override close event to minimize to tray instead of exiting."""
        event.ignore()
        self.hide()
        self._tray_manager.show_notification(
            "Livware is running in the background", 
            "The antivirus continues to protect your system."
        )

    def _force_exit(self) -> None:
        """Actually exit the application."""
        self._watcher.stop()
        from PyQt6.QtWidgets import QApplication
        QApplication.quit()
