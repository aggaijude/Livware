"""
tray_manager.py — System tray integration.

Allows the application to run silently in the background, 
manage notifications, and provides quick actions via a tray context menu.
"""

from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import QObject, pyqtSignal

class TrayManager(QObject):
    
    show_ui_requested = pyqtSignal()
    quick_scan_requested = pyqtSignal()
    toggle_protection_requested = pyqtSignal()
    exit_requested = pyqtSignal()

    def __init__(self, icon: QIcon, parent=None):
        super().__init__(parent)
        self._tray = QSystemTrayIcon(icon, parent)
        self._tray.setToolTip("Livware Antivirus")
        self._tray.activated.connect(self._on_tray_activated)
        
        self._menu = QMenu()
        self._menu.setStyleSheet("QMenu { font-size: 13px; margin: 4px; }")
        
        # Actions
        self._action_open = QAction("Open Livware", self)
        self._action_open.triggered.connect(self.show_ui_requested.emit)
        
        self._action_scan = QAction("Quick Scan", self)
        self._action_scan.triggered.connect(self.quick_scan_requested.emit)

        self._action_protection = QAction("Disable Protection", self)
        self._action_protection.triggered.connect(self.toggle_protection_requested.emit)
        
        self._action_exit = QAction("Exit", self)
        self._action_exit.triggered.connect(self.exit_requested.emit)
        
        self._menu.addAction(self._action_open)
        self._menu.addAction(self._action_scan)
        self._menu.addSeparator()
        self._menu.addAction(self._action_protection)
        self._menu.addSeparator()
        self._menu.addAction(self._action_exit)
        
        self._tray.setContextMenu(self._menu)
        self._tray.show()
        
    def update_protection_action(self, is_enabled: bool):
        """Update context menu text based on current protection state."""
        if is_enabled:
            self._action_protection.setText("Disable Protection")
        else:
            self._action_protection.setText("Enable Protection")

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_ui_requested.emit()

    def show_notification(self, title: str, message: str, is_threat: bool = False):
        """Show a system notification via the tray icon."""
        icon_type = QSystemTrayIcon.MessageIcon.Warning if is_threat else QSystemTrayIcon.MessageIcon.Information
        self._tray.showMessage(title, message, icon_type, 4000)
