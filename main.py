"""
main.py — Application entry point for LivKid AV.

Initializes the Qt application, loads the theme, boots the project
memory system, and launches the main window.
"""

import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt

from config import APP_TITLE, load_settings, BUNDLE_DIR
from memory.memory_manager import load_memory, get_summary, set_focus
from ui.main_window import MainWindow
from ui.styles import DARK_THEME, LIGHT_THEME


def main() -> None:
    # ── Boot memory system ──────────────────────────────────────────
    print("\n" + "=" * 50)
    print("  🛡️  Livware — AI Hybrid Antivirus System")
    print("=" * 50)

    mem = load_memory()
    set_focus("Application running")
    print(get_summary())
    print()

    # ── Create Qt Application ───────────────────────────────────────
    app = QApplication(sys.argv)
    app.setApplicationName("Livware")
    app.setOrganizationName("Livware")
    
    # Set Window Icon
    icon_path = os.path.join(BUNDLE_DIR, "logo.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    # High DPI support
    app.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    # ── Font ────────────────────────────────────────────────────────
    font = QFont("Segoe UI", 10)
    font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    app.setFont(font)

    # ── Apply Theme ─────────────────────────────────────────────────
    settings = load_settings()
    if settings.get("dark_mode", True):
        app.setStyleSheet(DARK_THEME)
    else:
        app.setStyleSheet(LIGHT_THEME)

    # ── Launch Window ───────────────────────────────────────────────
    window = MainWindow()
    window.show()

    print("[main] Application started. Ready to scan.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
