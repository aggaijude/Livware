"""
config.py — Application-wide configuration & path management.

Centralizes all constants, directory paths, and default settings.
Auto-creates required directories on import.
"""

import os
import sys
import json
import shutil

# ──────────────────────────── Base Paths ────────────────────────────

if getattr(sys, 'frozen', False):
    # PyInstaller bundles the environment here temporarily:
    BUNDLE_DIR = sys._MEIPASS
    # The actual .exe file directory is here:
    APP_DIR = os.path.dirname(sys.executable)
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))
    APP_DIR = BUNDLE_DIR

# Static bundled assets
MODELS_DIR = os.path.join(BUNDLE_DIR, "models")
RULES_DIR = os.path.join(BUNDLE_DIR, "rules")

# Dynamic user data / configs (persisted outside the temp folder)
QUARANTINE_DIR = os.path.join(APP_DIR, "quarantine")
LOGS_DIR = os.path.join(APP_DIR, "logs")
MEMORY_DIR = os.path.join(APP_DIR, "memory")

# ──────────────────────────── File Paths ────────────────────────────

MODEL_PATH = os.path.join(MODELS_DIR, "malware_model.pkl")
YARA_RULES_PATH = os.path.join(RULES_DIR, "rules.yar")
QUARANTINE_META_PATH = os.path.join(QUARANTINE_DIR, "metadata.json")
SCAN_LOG_PATH = os.path.join(LOGS_DIR, "scan_log.txt")
MEMORY_FILE_PATH = os.path.join(APP_DIR, "memory.json")
SETTINGS_FILE_PATH = os.path.join(APP_DIR, "settings.json")

# ──────────────────────────── Feature Config ────────────────────────

FEATURE_VECTOR_SIZE = 16          # Total features expected by ML model
NUM_HEADER_FEATURES = 10          # PE header-derived features
NUM_ENTROPY_FEATURES = 6          # Per-section entropy slots (pad/truncate)

# ──────────────────────────── ML Thresholds ─────────────────────────

ML_MALWARE_THRESHOLD = 0.7
ML_WARNING_THRESHOLD = 0.6

# ──────────────────────────── Scan Config ───────────────────────────

SCAN_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".com", ".bat", ".cmd"}
CLAMAV_TIMEOUT = 30               # seconds per file
SCAN_THREAD_COUNT = 1             # sequential scanning for stability

# ──────────────────────────── UI Constants ──────────────────────────

APP_NAME = "Livware"
APP_VERSION = "1.0.0"
APP_TITLE = f"{APP_NAME} — AI Hybrid Antivirus Engine"
WINDOW_MIN_WIDTH = 960
WINDOW_MIN_HEIGHT = 640
WINDOW_DEFAULT_WIDTH = 1200
WINDOW_DEFAULT_HEIGHT = 800
SIDEBAR_WIDTH = 220

# ──────────────────────────── ClamAV Detection ──────────────────────

CLAMAV_INSTALL_DIR = os.path.join(APP_DIR, "clamav_install", "clamav-1.4.2.win.x64")
CLAMAV_DB_PATH = os.path.join(CLAMAV_INSTALL_DIR, "database")

CLAMAV_SEARCH_PATHS = [
    os.path.join(CLAMAV_INSTALL_DIR, "clamscan.exe"),
    r"C:\Program Files\ClamAV\clamscan.exe",
    r"C:\Program Files (x86)\ClamAV\clamscan.exe",
    r"C:\ClamAV\clamscan.exe",
]


def find_clamav() -> str | None:
    """Locate clamscan.exe on the system."""
    # Check if it's on PATH
    clamscan = shutil.which("clamscan")
    if clamscan:
        return clamscan
    # Check common install paths
    for path in CLAMAV_SEARCH_PATHS:
        if os.path.isfile(path):
            return path
    return None


CLAMAV_PATH = find_clamav()

# ──────────────────────────── Settings ──────────────────────────────

DEFAULT_SETTINGS = {
    "dark_mode": True,
    "auto_quarantine": False,
}


def load_settings() -> dict:
    """Load settings from disk, falling back to defaults."""
    if os.path.isfile(SETTINGS_FILE_PATH):
        try:
            with open(SETTINGS_FILE_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
            merged = {**DEFAULT_SETTINGS, **saved}
            return merged
        except Exception:
            pass
    return dict(DEFAULT_SETTINGS)


def save_settings(settings: dict) -> None:
    """Persist settings to disk."""
    try:
        with open(SETTINGS_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"[config] Failed to save settings: {e}")


# ──────────────────────────── Directory Bootstrap ───────────────────

def _ensure_dirs():
    """Create required directories if they don't exist."""
    for d in [MODELS_DIR, RULES_DIR, QUARANTINE_DIR, LOGS_DIR]:
        os.makedirs(d, exist_ok=True)


_ensure_dirs()
