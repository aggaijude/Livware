"""
styles.py — Complete QSS stylesheet definitions for Dark and Light themes.

Defines a comprehensive, production-grade stylesheet for every widget type
used in the antivirus application. Both themes share the same structure
for consistency.
"""

# ──────────────────────────── Color Palettes ────────────────────────

DARK = {
    "bg_primary": "#0f172a",
    "bg_secondary": "#1e293b",
    "bg_tertiary": "#334155",
    "bg_card": "#1e293b",
    "bg_input": "#0f172a",
    "bg_sidebar": "#0b1120",
    "text_primary": "#e2e8f0",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "accent": "#3b82f6",
    "accent_hover": "#2563eb",
    "accent_pressed": "#1d4ed8",
    "border": "#334155",
    "border_light": "#1e293b",
    "safe": "#22c55e",
    "safe_bg": "#052e16",
    "warning": "#eab308",
    "warning_bg": "#422006",
    "danger": "#ef4444",
    "danger_bg": "#450a0a",
    "info": "#3b82f6",
    "info_bg": "#172554",
    "shadow": "rgba(0, 0, 0, 0.3)",
    "scrollbar": "#334155",
    "scrollbar_hover": "#475569",
}

LIGHT = {
    "bg_primary": "#f1f5f9",
    "bg_secondary": "#ffffff",
    "bg_tertiary": "#e2e8f0",
    "bg_card": "#ffffff",
    "bg_input": "#f8fafc",
    "bg_sidebar": "#ffffff",
    "text_primary": "#0f172a",
    "text_secondary": "#475569",
    "text_muted": "#94a3b8",
    "accent": "#2563eb",
    "accent_hover": "#1d4ed8",
    "accent_pressed": "#1e40af",
    "border": "#e2e8f0",
    "border_light": "#f1f5f9",
    "safe": "#16a34a",
    "safe_bg": "#dcfce7",
    "warning": "#ca8a04",
    "warning_bg": "#fef9c3",
    "danger": "#dc2626",
    "danger_bg": "#fee2e2",
    "info": "#2563eb",
    "info_bg": "#dbeafe",
    "shadow": "rgba(0, 0, 0, 0.08)",
    "scrollbar": "#cbd5e1",
    "scrollbar_hover": "#94a3b8",
}


def _build_stylesheet(c: dict) -> str:
    """Generate the full QSS from a color palette dictionary."""
    return f"""
/* ═══════════════════════ Global ═══════════════════════ */
QWidget {{
    background-color: {c['bg_primary']};
    color: {c['text_primary']};
    font-family: 'Segoe UI', 'Inter', 'Roboto', sans-serif;
    font-size: 13px;
    border: none;
    outline: none;
}}

QMainWindow {{
    background-color: {c['bg_primary']};
}}

/* ═══════════════════════ Labels ═══════════════════════ */
QLabel {{
    background: transparent;
    padding: 0px;
    border: none;
}}

QLabel[class="heading"] {{
    font-size: 22px;
    font-weight: 700;
    color: {c['text_primary']};
}}

QLabel[class="subheading"] {{
    font-size: 15px;
    font-weight: 600;
    color: {c['text_primary']};
}}

QLabel[class="caption"] {{
    font-size: 11px;
    color: {c['text_muted']};
}}

QLabel[class="status-safe"] {{
    color: {c['safe']};
    font-weight: 700;
    font-size: 14px;
}}

QLabel[class="status-warning"] {{
    color: {c['warning']};
    font-weight: 700;
    font-size: 14px;
}}

QLabel[class="status-danger"] {{
    color: {c['danger']};
    font-weight: 700;
    font-size: 14px;
}}

/* ═══════════════════════ Buttons ═══════════════════════ */
QPushButton {{
    background-color: {c['bg_secondary']};
    color: {c['text_primary']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 13px;
    font-weight: 600;
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: {c['bg_tertiary']};
    border-color: {c['accent']};
}}

QPushButton:pressed {{
    background-color: {c['accent_pressed']};
    color: white;
}}

QPushButton:disabled {{
    background-color: {c['bg_secondary']};
    color: {c['text_muted']};
    border-color: {c['border_light']};
}}

QPushButton[class="primary"] {{
    background-color: {c['accent']};
    color: white;
    border: none;
}}

QPushButton[class="primary"]:hover {{
    background-color: {c['accent_hover']};
}}

QPushButton[class="primary"]:pressed {{
    background-color: {c['accent_pressed']};
}}

QPushButton[class="danger"] {{
    background-color: {c['danger']};
    color: white;
    border: none;
}}

QPushButton[class="danger"]:hover {{
    background-color: #b91c1c;
}}

QPushButton[class="success"] {{
    background-color: {c['safe']};
    color: white;
    border: none;
}}

QPushButton[class="success"]:hover {{
    background-color: #16a34a;
}}

/* ═══════════════════════ Sidebar ═══════════════════════ */
QWidget#sidebar {{
    background-color: {c['bg_sidebar']};
    border-right: 1px solid {c['border']};
}}

QPushButton#sidebar_btn {{
    background: transparent;
    color: {c['text_secondary']};
    border: none;
    border-radius: 8px;
    padding: 12px 16px;
    text-align: left;
    font-size: 13px;
    font-weight: 600;
}}

QPushButton#sidebar_btn:hover {{
    background-color: {c['bg_secondary']};
    color: {c['text_primary']};
}}

QPushButton#sidebar_btn[active="true"] {{
    background-color: {c['accent']};
    color: white;
}}

/* ═══════════════════════ Cards ═══════════════════════ */
QFrame#card {{
    background-color: {c['bg_card']};
    border: 1px solid {c['border']};
    border-radius: 12px;
    padding: 20px;
}}

QFrame#card:hover {{
    border-color: {c['accent']};
}}

QFrame#status_card_safe {{
    background-color: {c['safe_bg']};
    border: 1px solid {c['safe']};
    border-radius: 12px;
    padding: 24px;
}}

QFrame#status_card_danger {{
    background-color: {c['danger_bg']};
    border: 1px solid {c['danger']};
    border-radius: 12px;
    padding: 24px;
}}

QFrame#result_card {{
    background-color: {c['bg_card']};
    border: 1px solid {c['border']};
    border-radius: 10px;
    padding: 14px 18px;
}}

QFrame#result_card:hover {{
    border-color: {c['accent']};
}}

/* ═══════════════════════ Progress Bar ═══════════════════════ */
QProgressBar {{
    background-color: {c['bg_tertiary']};
    border: none;
    border-radius: 6px;
    text-align: center;
    color: {c['text_primary']};
    font-size: 11px;
    font-weight: 600;
    min-height: 14px;
    max-height: 14px;
}}

QProgressBar::chunk {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {c['accent']},
        stop:1 #8b5cf6
    );
    border-radius: 6px;
}}

/* ═══════════════════════ Scroll Area ═══════════════════════ */
QScrollArea {{
    background: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background: transparent;
}}

QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 4px 2px;
}}

QScrollBar::handle:vertical {{
    background-color: {c['scrollbar']};
    border-radius: 4px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {c['scrollbar_hover']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: transparent;
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    margin: 2px 4px;
}}

QScrollBar::handle:horizontal {{
    background-color: {c['scrollbar']};
    border-radius: 4px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {c['scrollbar_hover']};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* ═══════════════════════ Text Edit / Plain Text ═══════════════════════ */
QPlainTextEdit, QTextEdit {{
    background-color: {c['bg_input']};
    color: {c['text_primary']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 10px;
    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: {c['accent']};
    selection-color: white;
}}

/* ═══════════════════════ Line Edit ═══════════════════════ */
QLineEdit {{
    background-color: {c['bg_input']};
    color: {c['text_primary']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
    selection-background-color: {c['accent']};
}}

QLineEdit:focus {{
    border-color: {c['accent']};
}}

/* ═══════════════════════ Combo Box ═══════════════════════ */
QComboBox {{
    background-color: {c['bg_input']};
    color: {c['text_primary']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
}}

QComboBox:hover {{
    border-color: {c['accent']};
}}

QComboBox::drop-down {{
    border: none;
    width: 30px;
}}

QComboBox QAbstractItemView {{
    background-color: {c['bg_secondary']};
    color: {c['text_primary']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    selection-background-color: {c['accent']};
    selection-color: white;
    padding: 4px;
}}

/* ═══════════════════════ Tooltips ═══════════════════════ */
QToolTip {{
    background-color: {c['bg_secondary']};
    color: {c['text_primary']};
    border: 1px solid {c['border']};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}}

/* ═══════════════════════ Menu ═══════════════════════ */
QMenu {{
    background-color: {c['bg_secondary']};
    color: {c['text_primary']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 4px;
}}

QMenu::item:selected {{
    background-color: {c['accent']};
    color: white;
    border-radius: 4px;
}}

/* ═══════════════════════ Tab Widget ═══════════════════════ */
QTabWidget::pane {{
    border: 1px solid {c['border']};
    border-radius: 8px;
    background-color: {c['bg_primary']};
}}

QTabBar::tab {{
    background-color: {c['bg_secondary']};
    color: {c['text_secondary']};
    padding: 8px 16px;
    border: 1px solid {c['border']};
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 2px;
}}

QTabBar::tab:selected {{
    background-color: {c['bg_primary']};
    color: {c['accent']};
    font-weight: 600;
}}

/* ═══════════════════════ Separator ═══════════════════════ */
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {c['border']};
    max-height: 1px;
}}
"""


# ──────────────────────────── Public API ────────────────────────────

DARK_THEME = _build_stylesheet(DARK)
LIGHT_THEME = _build_stylesheet(LIGHT)

STATUS_COLORS = {
    "SAFE": DARK["safe"],
    "WARNING": DARK["warning"],
    "MALWARE": DARK["danger"],
    "SUSPICIOUS": DARK["warning"],
    "ERROR": DARK["text_muted"],
}

STATUS_COLORS_LIGHT = {
    "SAFE": LIGHT["safe"],
    "WARNING": LIGHT["warning"],
    "MALWARE": LIGHT["danger"],
    "SUSPICIOUS": LIGHT["warning"],
    "ERROR": LIGHT["text_muted"],
}


def get_status_color(status: str, dark: bool = True) -> str:
    """Get the hex color for a status label."""
    palette = STATUS_COLORS if dark else STATUS_COLORS_LIGHT
    return palette.get(status, "#94a3b8")
