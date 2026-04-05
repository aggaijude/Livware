"""
toast.py — Toast notification popup widget.

Slides in from the top-right corner, auto-dismisses after a timeout,
with type-based coloring (success, warning, error, info).
"""

from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QLabel, QWidget, QHBoxLayout, QGraphicsOpacityEffect


TOAST_COLORS = {
    "success": ("#22c55e", "#052e16", "✅"),
    "warning": ("#eab308", "#422006", "⚠️"),
    "error":   ("#ef4444", "#450a0a", "❌"),
    "info":    ("#3b82f6", "#172554", "ℹ️"),
}


class Toast(QWidget):
    """Auto-dismissing toast notification that slides from top-right."""

    def __init__(
        self,
        message: str,
        toast_type: str = "info",
        duration_ms: int = 3000,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._duration = duration_ms
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedHeight(48)

        accent, bg, icon = TOAST_COLORS.get(toast_type, TOAST_COLORS["info"])

        # Container
        container = QWidget(self)
        container.setStyleSheet(
            f"background-color: {bg}; border: 1px solid {accent}; "
            f"border-radius: 10px; padding: 8px 16px;"
        )

        layout = QHBoxLayout(container)
        layout.setContentsMargins(14, 6, 14, 6)
        layout.setSpacing(10)

        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji", 14))
        icon_label.setStyleSheet("background: transparent; border: none;")
        layout.addWidget(icon_label)

        msg_label = QLabel(message)
        msg_label.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
        msg_label.setStyleSheet(f"color: {accent}; background: transparent; border: none;")
        layout.addWidget(msg_label)

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(container)

        # Opacity effect for fade-out
        self._opacity = QGraphicsOpacityEffect(self)
        self._opacity.setOpacity(1.0)
        self.setGraphicsEffect(self._opacity)

    def show_toast(self, parent_widget=None) -> None:
        """Position and animate the toast in."""
        if parent_widget:
            parent_geo = parent_widget.geometry()
            x = parent_geo.x() + parent_geo.width() - self.width() - 20
            y = parent_geo.y() + 20
        else:
            x = 100
            y = 40

        self.move(x, y - 40)
        self.show()

        # Slide in
        self._slide_anim = QPropertyAnimation(self, b"pos")
        self._slide_anim.setDuration(300)
        self._slide_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._slide_anim.setStartValue(QPoint(x, y - 40))
        self._slide_anim.setEndValue(QPoint(x, y))
        self._slide_anim.start()

        # Auto dismiss
        QTimer.singleShot(self._duration, self._dismiss)

    def _dismiss(self) -> None:
        """Fade out and close."""
        self._fade = QPropertyAnimation(self._opacity, b"opacity")
        self._fade.setDuration(300)
        self._fade.setStartValue(1.0)
        self._fade.setEndValue(0.0)
        self._fade.finished.connect(self.close)
        self._fade.start()
