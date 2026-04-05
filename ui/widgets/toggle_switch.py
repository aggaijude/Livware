"""
toggle_switch.py — Modern animated toggle switch widget.

A custom-painted toggle switch inspired by iOS/Android design,
with smooth QPropertyAnimation transitions.
"""

from PyQt6.QtCore import (
    Qt, QPropertyAnimation, QEasingCurve, QRectF, pyqtProperty, pyqtSignal, QSize
)
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush
from PyQt6.QtWidgets import QWidget


class ToggleSwitch(QWidget):
    """Custom animated toggle switch widget."""

    toggled = pyqtSignal(bool)

    def __init__(self, checked: bool = False, parent=None) -> None:
        super().__init__(parent)
        self._checked = checked
        self._handle_position = 1.0 if checked else 0.0

        # Colors
        self._track_on = QColor("#3b82f6")
        self._track_off = QColor("#475569")
        self._handle_color = QColor("#ffffff")

        # Sizing
        self._track_width = 44
        self._track_height = 24
        self._handle_size = 18
        self._handle_margin = 3

        self.setFixedSize(self._track_width + 4, self._track_height + 4)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        # Animation
        self._animation = QPropertyAnimation(self, b"handle_position")
        self._animation.setDuration(200)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutCubic)

    # ── Property for animation ──────────────────────────────────────

    @pyqtProperty(float)
    def handle_position(self) -> float:
        return self._handle_position

    @handle_position.setter
    def handle_position(self, value: float) -> None:
        self._handle_position = value
        self.update()

    # ── Sizing ──────────────────────────────────────────────────────

    def sizeHint(self) -> QSize:
        return QSize(self._track_width + 4, self._track_height + 4)

    # ── Events ──────────────────────────────────────────────────────

    def mousePressEvent(self, event) -> None:
        self._checked = not self._checked
        self._animation.stop()
        self._animation.setStartValue(self._handle_position)
        self._animation.setEndValue(1.0 if self._checked else 0.0)
        self._animation.start()
        self.toggled.emit(self._checked)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # ── Track ───────────────────────────────────────────────────
        track_rect = QRectF(2, 2, self._track_width, self._track_height)
        track_radius = self._track_height / 2

        # Interpolate track color
        t = self._handle_position
        r = int(self._track_off.red() + t * (self._track_on.red() - self._track_off.red()))
        g = int(self._track_off.green() + t * (self._track_on.green() - self._track_off.green()))
        b = int(self._track_off.blue() + t * (self._track_on.blue() - self._track_off.blue()))
        track_color = QColor(r, g, b)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(track_color))
        painter.drawRoundedRect(track_rect, track_radius, track_radius)

        # ── Handle ──────────────────────────────────────────────────
        x_start = 2 + self._handle_margin
        x_end = 2 + self._track_width - self._handle_size - self._handle_margin
        x = x_start + self._handle_position * (x_end - x_start)
        y = 2 + (self._track_height - self._handle_size) / 2

        # Subtle shadow
        shadow_color = QColor(0, 0, 0, 40)
        painter.setBrush(QBrush(shadow_color))
        painter.drawEllipse(QRectF(x + 1, y + 1, self._handle_size, self._handle_size))

        # Handle
        painter.setBrush(QBrush(self._handle_color))
        painter.drawEllipse(QRectF(x, y, self._handle_size, self._handle_size))

        painter.end()

    # ── Public API ──────────────────────────────────────────────────

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, checked: bool) -> None:
        if self._checked != checked:
            self._checked = checked
            self._handle_position = 1.0 if checked else 0.0
            self.update()
