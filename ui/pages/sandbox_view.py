"""
sandbox_view.py — Sandbox analysis page.

Provides a file picker, "Run in Sandbox" button, and displays a
comprehensive behavioral analysis report with risk scoring.
"""

from PyQt6.QtCore import Qt, QThread
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QFileDialog, QScrollArea, QSizePolicy,
)

from engine.sandbox import SandboxAnalyzer, SandboxReport, SandboxWorker


SEVERITY_COLORS = {
    "low": "#94a3b8",
    "medium": "#eab308",
    "high": "#f97316",
    "critical": "#ef4444",
}

RISK_COLORS = {
    "SAFE": "#22c55e",
    "LOW": "#3b82f6",
    "MEDIUM": "#eab308",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444",
}


class BehaviorCard(QFrame):
    """Card for a single behavior flag."""

    def __init__(self, category: str, detail: str, severity: str, parent=None):
        super().__init__(parent)
        self.setObjectName("result_card")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        color = SEVERITY_COLORS.get(severity, "#94a3b8")

        bar = QFrame()
        bar.setFixedWidth(4)
        bar.setStyleSheet(f"background-color: {color}; border-radius: 2px; margin: 3px 0px;")
        layout.addWidget(bar)

        content = QVBoxLayout()
        content.setContentsMargins(12, 8, 12, 8)
        content.setSpacing(2)

        row = QHBoxLayout()
        cat_label = QLabel(category)
        cat_label.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
        cat_label.setStyleSheet("background: transparent;")
        row.addWidget(cat_label)
        row.addStretch()

        badge = QLabel(f" {severity.upper()} ")
        badge.setStyleSheet(
            f"background-color: {color}; color: white; border-radius: 3px; "
            f"padding: 1px 8px; font-size: 10px; font-weight: 700;"
        )
        row.addWidget(badge)
        content.addLayout(row)

        det_label = QLabel(detail)
        det_label.setStyleSheet("color: #94a3b8; font-size: 11px; background: transparent;")
        det_label.setWordWrap(True)
        content.addWidget(det_label)

        layout.addLayout(content, 1)
        self.setMinimumHeight(48)


class SandboxViewPage(QWidget):
    """Sandbox behavioral analysis page."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._analyzer = SandboxAnalyzer()
        self._selected_file: str | None = None
        self._thread: QThread | None = None
        self._worker: SandboxWorker | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        # ── Title ───────────────────────────────────────────────────
        title = QLabel("Sandbox Analysis")
        title.setProperty("class", "heading")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel(
            "Run files in a safe static sandbox to analyze behavior without execution"
        )
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(subtitle)

        layout.addSpacing(4)

        # ── File Selection ──────────────────────────────────────────
        pick_card = QFrame()
        pick_card.setObjectName("card")
        pick_layout = QHBoxLayout(pick_card)
        pick_layout.setContentsMargins(16, 14, 16, 14)
        pick_layout.setSpacing(12)

        self._file_label = QLabel("No file selected")
        self._file_label.setFont(QFont("Segoe UI", 12))
        self._file_label.setStyleSheet("color: #64748b; background: transparent;")
        self._file_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        pick_layout.addWidget(self._file_label)

        browse_btn = QPushButton("📂  Browse")
        browse_btn.setProperty("class", "primary")
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.setFixedHeight(38)
        browse_btn.clicked.connect(self._browse)
        pick_layout.addWidget(browse_btn)

        layout.addWidget(pick_card)

        # ── Analyze Button ──────────────────────────────────────────
        self._analyze_btn = QPushButton("🧪  Run in Sandbox")
        self._analyze_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._analyze_btn.setFixedHeight(46)
        self._analyze_btn.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._analyze_btn.setEnabled(False)
        self._analyze_btn.setStyleSheet(
            "background-color: #7c3aed; color: white; border: none; "
            "border-radius: 8px; font-weight: 700; font-size: 14px;"
        )
        self._analyze_btn.clicked.connect(self._start_analysis)
        layout.addWidget(self._analyze_btn)

        # ── Status ──────────────────────────────────────────────────
        self._status_label = QLabel("")
        self._status_label.setFont(QFont("Segoe UI", 12))
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setStyleSheet("color: #94a3b8;")
        layout.addWidget(self._status_label)

        # ── Report Scroll Area ──────────────────────────────────────
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)

        self._report_widget = QWidget()
        self._report_layout = QVBoxLayout(self._report_widget)
        self._report_layout.setContentsMargins(0, 0, 0, 0)
        self._report_layout.setSpacing(8)
        self._report_layout.addStretch()

        self._scroll.setWidget(self._report_widget)
        layout.addWidget(self._scroll, 1)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File for Sandbox Analysis", "",
            "Executable Files (*.exe *.dll *.scr *.sys *.com);;All Files (*.*)",
        )
        if path:
            self._selected_file = path
            fname = path.split("/")[-1].split("\\")[-1]
            self._file_label.setText(f"📄 {fname}")
            self._file_label.setStyleSheet("color: #e2e8f0; font-weight: 600; background: transparent;")
            self._analyze_btn.setEnabled(True)

    def _start_analysis(self) -> None:
        if not self._selected_file:
            return

        self._clear_report()
        self._analyze_btn.setEnabled(False)
        self._status_label.setText("🧪 Analyzing in sandbox... Please wait")
        self._status_label.setStyleSheet("color: #7c3aed;")

        self._thread = QThread()
        self._worker = SandboxWorker(self._analyzer, self._selected_file)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _on_done(self, report: SandboxReport) -> None:
        self._analyze_btn.setEnabled(True)

        color = RISK_COLORS.get(report.risk_level, "#94a3b8")
        self._status_label.setText(
            f"Analysis complete — Risk: {report.risk_level} ({report.risk_score:.0%})"
        )
        self._status_label.setStyleSheet(f"color: {color}; font-weight: 600;")

        self._render_report(report)

    def _on_error(self, msg: str) -> None:
        self._analyze_btn.setEnabled(True)
        self._status_label.setText(f"❌ Error: {msg}")
        self._status_label.setStyleSheet("color: #ef4444;")

    def _render_report(self, report: SandboxReport) -> None:
        """Build the visual report from a SandboxReport."""
        layout = self._report_layout
        idx = 0

        # ── Risk Score Card ─────────────────────────────────────────
        risk_card = QFrame()
        risk_card.setObjectName("card")
        rc_layout = QVBoxLayout(risk_card)
        rc_layout.setContentsMargins(20, 16, 20, 16)
        rc_layout.setSpacing(8)

        color = RISK_COLORS.get(report.risk_level, "#94a3b8")

        risk_row = QHBoxLayout()
        risk_icon = QLabel("🎯")
        risk_icon.setFont(QFont("Segoe UI Emoji", 20))
        risk_icon.setStyleSheet("background: transparent;")
        risk_row.addWidget(risk_icon)

        risk_text = QLabel(f"Risk Score: {report.risk_score:.0%}")
        risk_text.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        risk_text.setStyleSheet(f"color: {color}; background: transparent;")
        risk_row.addWidget(risk_text)

        risk_row.addStretch()

        level_badge = QLabel(f"  {report.risk_level}  ")
        level_badge.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        level_badge.setStyleSheet(
            f"background-color: {color}; color: white; border-radius: 6px; "
            f"padding: 4px 16px;"
        )
        risk_row.addWidget(level_badge)
        rc_layout.addLayout(risk_row)

        # File info
        info_text = (
            f"File: {report.file_name}  ·  "
            f"Size: {report.file_size:,} bytes  ·  "
            f"PE: {'Yes' if report.is_pe else 'No'}  ·  "
            f"Time: {report.analysis_time:.2f}s"
        )
        info = QLabel(info_text)
        info.setStyleSheet("color: #94a3b8; font-size: 11px; background: transparent;")
        rc_layout.addWidget(info)

        layout.insertWidget(idx, risk_card)
        idx += 1

        # ── Severity Breakdown ──────────────────────────────────────
        sevs = report.severity_counts
        if any(v > 0 for v in sevs.values()):
            sev_card = QFrame()
            sev_card.setObjectName("card")
            sc_layout = QHBoxLayout(sev_card)
            sc_layout.setContentsMargins(16, 12, 16, 12)
            sc_layout.setSpacing(20)

            for sev_name, sev_count in sevs.items():
                sev_color = SEVERITY_COLORS.get(sev_name, "#94a3b8")
                lbl = QLabel(f"⬤ {sev_name.title()}: {sev_count}")
                lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
                lbl.setStyleSheet(f"color: {sev_color}; background: transparent;")
                sc_layout.addWidget(lbl)

            sc_layout.addStretch()
            layout.insertWidget(idx, sev_card)
            idx += 1

        # ── Behavior Flags ──────────────────────────────────────────
        if report.behaviors:
            beh_title = QLabel(f"🔍  Behaviors Detected ({len(report.behaviors)})")
            beh_title.setFont(QFont("Segoe UI", 14, QFont.Weight.DemiBold))
            layout.insertWidget(idx, beh_title)
            idx += 1

            # Sort: critical first
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_behaviors = sorted(
                report.behaviors,
                key=lambda b: sev_order.get(b.severity, 4),
            )

            for bflag in sorted_behaviors:
                card = BehaviorCard(bflag.category, bflag.detail, bflag.severity)
                layout.insertWidget(idx, card)
                idx += 1
        else:
            safe_label = QLabel("✅  No suspicious behaviors detected")
            safe_label.setFont(QFont("Segoe UI", 13))
            safe_label.setStyleSheet("color: #22c55e; padding: 16px;")
            safe_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.insertWidget(idx, safe_label)
            idx += 1

        # ── Sections Table ──────────────────────────────────────────
        if report.sections:
            sec_title = QLabel(f"📦  PE Sections ({len(report.sections)})")
            sec_title.setFont(QFont("Segoe UI", 14, QFont.Weight.DemiBold))
            layout.insertWidget(idx, sec_title)
            idx += 1

            for sec in report.sections:
                ent = sec["entropy"]
                ent_color = "#ef4444" if ent > 7.0 else "#eab308" if ent > 6.5 else "#22c55e"
                sec_frame = QFrame()
                sec_frame.setObjectName("result_card")
                sl = QHBoxLayout(sec_frame)
                sl.setContentsMargins(14, 8, 14, 8)
                sl.setSpacing(16)

                n = QLabel(sec["name"])
                n.setFont(QFont("Cascadia Code", 11, QFont.Weight.DemiBold))
                n.setStyleSheet("background: transparent;")
                sl.addWidget(n)

                e = QLabel(f"Entropy: {ent:.3f}")
                e.setStyleSheet(f"color: {ent_color}; font-size: 11px; background: transparent;")
                sl.addWidget(e)

                s = QLabel(f"Size: {sec['size']:,}")
                s.setStyleSheet("color: #94a3b8; font-size: 11px; background: transparent;")
                sl.addWidget(s)

                sl.addStretch()
                layout.insertWidget(idx, sec_frame)
                idx += 1

        # ── Imported APIs ───────────────────────────────────────────
        if report.imported_apis:
            api_title = QLabel(f"📋  Imported APIs ({len(report.imported_apis)})")
            api_title.setFont(QFont("Segoe UI", 14, QFont.Weight.DemiBold))
            layout.insertWidget(idx, api_title)
            idx += 1

            api_text = ", ".join(report.imported_apis[:60])
            if len(report.imported_apis) > 60:
                api_text += f" ... +{len(report.imported_apis) - 60} more"
            api_label = QLabel(api_text)
            api_label.setWordWrap(True)
            api_label.setStyleSheet(
                "color: #64748b; font-size: 11px; font-family: 'Cascadia Code'; "
                "padding: 8px; background: transparent;"
            )
            layout.insertWidget(idx, api_label)
            idx += 1

    def _clear_report(self) -> None:
        while self._report_layout.count():
            child = self._report_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self._report_layout.addStretch()
