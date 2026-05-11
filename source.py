
import sys
import os
import queue
import threading
import time
from datetime import datetime
from collections import defaultdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout,
    QHBoxLayout, QTableWidget, QTableWidgetItem, QLabel, QPushButton,
    QTextEdit, QHeaderView, QFrame, QSplitter, QFileDialog, QMessageBox,
    QProgressBar, QStatusBar, QGridLayout, QGroupBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QColor, QFont, QPalette, QBrush

from module1.interceptor import SyscallInterceptor, syscall_queue
from module2.detector import AnomalyDetector
from module3.logger import AuditLogger

import queue as _queue
_alert_queue_main = _queue.Queue(maxsize=500)
_log_event_queue = _queue.Queue(maxsize=1000)
_log_alert_queue = _queue.Queue(maxsize=500)


SEVERITY_COLORS = {
    "LOW":      ("#E8F5E9", "#2E7D32"),
    "MEDIUM":   ("#FFF8E1", "#F57F17"),
    "HIGH":     ("#FFEBEE", "#C62828"),
    "CRITICAL": ("#F3E5F5", "#6A1B9A"),
}

DARK_BG = "#1A1A2E"
DARK_PANEL = "#16213E"
DARK_CARD = "#0F3460"
ACCENT = "#E94560"
TEXT_PRIMARY = "#EAEAEA"
TEXT_SECONDARY = "#A0A0B0"


STYLE = f"""
QMainWindow, QWidget {{
    background-color: {DARK_BG};
    color: {TEXT_PRIMARY};
    font-family: 'Courier New', monospace;
}}
QTabWidget::pane {{
    border: 1px solid #333355;
    background: {DARK_PANEL};
}}
QTabBar::tab {{
    background: {DARK_CARD};
    color: {TEXT_SECONDARY};
    padding: 10px 22px;
    font-size: 12px;
    font-weight: bold;
    border-radius: 4px 4px 0 0;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    background: {ACCENT};
    color: white;
}}
QTableWidget {{
    background-color: {DARK_PANEL};
    color: {TEXT_PRIMARY};
    gridline-color: #222244;
    border: none;
    font-family: 'Courier New', monospace;
    font-size: 11px;
}}
QHeaderView::section {{
    background-color: {DARK_CARD};
    color: {ACCENT};
    padding: 8px;
    border: none;
    font-weight: bold;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
QTableWidget::item:selected {{
    background-color: #2a2a5a;
}}
QPushButton {{
    background-color: {ACCENT};
    color: white;
    border: none;
    padding: 8px 18px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 11px;
}}
QPushButton:hover {{
    background-color: #ff6b80;
}}
QPushButton:disabled {{
    background-color: #444;
    color: #888;
}}
QPushButton#stopBtn {{
    background-color: #444466;
}}
QPushButton#stopBtn:hover {{
    background-color: #666688;
}}
QLabel#statValue {{
    font-size: 28px;
    font-weight: bold;
    color: {ACCENT};
}}
QLabel#statLabel {{
    font-size: 10px;
    color: {TEXT_SECONDARY};
    text-transform: uppercase;
    letter-spacing: 1px;
}}
QGroupBox {{
    border: 1px solid #333355;
    border-radius: 6px;
    margin-top: 12px;
    padding: 8px;
    color: {TEXT_SECONDARY};
    font-size: 10px;
    font-weight: bold;
    text-transform: uppercase;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: {ACCENT};
}}
QTextEdit {{
    background-color: #0d0d1a;
    color: #00ff99;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    border: 1px solid #222244;
    border-radius: 4px;
}}
QStatusBar {{
    background: {DARK_CARD};
    color: {TEXT_SECONDARY};
    font-size: 10px;
}}
QScrollBar:vertical {{
    background: {DARK_BG};
    width: 8px;
}}
QScrollBar::handle:vertical {{
    background: #444466;
    border-radius: 4px;
}}
"""


class StatCard(QFrame):
    def __init__(self, title, value="0", color=ACCENT):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background: {DARK_CARD};
                border-radius: 8px;
                border: 1px solid #333355;
                padding: 10px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("statValue")
        self.value_label.setStyleSheet(f"color: {color}; font-size: 32px; font-weight: bold;")
        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("statLabel")
        self.title_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 9px; letter-spacing: 1px;")
        layout.addWidget(self.value_label, alignment=Qt.AlignCenter)
        layout.addWidget(self.title_label, alignment=Qt.AlignCenter)

    def set_value(self, val):
        self.value_label.setText(str(val))


class LiveMonitorTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Header
        header = QHBoxLayout()
        title = QLabel("⚡ LIVE SYSCALL STREAM")
        title.setStyleSheet(f"color: {ACCENT}; font-size: 13px; font-weight: bold; letter-spacing: 2px;")
        self.count_label = QLabel("Events: 0")
        self.count_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.count_label)
        layout.addLayout(header)

        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Timestamp", "PID", "Process", "Syscall", "Arguments", "Return"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        layout.addWidget(self.table)

        self._count = 0
        self._suspicious_syscalls = {"ptrace", "execve", "chmod", "unlinkat", "kill", "connect", "fork", "clone"}

    def add_event(self, event):
        self._count += 1
        self.count_label.setText(f"Events: {self._count}")

        # Keep max 200 rows
        if self.table.rowCount() > 200:
            self.table.removeRow(0)

        row = self.table.rowCount()
        self.table.insertRow(row)

        ts = event["timestamp"][11:23] if len(event["timestamp"]) > 11 else event["timestamp"]
        values = [ts, str(event["pid"]), event["process"],
                  event["syscall"], "; ".join(event.get("args", [])), event["return_val"]]

        is_suspicious = event["syscall"] in self._suspicious_syscalls
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if is_suspicious:
                item.setForeground(QBrush(QColor("#FF6B6B")))
            self.table.setItem(row, col, item)

        self.table.scrollToBottom()


class AlertsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        header = QHBoxLayout()
        title = QLabel("🚨 SECURITY ALERTS")
        title.setStyleSheet(f"color: {ACCENT}; font-size: 13px; font-weight: bold; letter-spacing: 2px;")
        self.alert_count = QLabel("Alerts: 0")
        self.alert_count.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.alert_count)
        layout.addLayout(header)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "PID", "Process", "Rule", "Description"])
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        layout.addWidget(self.table)

        self._count = 0

    def add_alert(self, alert):
        self._count += 1
        self.alert_count.setText(f"Alerts: {self._count}")

        row = self.table.rowCount()
        self.table.insertRow(row)

        ts = alert["timestamp"][11:19]
        sev = alert["severity"]
        bg_color, fg_color = SEVERITY_COLORS.get(sev, ("#222", "#fff"))

        values = [ts, sev, str(alert["pid"]), alert["process"], alert["rule"], alert["description"]]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if col == 1:
                item.setBackground(QBrush(QColor(bg_color)))
                item.setForeground(QBrush(QColor(fg_color)))
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self.table.setItem(row, col, item)

        self.table.scrollToBottom()


class LogsTab(QWidget):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        header = QHBoxLayout()
        title = QLabel("📋 AUDIT LOGS")
        title.setStyleSheet(f"color: {ACCENT}; font-size: 13px; font-weight: bold; letter-spacing: 2px;")
        export_csv_btn = QPushButton("Export CSV")
        export_csv_btn.clicked.connect(self.export_csv)
        export_json_btn = QPushButton("Export JSON")
        export_json_btn.clicked.connect(self.export_json)
        header.addWidget(title)
        header.addStretch()
        header.addWidget(export_csv_btn)
        header.addWidget(export_json_btn)
        layout.addLayout(header)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view)

        self._lines = []

    def append_line(self, text):
        self._lines.append(text)
        if len(self._lines) > 500:
            self._lines = self._lines[-500:]
        self.log_view.setPlainText("\n".join(self._lines[-100:]))
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", f"syscall_log_{datetime.now().strftime('%H%M%S')}.csv", "CSV Files (*.csv)")
        if path:
            import csv
            events = self.logger.get_recent_events(1000)
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "pid", "process", "syscall", "args", "return_val"])
                writer.writeheader()
                for e in events:
                    e["args"] = "; ".join(e.get("args", []))
                    writer.writerow(e)
            QMessageBox.information(self, "Exported", f"CSV saved to:\n{path}")

    def export_json(self):
        import json
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", f"syscall_log_{datetime.now().strftime('%H%M%S')}.json", "JSON Files (*.json)")
        if path:
            events = self.logger.get_recent_events(1000)
            with open(path, "w") as f:
                json.dump(events, f, indent=2)
            QMessageBox.information(self, "Exported", f"JSON saved to:\n{path}")


class ReportTab(QWidget):
    def __init__(self, logger, detector):
        super().__init__()
        self.logger = logger
        self.detector = detector
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        header = QHBoxLayout()
        title = QLabel("📊 COMPLIANCE REPORT")
        title.setStyleSheet(f"color: {ACCENT}; font-size: 13px; font-weight: bold; letter-spacing: 2px;")
        gen_btn = QPushButton("Generate Report")
        gen_btn.clicked.connect(self.generate)
        header.addWidget(title)
        header.addStretch()
        header.addWidget(gen_btn)
        layout.addLayout(header)

        self.report_view = QTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setPlainText("Click 'Generate Report' to create a session summary.")
        layout.addWidget(self.report_view)

    def generate(self):
        stats = self.detector.get_stats()
        report, path = self.logger.generate_report(stats)
        import json
        text = json.dumps(report, indent=2)
        self.report_view.setPlainText(text)
        QMessageBox.information(self, "Report Generated", f"Report saved:\n{path}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System Call Monitoring & Auditing Tool — CSE-316 CA2")
        self.setMinimumSize(1200, 750)
        self.setStyleSheet(STYLE)

        # Setup backend
        self._setup_backend()

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(12, 12, 12, 8)
        main_layout.setSpacing(10)

        # Top bar
        top_bar = self._build_top_bar()
        main_layout.addLayout(top_bar)

        # Stat cards
        self.stat_events = StatCard("Total Events", "0", ACCENT)
        self.stat_alerts = StatCard("Total Alerts", "0", "#FF6B6B")
        self.stat_critical = StatCard("Critical", "0", "#9C27B0")
        self.stat_high = StatCard("High", "0", "#F44336")
        self.stat_medium = StatCard("Medium", "0", "#FF9800")
        self.stat_low = StatCard("Low", "0", "#4CAF50")

        stats_layout = QHBoxLayout()
        for card in [self.stat_events, self.stat_alerts, self.stat_critical, self.stat_high, self.stat_medium, self.stat_low]:
            stats_layout.addWidget(card)
        main_layout.addLayout(stats_layout)

        # Tabs
        self.tabs = QTabWidget()
        self.monitor_tab = LiveMonitorTab()
        self.alerts_tab = AlertsTab()
        self.logs_tab = LogsTab(self.logger)
        self.report_tab = ReportTab(self.logger, self.detector)

        self.tabs.addTab(self.monitor_tab, "🖥 Live Monitor")
        self.tabs.addTab(self.alerts_tab, "🚨 Alerts")
        self.tabs.addTab(self.logs_tab, "📋 Audit Logs")
        self.tabs.addTab(self.report_tab, "📊 Report")
        main_layout.addWidget(self.tabs)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("● MONITORING ACTIVE  |  Simulation Mode  |  Session: " + self.logger.session_id)

        # Timer to pull data from queues
        self.timer = QTimer()
        self.timer.timeout.connect(self._poll_queues)
        self.timer.start(300)  # 300ms refresh

        self._running = True

    def _setup_backend(self):
        self.interceptor = SyscallInterceptor(output_queue=syscall_queue, simulate=True)
        self.detector = AnomalyDetector(input_queue=syscall_queue, alert_queue=_alert_queue_main)
        self.logger = AuditLogger(event_queue=_log_event_queue, alert_queue=_log_alert_queue)
        self.interceptor.start()
        self.detector.start()
        self.logger.start()

    def _build_top_bar(self):
        layout = QHBoxLayout()
        title = QLabel("⚙ SYSCALL MONITOR")
        title.setStyleSheet(f"color: {ACCENT}; font-size: 18px; font-weight: bold; letter-spacing: 3px;")
        subtitle = QLabel("CSE-316 · Security Audit Tool · Simulation Mode")
        subtitle.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 10px;")

        self.start_btn = QPushButton("▶ Start")
        self.stop_btn = QPushButton("■ Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.start_btn.clicked.connect(self._start_monitoring)
        self.stop_btn.clicked.connect(self._stop_monitoring)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addStretch()
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        return layout

    def _start_monitoring(self):
        if not self._running:
            self.interceptor.running = True
            self._running = True
            self.timer.start(300)
            self.status_bar.showMessage("● MONITORING ACTIVE")

    def _stop_monitoring(self):
        self._running = False
        self.interceptor.running = False
        self.timer.stop()
        self.status_bar.showMessage("■ MONITORING PAUSED")

    def _poll_queues(self):
        # Drain interceptor -> forward to detector is automatic (shared queue)
        # Forward events from syscall_queue snapshot to display
        processed = 0
        # We need a copy queue for GUI since detector already consumes
        # Use detector's _events via stats instead, and poll alert queue for GUI
        try:
            while not _alert_queue_main.empty() and processed < 20:
                alert = _alert_queue_main.get_nowait()
                d = alert.to_dict()
                self.alerts_tab.add_alert(d)
                self.logs_tab.append_line(f"[ALERT] {d['severity']} — {d['description']}")
                if not _log_alert_queue.full():
                    _log_alert_queue.put(alert)
                processed += 1
        except Exception:
            pass

        # Update stats from detector
        stats = self.detector.get_stats()
        sev = stats.get("by_severity", {})
        self.stat_events.set_value(stats["total_events"])
        self.stat_alerts.set_value(stats["total_alerts"])
        self.stat_critical.set_value(sev.get("CRITICAL", 0))
        self.stat_high.set_value(sev.get("HIGH", 0))
        self.stat_medium.set_value(sev.get("MEDIUM", 0))
        self.stat_low.set_value(sev.get("LOW", 0))

        # Add recent events to monitor tab (from detector's internal list)
        recent = self.detector.all_alerts
        if recent:
            # Show last event in log line
            last = recent[-1]
            e = last.event
            if e:
                ed = e.to_dict()
                self.monitor_tab.add_event(ed)
                self.logs_tab.append_line(
                    f"[{ed['timestamp'][11:19]}] PID:{ed['pid']} ({ed['process']}) → {ed['syscall']}({'; '.join(ed['args'])}) = {ed['return_val']}"
                )
                if not _log_event_queue.full():
                    _log_event_queue.put(e)

    def closeEvent(self, event):
        self.interceptor.stop()
        self.detector.stop()
        self.logger.stop()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SysCall Monitor")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
 isko explain kr do module 3
