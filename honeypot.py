import sys
import threading
import socket
import logging
import time
import subprocess
from collections import defaultdict, deque
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit,
                             QTabWidget)
from PyQt5.QtCore import pyqtSignal, QObject, QTimer, Qt
from PyQt5.QtGui import QColor, QTextCharFormat, QTextCursor, QFont
import pyqtgraph as pg

# ---------- Setup Logging ----------
logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(asctime)s %(message)s')

# ---------- Signal for thread-safe logging ----------
class LoggerSignals(QObject):
    log_signal = pyqtSignal(str, bool)  # message, is_alert
    update_chart = pyqtSignal(str)

signals = LoggerSignals()

connection_stats = defaultdict(int)

# ---------- IDS Settings ----------
ATTACK_THRESHOLD = 5         
TIME_WINDOW = 30             

ip_connection_times = defaultdict(deque)  # ip -> deque of timestamps

# ---------- Honeypot Thread ----------
def start_listener(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('0.0.0.0', port))
        sock.listen(1)
        signals.log_signal.emit(f"[+] Listening on port {port}", False)
        while True:
            client, addr = sock.accept()
            ip = addr[0]
            now = time.time()

          
            timestamps = ip_connection_times[ip]
            timestamps.append(now)
           
            while timestamps and now - timestamps[0] > TIME_WINDOW:
                timestamps.popleft()

            
            is_alert = False
            if len(timestamps) > ATTACK_THRESHOLD:
                alert_msg = f"[!!!] Possible attack detected from {ip} - {len(timestamps)} connections in last {TIME_WINDOW}s"
                logging.warning(alert_msg)
                signals.log_signal.emit(alert_msg, True)
                is_alert = True

            if not is_alert:
                log = f"[!] Connection from {ip} on port {port}"
                logging.info(log)
                signals.log_signal.emit(log, False)
            connection_stats[str(port)] += 1
            signals.update_chart.emit(str(port))
            client.close()
    except Exception as e:
        signals.log_signal.emit(f"[!] Error on port {port}: {e}", True)

# ---------- Main GUI ----------
class HoneypotApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("@Tech0Team - Famoso")
        self.setGeometry(200, 100, 950, 700)

        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #E0E0E0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 12pt;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                border-radius: 6px;
                margin: 10px;
            }
            QTabBar::tab {
                background: #1E1E1E;
                color: #AAA;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #282828;
                color: #FFFFFF;
                font-weight: bold;
            }
            QLabel {
                font-weight: bold;
                font-size: 14pt;
                padding: 8px 0px;
            }
            QTextEdit {
                background-color: #1E1E1E;
                border: 1px solid #333;
                padding: 8px;
                border-radius: 6px;
                color: #DDD;
            }
        """)

        self.tabs = QTabWidget()
        self.init_services_tab()
        self.init_logs_tab()
        self.init_stats_tab()

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        signals.log_signal.connect(self.append_log)
        signals.update_chart.connect(self.update_chart)

        self.init_honeypot()

        self.chart_timer = QTimer()
        self.chart_timer.timeout.connect(self.refresh_chart)
        self.chart_timer.start(3000)

    def init_services_tab(self):
        self.services_tab = QWidget()
        layout = QVBoxLayout()
        self.services_label = QLabel("Listening Services")
        self.services_text = QTextEdit()
        self.services_text.setReadOnly(True)
        layout.addWidget(self.services_label)
        layout.addWidget(self.services_text)
        self.services_tab.setLayout(layout)
        self.tabs.addTab(self.services_tab, "Services")

    def init_logs_tab(self):
        self.logs_tab = QWidget()
        layout = QVBoxLayout()
        self.logs_label = QLabel("Activity Logs")
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        layout.addWidget(self.logs_label)
        layout.addWidget(self.logs_text)
        self.logs_tab.setLayout(layout)
        self.tabs.addTab(self.logs_tab, "Logs")

    def init_stats_tab(self):
        self.stats_tab = QWidget()
        layout = QVBoxLayout()
        self.stats_label = QLabel("Live Attack Statistics")
        self.plot_widget = pg.PlotWidget(title="Connections Per Port")
        self.plot_widget.setBackground('#121212')
        self.bar_graph = pg.BarGraphItem(x=[], height=[], width=0.6, brush=pg.mkBrush('#00BFFF'))
        self.plot_widget.addItem(self.bar_graph)
        layout.addWidget(self.stats_label)
        layout.addWidget(self.plot_widget)
        self.stats_tab.setLayout(layout)
        self.tabs.addTab(self.stats_tab, "Statistics")
    
    def append_log(self, msg, is_alert):
        
        fmt = QTextCharFormat()
        cursor = self.logs_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        if is_alert:
            fmt.setForeground(QColor('#FF5555'))
            fmt.setFontWeight(QFont.Bold)
        else:
            fmt.setForeground(QColor('#DDD'))
            fmt.setFontWeight(QFont.Normal)

        cursor.insertText(msg + '\n', fmt)
        self.logs_text.setTextCursor(cursor)
        self.logs_text.ensureCursorVisible()

        if "Listening" in msg:
            
            self.services_text.append(msg)

    def update_chart(self, port):
        self.refresh_chart()

    def refresh_chart(self):
        ports = list(connection_stats.keys())
        values = [connection_stats[p] for p in ports]
        x_ticks = list(range(len(ports)))
        self.plot_widget.clear()
        self.bar_graph = pg.BarGraphItem(x=x_ticks, height=values, width=0.6, brush=pg.mkBrush('#00BFFF'))
        self.plot_widget.addItem(self.bar_graph)
        self.plot_widget.getAxis('bottom').setTicks([list(zip(x_ticks, ports))])
        self.plot_widget.getAxis('bottom').setStyle(tickTextOffset=10)
        self.plot_widget.getAxis('bottom').setTickFont(pg.QtGui.QFont('Segoe UI', 10))
        self.plot_widget.getAxis('left').setTickFont(pg.QtGui.QFont('Segoe UI', 10))
        self.plot_widget.setLabel('left', 'Connection Count')
        self.plot_widget.setLabel('bottom', 'Ports')

    def init_honeypot(self):
        common_ports = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080]
        for port in common_ports:
            t = threading.Thread(target=start_listener, args=(port,), daemon=True)
            t.start()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = HoneypotApp()
    window.show()
    sys.exit(app.exec_())
