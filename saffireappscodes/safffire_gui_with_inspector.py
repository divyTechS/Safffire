import sys
import threading
import time
from datetime import datetime
from collections import defaultdict, deque

from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QWidget, QPushButton,
    QLineEdit, QLabel, QTextEdit, QHBoxLayout, QComboBox
)
from PyQt5.QtGui import QFontDatabase
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from scapy.all import sniff, IP, get_if_list, get_if_addr
import matplotlib.ticker as ticker
import socket
from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QWidget, QPushButton,
    QLineEdit, QLabel, QTextEdit, QHBoxLayout, QComboBox,
    QDialog, QMessageBox, QFileDialog
)
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QTextEdit, QComboBox, QMessageBox, QFileDialog, QDialog
)
from PyQt5.QtCore import QTimer
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.ticker as ticker
from scapy.all import get_if_list


def get_most_active_interface(duration=2):
    from scapy.all import AsyncSniffer

    interfaces = get_if_list()
    traffic_counts = {}

    def count_packets(pkt, iface_name):
        traffic_counts[iface_name] = traffic_counts.get(iface_name, 0) + 1

    sniffers = []
    for iface in interfaces:
        traffic_counts[iface] = 0
        s = AsyncSniffer(iface=iface, prn=lambda pkt, name=iface: count_packets(pkt, name), store=False)
        sniffers.append(s)
        s.start()

    time.sleep(duration)

    for s in sniffers:
        s.stop()

    if traffic_counts:
        most_active = max(traffic_counts, key=lambda k: traffic_counts[k])
    else:
        most_active = interfaces[0] if interfaces else None

    return most_active, traffic_counts


from PyQt5.QtCore import QObject, pyqtSignal

class PacketSniffer(QObject):
    error_signal = pyqtSignal(str)  # signal to send error messages

    def __init__(self, interface=None):
        super().__init__()  # Initialize QObject
        self.interface = interface or get_if_list()[0]
        self.packet_counts = defaultdict(int)
        self.suspicious_counts = defaultdict(int)
        self.packets = []
        self.packet_times = deque(maxlen=1000)
        self.timestamps = deque(maxlen=1000)
        self.running = False
        self.lock = threading.Lock()

    def capture_packets(self):
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.running = False
            error_msg = f"Packet capture error on interface '{self.interface}': {str(e)}"
            print(f"[Error] {error_msg}")
            self.error_signal.emit(error_msg)  # emit signal on error

    def start(self):
        if not self.running:
            self.running = True
            self.sniff_thread = threading.Thread(target=self.capture_packets, daemon=True)
            self.sniff_thread.start()

    def stop(self):
        self.running = False

 
    def packet_callback(self, packet):
        if IP in packet:
            now = int(time.time())
            classification = self.classify_packet(packet)

            with self.lock:
                self.packet_counts[now] += 1
                if classification.startswith("Suspicious"):
                    self.suspicious_counts[now] += 1

                self.packets.append(packet)
                self.packet_times.append(datetime.now())
                self.timestamps.append(now)

    def get_recent_counts(self, seconds=60):
        now = int(time.time())
        time_list = []
        count_list = []
        with self.lock:
            for i in range(seconds):
                t = now - (seconds - 1) + i
                time_str = datetime.fromtimestamp(t).strftime("%H:%M:%S")
                time_list.append(time_str)
                count_list.append(self.packet_counts.get(t, 0))
        return time_list, count_list

    def get_suspicious_recent_counts(self, seconds=60):
        now = int(time.time())
        time_list = []
        count_list = []
        with self.lock:
            for i in range(seconds):
                t = now - (seconds - 1) + i
                time_str = datetime.fromtimestamp(t).strftime("%H:%M:%S")
                time_list.append(time_str)
                count_list.append(self.suspicious_counts.get(t, 0))
        return time_list, count_list

    def get_packet_info(self, index=-1):
        with self.lock:
            if not self.packets:
                return "No packets captured yet."
            if index >= len(self.packets) or index < -len(self.packets):
                return f"Invalid packet index: {index}. Total packets: {len(self.packets)}"
            packet = self.packets[index]
            if IP in packet:
                ip_layer = packet[IP]
                classification = self.classify_packet(packet)
                info = {
                    "Classification": classification,
                    "Source IP": ip_layer.src,
                    "Destination IP": ip_layer.dst,
                    "TTL": ip_layer.ttl,
                    "Protocol": ip_layer.proto,
                    "Length": ip_layer.len,
                    "Flags": ip_layer.flags,
                    "Fragment Offset": ip_layer.frag,
                    "Header Checksum": ip_layer.chksum,
                    "IP ID": ip_layer.id
                }
                return "\n".join(f"{k}: {v}" for k, v in info.items())
            else:
                return "IP layer not present in this packet."

    def classify_packet(self, packet):
        if IP in packet:
            ip = packet[IP]
            if ip.ttl > 200:
                self.log_suspicious(packet, "High TTL")
                return "Suspicious (High TTL)"
            if ip.proto == 1:
                self.log_suspicious(packet, "ICMP Protocol")
                return "Suspicious (ICMP)"
            if hasattr(packet, 'sport') and packet.sport == 4444:
                self.log_suspicious(packet, "Suspicious Src Port 4444")
                return "Suspicious (Suspicious Src Port)"
            if hasattr(packet, 'dport') and packet.dport == 4444:
                self.log_suspicious(packet, "Suspicious Dst Port 4444")
                return "Suspicious (Suspicious Dst Port)"
        return "Normal"

    def log_suspicious(self, packet, reason):
        with open("suspicious_log.txt", "a") as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            src = packet[IP].src if IP in packet else "Unknown"
            dst = packet[IP].dst if IP in packet else "Unknown"
            f.write(f"[{timestamp}] {reason} | {src} → {dst}\n")



class LivePlot(QWidget):
    def __init__(self, sniffer):
        super().__init__()
        self.sniffer = sniffer
        self.sniffer.error_signal.connect(self.show_error_message)

        self.setWindowTitle("Safffire - Live Packet Sniffer")
        self.resize(1000, 700)
        self.setStyleSheet("background-color: #121212; color: white;")

        self.layout = QVBoxLayout(self)
        self.setLayout(self.layout)

        self.interface_selector = QComboBox()
        self.layout.addWidget(QLabel("Select Network Interface:"))
        self.layout.addWidget(self.interface_selector)

        self.iface_map = {}
        most_active_iface, _ = get_most_active_interface()
        for iface in get_if_list():
            display = f"{iface}"
            if iface == most_active_iface:
                display += " (most active)"
            self.interface_selector.addItem(display)
            self.iface_map[display] = iface

        self.status_label = QLabel("Sniffing: STOPPED")
        self.status_label.setStyleSheet("color: red; font-weight: bold; font-size: 16px;")
        self.layout.addWidget(self.status_label)

        self.figure = Figure(facecolor='#1e1e1e')
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas)

        button_layout = QHBoxLayout()
        self.btn_start = QPushButton("Start Sniffing")
        self.btn_stop = QPushButton("Stop Sniffing")
        self.btn_view_log = QPushButton("View Suspicious Log")

        button_layout.addWidget(self.btn_start)
        button_layout.addWidget(self.btn_stop)
        button_layout.addWidget(self.btn_view_log)

        self.layout.addLayout(button_layout)

        self.packet_index_input = QLineEdit()
        self.packet_index_input.setPlaceholderText("e.g. 1 for first, -1 for last packet")
        self.inspect_button = QPushButton("Show Packet IP Fields")
        self.packet_info_output = QTextEdit()
        self.packet_info_output.setReadOnly(True)

        self.layout.addWidget(QLabel("Inspect Packet by Index:"))
        self.layout.addWidget(self.packet_index_input)
        self.layout.addWidget(self.inspect_button)
        self.layout.addWidget(QLabel("Packet IP Fields:"))
        self.layout.addWidget(self.packet_info_output)

        # Packet counters
        self.label_total = QLabel("Total Packets: 0")
        self.label_suspicious = QLabel("Suspicious Packets: 0")
        self.layout.addWidget(self.label_total)
        self.layout.addWidget(self.label_suspicious)

        # Connections
        self.btn_start.clicked.connect(self.start_sniffing)
        self.btn_stop.clicked.connect(self.stop_sniffing)
        self.inspect_button.clicked.connect(self.show_packet_info)
        self.btn_view_log.clicked.connect(self.show_log)

        # Tooltips
        self.interface_selector.setToolTip("Select the network interface to capture packets from.")
        self.btn_start.setToolTip("Start capturing packets on the selected interface.")
        self.btn_stop.setToolTip("Stop capturing packets.")
        self.inspect_button.setToolTip("Inspect a captured packet's IP fields by its index.")
        self.packet_index_input.setToolTip("Enter an index: 1 for first packet, -1 for last.")
        self.btn_view_log.setToolTip("View and manage the suspicious packet log.")

        # Timer
        self.timer = self.startTimer(1000)

    def start_sniffing(self):
        selected_display = self.interface_selector.currentText()
        iface = self.iface_map.get(selected_display, None)
        if not iface or iface not in get_if_list():
            QMessageBox.warning(self, "Interface Error", "Selected network interface is invalid or unavailable.")
            return

        self.sniffer.interface = iface
        try:
            self.sniffer.start()
            self.status_label.setText("Sniffing: ACTIVE")
            self.status_label.setStyleSheet("color: lime; font-weight: bold; font-size: 16px;")
            self.interface_selector.setDisabled(True)
            self.btn_start.setDisabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Sniffer Error", f"Failed to start packet sniffer:\n{str(e)}")

    def stop_sniffing(self):
        self.sniffer.stop()
        self.status_label.setText("Sniffing: STOPPED")
        self.status_label.setStyleSheet("color: red; font-weight: bold; font-size: 16px;")
        self.interface_selector.setDisabled(False)
        self.btn_start.setDisabled(False)

    def show_error_message(self, message):
        QMessageBox.critical(self, "Sniffer Error", message)

    def show_packet_info(self):
        try:
            x = self.packet_index_input.text().strip()
            index = int(x) if x else -1
            info = self.sniffer.get_packet_info(index - 1 if index > 0 else index)
            self.packet_info_output.setText(info)
            self.packet_info_output.setStyleSheet("color: red;" if "Suspicious" in info else "color: white;")
        except ValueError:
            self.packet_info_output.setText("Invalid input. Please enter an integer like 1 or -1.")

    def show_log(self):
        try:
            with open("suspicious_log.txt", "r") as f:
                log_text = f.read()
        except FileNotFoundError:
            log_text = "No suspicious log file found."

        dialog = QDialog(self)
        dialog.setWindowTitle("Suspicious Packet Log")
        dialog.resize(600, 400)

        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlainText(log_text)
        layout.addWidget(text_edit)

        button_layout = QHBoxLayout()

        clear_button = QPushButton("Clear Log")
        clear_button.clicked.connect(lambda: self.clear_log_file(dialog, text_edit))
        button_layout.addWidget(clear_button)

        export_button = QPushButton("Export Log")
        export_button.clicked.connect(lambda: self.export_log_file(dialog, text_edit))
        button_layout.addWidget(export_button)

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)
        dialog.exec_()

    def clear_log_file(self, parent, text_edit):
        confirm = QMessageBox.question(
            parent, "Confirm Clear Log",
            "Are you sure you want to clear the suspicious log file?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            try:
                open("suspicious_log.txt", "w").close()
                text_edit.clear()
            except Exception as e:
                QMessageBox.warning(parent, "Error", f"Failed to clear log: {e}")

    def export_log_file(self, parent, text_edit):
        export_path, _ = QFileDialog.getSaveFileName(
            parent, "Export Suspicious Log", "suspicious_log.txt", "Text Files (*.txt);;All Files (*)"
        )
        if export_path:
            try:
                with open(export_path, "w") as f_out:
                    f_out.write(text_edit.toPlainText())
                QMessageBox.information(parent, "Export Success", f"Log exported to:\n{export_path}")
            except Exception as e:
                QMessageBox.warning(parent, "Export Failed", f"Failed to export log: {e}")

    def timerEvent(self, event):
        self.update_plot()

    def update_plot(self):
        x, y_normal = self.sniffer.get_recent_counts()
        _, y_suspicious = self.sniffer.get_suspicious_recent_counts()

        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.plot(x, y_normal, color='cyan', marker='o', label='Normal')
        ax.plot(x, y_suspicious, color='red', marker='x', label='Suspicious')

        ax.set_title("Packets per Second (Normal & Suspicious)", color='white')
        ax.set_xlabel("Time", color='white')
        ax.set_ylabel("Packets", color='white')

        ax.xaxis.set_major_locator(ticker.MaxNLocator(nbins=12))
        ax.set_xticks(range(len(x)))
        ax.set_xticklabels(x, rotation=60)
        for label in ax.get_xticklabels():
            label.set_fontsize(9)
            label.set_color('white')
        ax.tick_params(axis='y', labelcolor='white')

        ax.set_facecolor('#2e2e2e')
        ax.legend(facecolor='#1e1e1e', edgecolor='white', labelcolor='white')
        self.figure.subplots_adjust(bottom=0.3)
        self.canvas.draw()

        with self.sniffer.lock:
            total = sum(self.sniffer.packet_counts.values())
            suspicious = sum(self.sniffer.suspicious_counts.values())

        self.label_total.setText(f"Total Packets: {total}")
        self.label_suspicious.setText(f"Suspicious Packets: {suspicious}")

import sys
import os
from PyQt5.QtWidgets import QApplication, QSplashScreen
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFontDatabase

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Load and show splash screen
    splash_pix = QPixmap(resource_path("logo.png"))  # Put your logo file path here
    splash = QSplashScreen(splash_pix, Qt.WindowStaysOnTopHint)
    splash.setMask(splash_pix.mask())
    splash.show()
    app.processEvents()

    font_id = QFontDatabase.addApplicationFont(resource_path("Orbitron.ttf"))
    font_family = QFontDatabase.applicationFontFamilies(font_id)[0] if font_id != -1 else "Consolas"

    app.setStyleSheet(f"""
        QWidget {{
            background-color: #0f1a2b;  /* Deep Sapphire Base */
            color: #e0e6ed;  /* Light Sapphire Gray for text */
            font-family: '{font_family}', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 14px;
        }}

        QLabel {{
            color: #e0e6ed;
            font-weight: 600;
        }}

        QPushButton {{
            background-color: #145DA0;  /* Blue Sapphire Primary */
            color: white;
            border: none;
            border-radius: 8px;
            padding: 10px 18px;
            font-weight: 600;
            transition: background-color 0.3s ease;
        }}
        QPushButton:hover {{
            background-color: #0C3C78;  /* Darker Sapphire on hover */
        }}
        QPushButton:pressed {{
            background-color: #062C4E;  /* Deepest Sapphire on click */
        }}

        QLineEdit, QTextEdit {{
            background-color: #1a2b40;
            border: 1px solid #34577c;
            border-radius: 6px;
            padding: 6px;
            color: #e0e6ed;
        }}
        QLineEdit:focus, QTextEdit:focus {{
            border: 1px solid #4da6ff;
            background-color: #21344d;
        }}

        QComboBox {{
            background-color: #1a2b40;
            border: 1px solid #34577c;
            border-radius: 6px;
            padding: 6px;
            color: #e0e6ed;
        }}
        QComboBox QAbstractItemView {{
            background-color: #1a2b40;
            color: #e0e6ed;
            selection-background-color: #145DA0;
        }}

        QToolTip {{
            background-color: #1a2b40;
            color: #e0e6ed;
            border: 1px solid #4da6ff;
            padding: 5px;
        }}

        QScrollBar:vertical, QScrollBar:horizontal {{
            background: #0f1a2b;
            width: 10px;
        }}
        QScrollBar::handle {{
            background: #34577c;
            border-radius: 5px;
        }}
        QScrollBar::handle:hover {{
            background: #4da6ff;
        }}
    """)


    sniffer = PacketSniffer()
    window = LivePlot(sniffer)

    # Show main window after 2 seconds and finish splash
    def show_main_window():
        window.show()
        splash.finish(window)

    QTimer.singleShot(2000, show_main_window)

    sys.exit(app.exec_())
