import sys
import threading
import time
from datetime import datetime
from collections import defaultdict, deque
import json

from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QWidget, QPushButton, QLineEdit, QLabel, 
    QTextEdit, QHBoxLayout, QComboBox, QDialog, QCheckBox, QSplashScreen,
    QToolBar, QAction, QMenuBar, QFileDialog, QMessageBox
)
from PyQt5.QtGui import QFontDatabase, QPixmap, QIcon
from PyQt5.QtCore import Qt, QTimer

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from scapy.all import sniff, IP, get_if_list, AsyncSniffer, wrpcap
import matplotlib.ticker as ticker

def get_most_active_interface(duration=2):
    try:
        interfaces = get_if_list()
        if not interfaces:
            raise ValueError("No network interfaces found.")
        
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
            most_active = interfaces[0]

        return most_active, traffic_counts
    except Exception as e:
        print(f"Error finding active interface: {e}")
        return None, {}

class PacketSniffer:
    def __init__(self, interface=None, packet_callback_gui=None):
        self.interface = interface or get_if_list()[0]
        self.packet_counts = defaultdict(int)
        self.suspicious_counts = defaultdict(int)
        self.packets = []
        self.packet_times = deque(maxlen=1000)
        self.timestamps = deque(maxlen=1000)
        self.running = False
        self.lock = threading.Lock()
        self.packet_callback_gui = packet_callback_gui
        self.filter_ip = None
        self.filter_protocol = None

    def set_filter(self, ip=None, protocol=None):
        self.filter_ip = ip
        self.filter_protocol = protocol

    def start(self):
        if not self.running:
            self.running = True
            self.sniff_thread = threading.Thread(target=self.capture_packets, daemon=True)
            self.sniff_thread.start()

    def stop(self):
        self.running = False

    def capture_packets(self):
        print(f"[DEBUG] Sniffer thread started on interface {self.interface}")
        sniff(
            iface=self.interface,
            prn=self.packet_callback,
            store=0,
            stop_filter=lambda x: not self.running
        )

    def packet_callback(self, packet):
        if IP not in packet:
            return

        # Apply filters
        ip_layer = packet[IP]
        if self.filter_ip and (ip_layer.src != self.filter_ip and ip_layer.dst != self.filter_ip):
            return
        if self.filter_protocol and ip_layer.proto != self.filter_protocol:
            return

        now = int(time.time())
        classification = self.classify_packet(packet)

        with self.lock:
            self.packet_counts[now] += 1
            if classification.startswith("Suspicious"):
                self.suspicious_counts[now] += 1

            self.packets.append(packet)
            self.packet_times.append(datetime.now())
            self.timestamps.append(now)

        if self.packet_callback_gui:
            log_line = f"{datetime.now().strftime('%H:%M:%S')} | {classification} | {ip_layer.src} → {ip_layer.dst}"
            self.packet_callback_gui(log_line, classification)

    def get_recent_counts(self, seconds=60):
        now = int(time.time())
        time_list, count_list = [], []
        with self.lock:
            for i in range(seconds):
                t = now - (seconds - 1) + i
                time_str = datetime.fromtimestamp(t).strftime("%H:%M:%S")
                time_list.append(time_str)
                count_list.append(self.packet_counts.get(t, 0))
        return time_list, count_list

    def get_suspicious_recent_counts(self, seconds=60):
        now = int(time.time())
        time_list, count_list = [], []
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
        try:
            with open("suspicious_log.txt", "a") as f:
                timestamp = datetime.now().strftime('%Y-%m-d %H:%M:%S')
                src = packet[IP].src if IP in packet else "Unknown"
                dst = packet[IP].dst if IP in packet else "Unknown"
                f.write(f"[{timestamp}] {reason} | {src} → {dst}\n")
        except Exception as e:
            print(f"Error logging suspicious packet: {e}")

    def save_packets(self, filename):
        try:
            with self.lock:
                if not self.packets:
                    return "No packets to save."
                wrpcap(filename, self.packets)
                return f"Saved {len(self.packets)} packets to {filename}."
        except Exception as e:
            return f"Error saving packets: {e}"

class LivePlot(QWidget):
    def __init__(self, sniffer):
        super().__init__()
        self.sniffer = sniffer
        self.setWindowTitle("Safffire - Advanced Packet Sniffer")
        self.resize(1200, 800)
        self.packet_counter = 0
        self.is_capturing = False  # Track capturing state

        # Set the window icon
        self.setWindowIcon(QIcon("logo.png"))

        # Main layout
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)

        # Toolbar
        self.toolbar = QToolBar("Main Toolbar")
        self.main_layout.addWidget(self.toolbar)

        # Actions for toolbar
        self.action_toggle_capture = QAction(QIcon("start_icon.png"), "Start Capturing", self)
        self.action_toggle_capture.triggered.connect(self.toggle_capture)
        self.action_save = QAction(QIcon("save_icon.png"), "Save Packets", self)
        self.action_clear = QAction(QIcon("clear_icon.png"), "Clear Logs", self)

        self.action_save.triggered.connect(self.save_packets)
        self.action_clear.triggered.connect(self.clear_logs)

        self.toolbar.addAction(self.action_toggle_capture)
        self.toolbar.addAction(self.action_save)
        self.toolbar.addAction(self.action_clear)

        # Interface selection
        self.interface_selector = QComboBox()
        self.main_layout.addWidget(QLabel("Select Network Interface:"))
        most_active_iface, iface_stats = get_most_active_interface()
        self.iface_map = {}
        for iface in get_if_list():
            display = f"{iface}"
            if iface == most_active_iface:
                display += " (most active)"
            self.interface_selector.addItem(display)
            self.iface_map[display] = iface
        self.main_layout.addWidget(self.interface_selector)

        # Filter controls
        filter_layout = QHBoxLayout()
        self.filter_ip_input = QLineEdit()
        self.filter_ip_input.setPlaceholderText("Filter by IP (e.g., 192.168.1.1)")
        self.filter_protocol_input = QComboBox()
        self.filter_protocol_input.addItems(["All", "TCP (6)", "UDP (17)", "ICMP (1)"])
        self.apply_filter_button = QPushButton("Apply Filter")
        self.apply_filter_button.clicked.connect(self.apply_filter)
        filter_layout.addWidget(QLabel("Filters:"))
        filter_layout.addWidget(self.filter_ip_input)
        filter_layout.addWidget(self.filter_protocol_input)
        filter_layout.addWidget(self.apply_filter_button)
        self.main_layout.addLayout(filter_layout)

        # Matplotlib plot
        self.figure = Figure(facecolor='#1e1e1e')
        self.canvas = FigureCanvas(self.figure)
        self.main_layout.addWidget(self.canvas)

        # Packet inspection
        inspect_layout = QHBoxLayout()
        self.packet_index_input = QLineEdit()
        self.packet_index_input.setPlaceholderText("Enter packet index (default -1 for last packet)")
        self.inspect_button = QPushButton("Inspect Packet")
        self.inspect_button.clicked.connect(self.show_packet_info)
        inspect_layout.addWidget(self.packet_index_input)
        inspect_layout.addWidget(self.inspect_button)
        self.main_layout.addLayout(inspect_layout)

        self.packet_info_output = QTextEdit()
        self.packet_info_output.setReadOnly(True)
        self.main_layout.addWidget(QLabel("Packet Details:"))
        self.main_layout.addWidget(self.packet_info_output) 

        # Packet log
        self.packet_log_output = QTextEdit()
        self.packet_log_output.setReadOnly(True)
        self.main_layout.addWidget(QLabel("Captured Packets:"))
        self.main_layout.addWidget(self.packet_log_output)

        self.auto_scroll_checkbox = QCheckBox("Auto-scroll to latest")
        self.auto_scroll_checkbox.setChecked(True)
        self.main_layout.addWidget(self.auto_scroll_checkbox)

        # Suspicious log button
        self.btn_view_log = QPushButton("View Suspicious Log")
        self.btn_view_log.clicked.connect(self.show_log)
        self.main_layout.addWidget(self.btn_view_log)

        # Timer for updating plot
        self.sniffer.packet_callback_gui = self.display_packet_log
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_plot)
        self.timer.start(1000)

    def display_packet_log(self, log_line, classification):
        self.packet_counter += 1
        index = self.packet_counter
        color = "red" if "Suspicious" in classification else "cyan"
        formatted_line = f'<span style="color:{color};">[{index}] {log_line}</span><br>'
        self.packet_log_output.append(formatted_line)
        if self.auto_scroll_checkbox.isChecked():
            self.packet_log_output.ensureCursorVisible()

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
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button)
        dialog.exec_()

    def toggle_capture(self):
        selected_display = self.interface_selector.currentText()
        self.sniffer.interface = self.iface_map.get(selected_display)
        if not self.sniffer.interface:
            QMessageBox.warning(self, "Error", "Please select a valid network interface.")
            return

        if not self.is_capturing:
            # Start capturing
            self.packet_counter = 0
            self.packet_log_output.clear()
            self.sniffer.start()
            self.is_capturing = True
            self.action_toggle_capture.setText("Stop Capturing")
            self.action_toggle_capture.setIcon(QIcon("stop_icon.png"))
        else:
            # Stop capturing
            self.sniffer.stop()
            self.is_capturing = False
            self.action_toggle_capture.setText("Start Capturing")
            self.action_toggle_capture.setIcon(QIcon("start_icon.png"))

    def apply_filter(self):
        ip_filter = self.filter_ip_input.text().strip() or None
        protocol_text = self.filter_protocol_input.currentText()
        protocol_map = {"All": None, "TCP (6)": 6, "UDP (17)": 17, "ICMP (1)": 1}
        protocol_filter = protocol_map.get(protocol_text)
        self.sniffer.set_filter(ip=ip_filter, protocol=protocol_filter)
        QMessageBox.information(self, "Filter Applied", "Filter has been applied successfully.")

    def save_packets(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Packets", "", "PCAP Files (*.pcap);;All Files (*)")
        if filename:
            result = self.sniffer.save_packets(filename)
            QMessageBox.information(self, "Save Packets", result)

    def clear_logs(self):
        self.packet_log_output.clear()
        self.packet_counter = 0
        self.sniffer.packets.clear()
        QMessageBox.information(self, "Logs Cleared", "Packet logs have been cleared.")

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
        ax.set_xticklabels(x)
        for label in ax.get_xticklabels():
            label.set_fontsize(9)
            label.set_color('white')
        ax.tick_params(axis='x', rotation=90)
        ax.tick_params(axis='y', labelcolor='white')
        ax.set_facecolor('#2e2e2e')
        ax.legend(facecolor='#1e1e1e', edgecolor='white', labelcolor='white')
        ax.figure.subplots_adjust(bottom=0.3)
        self.canvas.draw()

    def show_packet_info(self):
        try:
            x = self.packet_index_input.text()
            index = -1 if not x.strip() else int(x) - 1
            if index < -len(self.sniffer.packets) or index >= len(self.sniffer.packets):
                self.packet_info_output.setText("Invalid packet index.")
                return
            info = self.sniffer.get_packet_info(index)
            self.packet_info_output.setText(info)
            self.packet_info_output.setStyleSheet("color: red;" if "Suspicous" in info else "color: white;")
        except ValueError:
            self.packet_info_output.setText("Invalid input. Please enter an integer.")

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Set the application icon (for taskbar on some OSes)
    app.setWindowIcon(QIcon("logo.png"))

    # Splash screen
    splash_pix = QPixmap("logo.png")
    splash = QSplashScreen(splash_pix, Qt.WindowStaysOnTopHint)
    splash.setMask(splash_pix.mask())
    splash.show()
    app.processEvents()

    # Load custom font
    font_id = QFontDatabase.addApplicationFont("Orbitron.ttf")
    font_family = QFontDatabase.applicationFontFamilies(font_id)[0] if font_id != -1 else "Consolas"

    # Apply stylesheet
    app.setStyleSheet(f"""
        QWidget {{
            background-color: #121212;
            color: #e0e0e0;
            font-family: '{font_family}', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 14px;
        }}
        QPushButton {{
            background-color: #0078d7;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px 18px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background-color: #005a9e;
        }}
        QPushButton:pressed {{
            background-color: #003f6d;
        }}
        QLineEdit, QTextEdit {{
            background-color: #1e1e1e;
            border: 1px solid #333333;
            border-radius: 6px;
            padding: 6px;
            color: #ffffff;
        }}
        QLineEdit:focus, QTextEdit:focus {{
            border: 1px solid #0078d7;
            background-color: #2a2a2a;
        }}
        QLabel {{
            color: #e0e0e0;
            font-weight: 600;
        }}
        QToolBar {{
            background-color: #1e1e1e;
            border: none;
        }}
        QComboBox {{
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #333333;
            border-radius: 6px;
            padding: 6px;
        }}
    """)

    sniffer = PacketSniffer()
    window = LivePlot(sniffer)

    def show_main_window():
        window.show()
        splash.finish(window)

    QTimer.singleShot(2000, show_main_window)
    sys.exit(app.exec_())