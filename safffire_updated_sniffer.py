import sys
import threading
import time
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, AsyncSniffer, get_if_list, IP

def get_most_active_interface(duration=1):
    try:
        interfaces = get_if_list()
        if not interfaces:
            raise ValueError("No network interfaces found.")
        
        traffic_counts = {iface: 0 for iface in interfaces}

        sniffers = []
        for iface in interfaces:
            sniffer = AsyncSniffer(
                iface=iface,
                prn=lambda pkt, name=iface: traffic_counts.__setitem__(name, traffic_counts[name] + 1),
                store=False
            )
            sniffer.start()
            sniffers.append(sniffer)

        time.sleep(duration)

        for sniffer in sniffers:
            sniffer.stop()

        most_active = max(traffic_counts, key=traffic_counts.get, default=interfaces[0])
        return most_active, traffic_counts
    except Exception as e:
        print(f"[ERROR] get_most_active_interface failed: {e}")
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
        try:
            print(f"[DEBUG] Starting packet sniffing on interface: {self.interface}")
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            print(f"[ERROR] Failed to capture packets: {e}")

    def packet_callback(self, packet):
        if IP not in packet:
            return

        ip_layer = packet[IP]

        if self.filter_ip and (ip_layer.src != self.filter_ip and ip_layer.dst != self.filter_ip):
            return
        if self.filter_protocol and ip_layer.proto != self.filter_protocol:
            return

        classification = self.classify_packet(packet)
        now = int(time.time())

        with self.lock:
            self.packet_counts[now] += 1
            if classification.startswith("Suspicious"):
                self.suspicious_counts[now] += 1

            self.packets.append(packet)
            self.packet_times.append(datetime.now())
            self.timestamps.append(now)

        if self.packet_callback_gui:
            log_line = f"{datetime.now().strftime('%H:%M:%S')} | {classification} | {ip_layer.src} → {ip_layer.dst}"
            print(f"[DEBUG] Captured: {log_line}")
            self.packet_callback_gui(log_line, classification)

    def classify_packet(self, packet):
        if IP in packet:
            ip = packet[IP]
            if ip.ttl > 200:
                return "Suspicious (High TTL)"
            if ip.proto == 1:
                return "Suspicious (ICMP)"
            if hasattr(packet, 'sport') and packet.sport == 4444:
                return "Suspicious (Suspicious Src Port)"
            if hasattr(packet, 'dport') and packet.dport == 4444:
                return "Suspicious (Suspicious Dst Port)"
        return "Normal"

# Test usage (standalone)
if __name__ == "__main__":
    iface, stats = get_most_active_interface()
    print(f"Most active interface: {iface} ({stats.get(iface, 0)} packets)")
    sniffer = PacketSniffer(interface=iface)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping sniffer...")
        sniffer.stop()
