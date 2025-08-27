import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, deque
from datetime import datetime
import threading
import time

packet_counts = defaultdict(int)  # key: second, value: count
lock = threading.Lock()
running = True

# Track up to 60 seconds for live plot
time_window = deque(maxlen=60)
count_window = deque(maxlen=60)

def packet_callback(packet):
    global packet_counts
    if IP in packet:
        now = int(time.time())
        with lock:
            packet_counts[now] += 1

def capture_packets():
    sniff(prn=packet_callback, store=0)

def update_plot():
    plt.ion()
    fig, ax = plt.subplots()
    ax.set_title("Packets per Second (Live)")
    ax.set_xlabel("Time (HH:MM:SS)")
    ax.set_ylabel("Packets")

    while running:
        with lock:
            now = int(time.time())
            time_window.clear()
            count_window.clear()

            for i in range(60):
                t = now - 59 + i
                time_str = datetime.fromtimestamp(t).strftime("%H:%M:%S")
                time_window.append(time_str)
                count_window.append(packet_counts.get(t, 0))

        ax.clear()
        ax.plot(list(time_window), list(count_window), color='cyan', marker='o')
        ax.set_xticklabels(time_window, rotation=45, ha='right', fontsize=8)
        ax.set_title("Packets per Second (Live)")
        ax.set_xlabel("Time (HH:MM:SS)")
        ax.set_ylabel("Packets")
        plt.tight_layout()
        plt.pause(1)

try:
    print("[*] Starting live capture and graph...")
    threading.Thread(target=capture_packets, daemon=True).start()
    update_plot()
except KeyboardInterrupt:
    running = False
    print("\n[*] Stopping...")
