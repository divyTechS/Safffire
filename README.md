# 🔥 Safffire – Advanced Packet Sniffer with Suspicious Traffic Detection

Safffire is a **PyQt5-based packet sniffer and analyzer** built on top of [Scapy](https://scapy.net/).  
It provides a modern GUI, real-time plotting, filtering, and automatic detection of suspicious packets (using simple heuristic rules).

---

## ✨ Features
- 🌐 **Automatic Interface Detection** – Finds and suggests the most active network interface.
- 📊 **Live Graphs** – Real-time visualization of normal vs suspicious traffic.
- 🔎 **Packet Inspection** – View detailed info of any captured packet.
- 🎛 **Filtering** – Filter by IP address or protocol (TCP, UDP, ICMP).
- ⚠️ **Suspicious Packet Detection** – Flags packets with:
  - Abnormally high TTL
  - ICMP traffic
  - Source/Destination port `4444`
- 📂 **Save & Export** – Save captured packets as `.pcap` for later analysis (Wireshark compatible).
- 🧾 **Suspicious Log** – Logs flagged packets into `suspicious_log.txt`.
- 🎨 **Dark Mode UI** with custom fonts and icons.

---

## 🛠 Requirements

Install dependencies before running:

```bash
sudo apt update
sudo apt install python3-pip python3-pyqt5
pip3 install scapy matplotlib pyqt5
⚠️ Note: Packet sniffing requires root privileges.

🚀 How to Run
Clone this repo and start the app:

bash
Copy code
git clone https://github.com/divyTechS/Safffire.git
cd Safffire
sudo python3 main.py
sudo is required because raw packet capture needs elevated permissions.

📷 Screenshots
(Add your screenshots here, e.g. GUI, graphs, suspicious log window.)

📂 Project Structure
bash
Copy code
Safffire/
│── main.py              # Main PyQt5 GUI application
│── suspicious_log.txt   # Generated log of suspicious packets
│── README.md            # Project documentation
│── logo.png             # App icon/logo
│── Orbitron.ttf         # Custom font
📝 Usage Guide
Select the network interface from the dropdown.

Click Start Capturing to begin sniffing packets.

Apply filters (IP / protocol) if needed.

View real-time graphs & packet logs.

Inspect packet details by entering its index.

Save packets to .pcap for Wireshark analysis.

Check suspicious logs via the "View Suspicious Log" button.

⚠️ Disclaimer
This tool is intended for educational and research purposes only.
Do not use it for malicious activities. You are responsible for your usage.

👨‍💻 Author
Developed by Divyesh Shivdas Swarge