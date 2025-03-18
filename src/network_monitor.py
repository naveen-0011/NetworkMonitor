import logging
import signal
import sys
import time
import threading
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sniff
import geoip2.database
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog

# Load GeoLite2 Database
GEO_DB_PATH = r"D:\Network Monitor\GeoLite2-City.mmdb"
geo_reader = geoip2.database.Reader(GEO_DB_PATH)

# Setup logging
logging.basicConfig(
    filename=r"D:\Network Monitor\network_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Packet counters and bandwidth calculation
tcp_total = 0
udp_total = 0
icmp_total = 0
error_count = 0
total_bytes = 0
start_time = time.time()
running = False
selected_protocol = "ALL"
filter_ip = ""
packet_count = 0

# Protocol map for readability
PROTOCOL_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}

# Threat detection storage
connection_attempts = defaultdict(int)
last_seen = defaultdict(float)


# Function to get geolocation details from IP
def get_geolocation(ip):
    try:
        location = geo_reader.city(ip)
        country = location.country.name
        city = location.city.name or "Unknown City"
        return f"{country}, {city}"
    except:
        return "Unknown Location"


# Function to display packet info
def packet_callback(packet):
    global tcp_total, udp_total, icmp_total, total_bytes, packet_count, error_count

    if not running:
        return

    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_num = packet[IP].proto
            protocol = PROTOCOL_MAP.get(protocol_num, f"Unknown ({protocol_num})")
            total_bytes += len(packet)
            packet_count += 1

            # Filter by IP if set
            if filter_ip and src_ip != filter_ip:
                return

            # Get geolocation details
            geolocation = get_geolocation(src_ip)

            log_message = ""

            # TCP Packet
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                tcp_total += 1
                log_message = f"{protocol} Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port} ({geolocation})"

            # UDP Packet
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                udp_total += 1
                log_message = f"{protocol} Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port} ({geolocation})"

            # ICMP Packet
            elif ICMP in packet:
                icmp_total += 1
                log_message = f"{protocol} Packet: {src_ip} --> {dst_ip} ({geolocation})"

            # If filtering is enabled, match selected protocol
            if selected_protocol == "ALL" or selected_protocol == protocol:
                log_packet(log_message)
                logging.info(log_message)

    except Exception:
        error_count += 1


# Function to log packets in GUI
def log_packet(message):
    output_text.insert(tk.END, message + "\n")
    output_text.see(tk.END)


# Function to start sniffing
def start_sniffing():
    global running, start_time, packet_count
    if not running:
        running = True
        start_time = time.time()
        packet_count = 0
        output_text.insert(tk.END, "\n[+] Starting packet capture...\n")
        sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=0))
        sniff_thread.daemon = True
        sniff_thread.start()
        update_stats()


# Function to stop sniffing and show summary
def stop_sniffing():
    global running
    if running:
        running = False
        end_time = time.time()
        duration = end_time - start_time
        bandwidth = (total_bytes * 8) / (duration * 1000) if duration > 0 else 0

        summary = f"""
=== Traffic Summary ===
Total TCP Packets: {tcp_total}
Total UDP Packets: {udp_total}
Total ICMP Packets: {icmp_total}
Total Data Transferred: {total_bytes / 1024:.2f} KB
Average Bandwidth: {bandwidth:.2f} Kbps
Error Rate: {(error_count / packet_count * 100) if packet_count > 0 else 0:.2f}%
        """
        output_text.insert(tk.END, summary)
        output_text.see(tk.END)


# Function to export logs to a file
def export_logs():
    log_data = output_text.get("1.0", tk.END)
    if not log_data.strip():
        messagebox.showwarning("No Data", "No log data to export.")
        return

    file = filedialog.asksaveasfilename(defaultextension=".txt",
                                        filetypes=[("Text files", "*.txt"),
                                                   ("All files", "*.*")])
    if file:
        with open(file, "w") as f:
            f.write(log_data)
        messagebox.showinfo("Export Complete", f"Logs exported to {file}")


# Function to update real-time stats
def update_stats():
    if running:
        current_time = time.time()
        duration = current_time - start_time
        packet_rate = packet_count / duration if duration > 0 else 0
        error_rate = (error_count / packet_count * 100) if packet_count > 0 else 0
        tcp_percent = (tcp_total / packet_count * 100) if packet_count > 0 else 0
        udp_percent = (udp_total / packet_count * 100) if packet_count > 0 else 0
        icmp_percent = (icmp_total / packet_count * 100) if packet_count > 0 else 0

        stats_label.config(text=f"""
Packets/sec: {packet_rate:.2f}
Error Rate: {error_rate:.2f}%
TCP: {tcp_percent:.2f}%  |  UDP: {udp_percent:.2f}%  |  ICMP: {icmp_percent:.2f}%
        """)

        window.after(1000, update_stats)


# GUI Setup
window = tk.Tk()
window.title("Network Monitor")
window.geometry("800x600")

# Start and Stop Buttons
btn_start = tk.Button(window, text="Start", width=15, command=start_sniffing, bg="green", fg="white")
btn_start.grid(row=0, column=0, padx=5, pady=5)

btn_stop = tk.Button(window, text="Stop", width=15, command=stop_sniffing, bg="red", fg="white")
btn_stop.grid(row=0, column=1, padx=5, pady=5)

# Output Window
output_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=100, height=25)
output_text.grid(row=1, column=0, columnspan=5, padx=5, pady=5)

# Stats Display
stats_label = tk.Label(window, text="", font=("Courier", 10), justify="left")
stats_label.grid(row=2, column=0, columnspan=5, padx=5, pady=5)

# Export and Exit Buttons
btn_export = tk.Button(window, text="Export Logs", width=15, command=export_logs, bg="blue", fg="white")
btn_export.grid(row=3, column=0, padx=5, pady=5)

btn_exit = tk.Button(window, text="Exit", width=15, command=window.quit, bg="gray", fg="white")
btn_exit.grid(row=3, column=1, padx=5, pady=5)

# Start GUI
window.mainloop()

