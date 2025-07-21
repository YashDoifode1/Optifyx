import tkinter as tk
from tkinter import ttk, messagebox
import scapy.all as scapy
import threading
import time
import json
import csv
import re
from datetime import datetime
import queue
import logging
from collections import defaultdict
import netifaces  # New dependency for listing interfaces

class IntrusionDetectionSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Signature-Based IDS")
        self.root.geometry("800x600")
        self.default_bg = "white"
        self.root.configure(bg=self.default_bg)
        
        # Packet and threat counters
        self.packet_count = 0
        self.threat_count = 0
        self.packet_queue = queue.Queue()
        self.is_sniffing = False
        self.selected_interface = None
        
        # Signature database
        self.signatures = {
            "syn_flood": {
                "pattern": lambda pkt: pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].flags == "S",
                "threshold": 10,  # SYN packets in 5 seconds
                "time_window": 5,
                "description": "SYN Flood"
            },
            "sql_injection": {
                "pattern": lambda pkt: pkt.haslayer(scapy.Raw) and any(keyword in pkt[scapy.Raw].load.decode('utf-8', errors='ignore').lower() 
                    for keyword in ["select", "drop", "union"]),
                "description": "SQL Injection"
            },
            "port_scan": {
                "pattern": lambda pkt: pkt.haslayer(scapy.TCP),
                "threshold": 10,  # Different ports in 5 seconds
                "time_window": 5,
                "description": "Port Scan"
            }
        }
        
        # Track activity for threshold-based detection
        self.activity_tracker = {
            "syn_flood": defaultdict(lambda: {"count": 0, "time": time.time()}),
            "port_scan": defaultdict(lambda: {"ports": set(), "time": time.time()})
        }
        
        # Setup logging
        self.setup_logging()
        self.setup_gui()
        
        # Start packet processing thread
        self.process_thread = threading.Thread(target=self.process_packets)
        self.process_thread.daemon = True
        self.process_thread.start()
        
    def setup_logging(self):
        logging.basicConfig(filename='ids_log.csv', level=logging.INFO,
                          format='%(asctime)s,%(message)s')
        with open('ids_log.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Alert Type'])
            
    def setup_gui(self):
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        ttk.Label(self.main_frame, text="Signature-Based Intrusion Detection System", 
                 font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        
        # Interface selection
        self.interface_frame = ttk.LabelFrame(self.main_frame, text="Network Interface", padding="5")
        self.interface_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        self.interface_var = tk.StringVar()
        interfaces = self.get_network_interfaces()
        if not interfaces:
            messagebox.showerror("Error", "No network interfaces found. Please check your network configuration.")
            self.root.quit()
            return
        
        ttk.Label(self.interface_frame, text="Select Interface:").grid(row=0, column=0, padx=5)
        self.interface_combo = ttk.Combobox(self.interface_frame, textvariable=self.interface_var, values=interfaces)
        self.interface_combo.grid(row=0, column=1, padx=5)
        self.interface_combo.current(0)  # Select first interface by default
        
        # Packet display
        self.packet_text = tk.Text(self.main_frame, height=20, width=80)
        self.packet_text.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Status frame
        self.status_frame = ttk.LabelFrame(self.main_frame, text="Status", padding="5")
        self.status_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Status labels
        self.packet_label = ttk.Label(self.status_frame, text="Total Packets: 0")
        self.packet_label.grid(row=0, column=0, padx=5)
        self.threat_label = ttk.Label(self.status_frame, text="Threats Detected: 0")
        self.threat_label.grid(row=0, column=1, padx=5)
        self.status_label = ttk.Label(self.status_frame, text="Status: Normal")
        self.status_label.grid(row=1, column=0, columnspan=2, pady=5)
        
        # Start/Stop button
        self.start_button = ttk.Button(self.main_frame, text="Start Sniffing", command=self.toggle_sniffing)
        self.start_button.grid(row=4, column=0, columnspan=2, pady=10)
        
    def get_network_interfaces(self):
        try:
            return netifaces.interfaces()
        except Exception as e:
            logging.error(f"Error getting network interfaces: {str(e)}")
            return []
            
    def toggle_sniffing(self):
        if not self.is_sniffing:
            self.selected_interface = self.interface_var.get()
            if not self.selected_interface:
                messagebox.showerror("Error", "Please select a valid network interface.")
                return
            self.is_sniffing = True
            self.start_button.configure(text="Stop Sniffing")
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
        else:
            self.is_sniffing = False
            self.start_button.configure(text="Start Sniffing")
            
    def sniff_packets(self):
        try:
            scapy.sniff(iface=self.selected_interface, prn=self.packet_callback, store=False)
        except Exception as e:
            self.update_status(f"Error sniffing packets: {str(e)}")
            messagebox.showerror("Error", f"Failed to sniff packets on {self.selected_interface}: {str(e)}")
            self.is_sniffing = False
            self.start_button.configure(text="Start Sniffing")
            
    def packet_callback(self, packet):
        self.packet_queue.put(packet)
        
    def process_packets(self):
        while True:
            try:
                packet = self.packet_queue.get(timeout=1)
                self.packet_count += 1
                self.update_gui(packet)
                self.analyze_packet(packet)
            except queue.Empty:
                continue
                
    def update_gui(self, packet):
        # Update packet count
        self.packet_label.configure(text=f"Total Packets: {self.packet_count}")
        
        # Display packet info
        packet_info = self.get_packet_info(packet)
        self.packet_text.insert(tk.END, packet_info + "\n")
        self.packet_text.see(tk.END)
        
    def get_packet_info(self, packet):
        src_ip = dst_ip = protocol = src_port = dst_port = "N/A"
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                if packet.haslayer(scapy.TCP):
                    src_port = packet[scapy.TCP].sport
                    dst_port = packet[scapy.TCP].dport
                elif packet.haslayer(scapy.UDP):
                    src_port = packet[scapy.UDP].sport
                    dst_port = packet[scapy.UDP].dport
        except:
            pass
        return f"Src: {src_ip}:{src_port} -> Dst: {dst_ip}:{dst_port} Proto: {protocol}"
        
    def analyze_packet(self, packet):
        current_time = time.time()
        
        # Check each signature
        for attack_type, signature in self.signatures.items():
            try:
                if signature["pattern"](packet):
                    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "Unknown"
                    
                    if attack_type == "syn_flood":
                        tracker = self.activity_tracker["syn_flood"][src_ip]
                        tracker["count"] += 1
                        if current_time - tracker["time"] > signature["time_window"]:
                            tracker["count"] = 1
                            tracker["time"] = current_time
                        if tracker["count"] >= signature["threshold"]:
                            self.trigger_alert(attack_type, src_ip, packet)
                            
                    elif attack_type == "port_scan":
                        tracker = self.activity_tracker["port_scan"][src_ip]
                        if packet.haslayer(scapy.TCP):
                            tracker["ports"].add(packet[scapy.TCP].dport)
                        if current_time - tracker["time"] > signature["time_window"]:
                            tracker["ports"] = set()
                            tracker["time"] = current_time
                        if len(tracker["ports"]) >= signature["threshold"]:
                            self.trigger_alert(attack_type, src_ip, packet)
                            
                    elif attack_type == "sql_injection":
                        self.trigger_alert(attack_type, src_ip, packet)
            except Exception as e:
                logging.error(f"Error analyzing packet: {str(e)}")
                
    def trigger_alert(self, attack_type, src_ip, packet):
        self.threat_count += 1
        self.threat_label.configure(text=f"Threats Detected: {self.threat_count}")
        self.update_status(f"Suspicious Activity Detected: {self.signatures[attack_type]['description']} from {src_ip}")
        
        # Change background to red
        self.root.configure(bg="red")
        self.root.after(10000, lambda: self.root.configure(bg=self.default_bg) if not self.is_sniffing else None)
        
        # Log the alert
        self.log_alert(attack_type, src_ip, packet)
        
    def update_status(self, message):
        self.status_label.configure(text=f"Status: {message}")
        
    def log_alert(self, attack_type, src_ip, packet):
        dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "Unknown"
        protocol = packet[scapy.IP].proto if packet.haslayer(scapy.IP) else "Unknown"
        with open('ids_log.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([datetime.now().isoformat(), src_ip, dst_ip, protocol, 
                           self.signatures[attack_type]["description"]])

def main():
    root = tk.Tk()
    app = IntrusionDetectionSystem(root)
    root.mainloop()

if __name__ == "__main__":
    main()