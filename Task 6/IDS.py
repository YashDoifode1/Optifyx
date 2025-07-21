import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP
import time
import csv
from datetime import datetime
import threading
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest
import json

class IntrusionDetectionSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.is_monitoring = False
        self.packet_counts = defaultdict(int)
        self.traffic_history = []
        self.blacklist = {"192.168.1.100", "10.0.0.50"}  # Example IP blacklist
        self.alerts = []
        
        # Port rules for professional and personal profiles
        self.port_profiles = {
            "Professional": {
                "allowed_ports": [80, 443, 22, 3389],  # Common for business (HTTP, HTTPS, SSH, RDP)
                "restricted_ports": [23, 445, 1433, 3306]  # Telnet, SMB, MSSQL, MySQL
            },
            "Personal": {
                "allowed_ports": [80, 443, 25, 110, 143],  # Common for home (HTTP, HTTPS, SMTP, POP3, IMAP)
                "restricted_ports": [445, 137, 138, 139]  # SMB, NetBIOS
            }
        }
        self.current_profile = "Professional"  # Default profile
        
        # GUI Components
        self.setup_gui()
        
        # Anomaly Detection Model
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.traffic_baseline = []
        
        # Log File
        self.log_file = "ids_alerts.csv"
        self.initialize_log()

    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Profile selection
        ttk.Label(main_frame, text="Profile:").grid(row=0, column=0, padx=5, pady=5)
        self.profile_var = tk.StringVar(value=self.current_profile)
        profile_combo = ttk.Combobox(main_frame, textvariable=self.profile_var, 
                                   values=list(self.port_profiles.keys()), state="readonly")
        profile_combo.grid(row=0, column=1, padx=5, pady=5)
        profile_combo.bind("<<ComboboxSelected>>", self.update_profile)
        
        # Control buttons
        self.start_button = ttk.Button(main_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)
        
        self.stop_button = ttk.Button(main_frame, text="Stop Monitoring", command=self.stop_monitoring, state="disabled")
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)
        
        # Alert display
        self.alert_text = tk.Text(main_frame, height=15, width=80)
        self.alert_text.grid(row=1, column=0, columnspan=4, pady=10)
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Status: Idle")
        self.status_label.grid(row=2, column=0, columnspan=4, pady=5)
        
        # Log button
        ttk.Button(main_frame, text="Save Log", command=self.save_log).grid(row=3, column=0, columnspan=4, pady=5)

    def initialize_log(self):
        with open(self.log_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Port', 'Threat Type', 'Description'])

    def update_profile(self, event=None):
        self.current_profile = self.profile_var.get()
        self.alert_text.insert(tk.END, f"Profile switched to {self.current_profile}\n")
        self.alert_text.see(tk.END)

    def start_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.status_label.config(text="Status: Monitoring")
            self.alert_text.delete(1.0, tk.END)
            
            # Start packet capture in a separate thread
            self.monitor_thread = threading.Thread(target=self.capture_packets)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            
            # Start anomaly detection updates
            self.update_anomaly_detection()

    def stop_monitoring(self):
        self.is_monitoring = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Status: Idle")

    def capture_packets(self):
        try:
            sniff(prn=self.process_packet, filter="ip", store=0, stop_filter=lambda x: not self.is_monitoring)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Packet capture failed: {str(e)}"))

    def process_packet(self, packet):
        if not self.is_monitoring:
            return
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            port = None
            packet_size = len(packet)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if TCP in packet:
                port = packet[TCP].dport
                protocol_name = "TCP"
            elif UDP in packet:
                port = packet[UDP].dport
                protocol_name = "UDP"
            else:
                protocol_name = "Other"
            
            # Pattern matching detection
            threat_type, description = self.pattern_matching(src_ip, dst_ip, port, protocol_name)
            
            # Update traffic history for anomaly detection
            self.traffic_history.append([packet_size, 1 if port in self.port_profiles[self.current_profile]["allowed_ports"] else 0])
            
            if threat_type:
                alert = {
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol_name,
                    'port': port,
                    'threat_type': threat_type,
                    'description': description
                }
                self.alerts.append(alert)
                self.log_alert(alert)
                self.root.after(0, lambda: self.display_alert(alert))
                
            # Update packet counts
            self.packet_counts[src_ip] += 1

    def pattern_matching(self, src_ip, dst_ip, port, protocol):
        # Check for blacklisted IPs
        if src_ip in self.blacklist or dst_ip in self.blacklist:
            return "Blacklist", f"Suspicious IP detected: {src_ip} -> {dst_ip}"
        
        # Check for port scanning behavior
        if self.packet_counts[src_ip] > 100:  # Threshold for potential port scan
            return "Port Scan", f"High packet count from {src_ip}"
        
        # Check port rules based on current profile
        if port:
            if port in self.port_profiles[self.current_profile]["restricted_ports"]:
                return "Restricted Port", f"Access to restricted port {port} in {self.current_profile} profile"
            if port not in self.port_profiles[self.current_profile]["allowed_ports"]:
                return "Unusual Port", f"Access to non-allowed port {port} in {self.current_profile} profile"
        
        return None, None

    def update_anomaly_detection(self):
        if not self.is_monitoring:
            return
        
        if len(self.traffic_history) > 100:  # Enough data for anomaly detection
            X = np.array(self.traffic_history[-100:])
            predictions = self.model.fit_predict(X)
            
            if predictions[-1] == -1:  # Anomaly detected
                alert = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'src_ip': 'N/A',
                    'dst_ip': 'N/A',
                    'protocol': 'N/A',
                    'port': 'N/A',
                    'threat_type': 'Anomaly',
                    'description': f"Unusual traffic pattern detected in {self.current_profile} profile"
                }
                self.alerts.append(alert)
                self.log_alert(alert)
                self.root.after(0, lambda: self.display_alert(alert))
        
        self.root.after(1000, self.update_anomaly_detection)

    def log_alert(self, alert):
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                alert['timestamp'],
                alert['src_ip'],
                alert['dst_ip'],
                alert['protocol'],
                alert['port'],
                alert['threat_type'],
                alert['description']
            ])

    def display_alert(self, alert):
        alert_text = (f"[{alert['timestamp']}] {alert['threat_type']} - "
                     f"{alert['src_ip']} -> {alert['dst_ip']} "
                     f"({alert['protocol']}:{alert['port']}) {alert['description']}\n")
        self.alert_text.insert(tk.END, alert_text)
        self.alert_text.see(tk.END)
        messagebox.showwarning("Threat Detected", f"{alert['threat_type']}: {alert['description']}")

    def save_log(self):
        with open("ids_report.json", 'w') as f:
            json.dump(self.alerts, f, indent=2)
        messagebox.showinfo("Success", "Log saved as ids_report.json")

if __name__ == "__main__":
    root = tk.Tk()
    app = IntrusionDetectionSystem(root)
    root.mainloop()