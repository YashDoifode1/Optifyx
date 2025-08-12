import socket
import struct
import collections
import time
import threading
import logging
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, Listbox
import smtplib
from email.mime.text import MIMEText
from plyer import notification
import win32evtlog
import win32evtlogutil
import socket as socket_lib
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from io import StringIO
import os
import psutil  # For local listening ports

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler('ids_log.txt'),
        logging.StreamHandler()
    ]
)

# Constants
DEFAULT_SYN_FLOOD_THRESHOLD = 5
DEFAULT_PORT_SCAN_THRESHOLD = 10
SUSPICIOUS_KEYWORDS = [b'evil', b'malicious']
CLEAR_INTERVAL = 60
METRICS_INTERVAL = 10
DEBUG_MODE = True
ALERT_COOLDOWN = 10
PORT_SERVICES = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 8080: 'HTTP-Alt', 445: 'SMB', 135: 'RPC'}
LISTENING_REFRESH = 30  # Seconds to refresh local listening ports

class IDSMonitor:
    def __init__(self, syn_threshold: int, port_threshold: int):
        self.syn_threshold = syn_threshold
        self.port_threshold = port_threshold
        self.syn_tracker = collections.defaultdict(int)
        self.port_tracker = collections.defaultdict(set)
        self.open_ports = {}  # port -> {'service': str, 'time': str, 'status': str, 'source': str} ('detected' or 'local')
        self.last_clear_time = time.time()
        self.running = False
        self.conn = None
        self.log_callback = None
        self.alert_callback = None
        self.packet_count = 0
        self.pps = 0
        self.last_metrics_time = time.time()
        self.local_ip = '10.105.155.111'  # Change to '127.0.0.1' if needed
        self.email_config = {}
        self.total_alerts = 0
        self.alert_history = collections.defaultdict(float)
        self.local_listening_ports = {}  # Separate for local listening

    def enable_promiscuous_mode(self):
        SIO_RCVALL = 0x98000001
        try:
            self.conn.ioctl(SIO_RCVALL, 1)
            logging.info("Promiscuous mode enabled.")
            self.log_callback("Promiscuous mode enabled.\n", "info")
        except OSError as e:
            logging.warning(f"Promiscuous mode failed: {e}. Capturing local traffic only.")
            self.log_callback(f"Warning: Promiscuous mode failed: {e}. Capturing local traffic only on {self.local_ip}.\n", "warning")

    def start(self, log_callback, alert_callback):
        self.log_callback = log_callback
        self.alert_callback = alert_callback
        self.running = True

        # Log interfaces
        try:
            import netifaces
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for addr in addrs:
                    ip = addr.get('addr')
                    if ip:
                        logging.info(f"Interface: {iface}, IP: {ip}")
                        self.log_callback(f"Interface: {iface}, IP: {ip}\n", "info")
        except Exception as e:
            logging.warning(f"Error listing interfaces: {e}. Continuing without interface list.")
            self.log_callback(f"Warning: Error listing interfaces: {e}.\n", "warning")

        # Socket creation
        for proto in [socket.IPPROTO_IP, socket.IPPROTO_RAW, socket.IPPROTO_TCP]:
            for attempt in range(3):
                try:
                    self.conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                    self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.conn.settimeout(1.0)
                    self.conn.bind((self.local_ip, 0))
                    self.enable_promiscuous_mode()
                    logging.info(f"IDS started with protocol {proto}, bound to {self.local_ip}.")
                    self.log_callback(f"IDS started with protocol {proto}, bound to {self.local_ip}.\n", "info")
                    break
                except OSError as e:
                    logging.error(f"Socket error with protocol {proto}, attempt {attempt + 1}: {e}")
                    self.log_callback(f"Socket error with protocol {proto}, attempt {attempt + 1}: {e}\n", "error")
                    time.sleep(1)
                if attempt == 2:
                    self.log_callback(f"Failed to start with protocol {proto}.\n", "error")
            else:
                continue
            break
        else:
            self.log_callback("All socket protocols failed. Check admin privileges, Npcap, firewall, and conflicts.\n", "error")
            return

        threading.Thread(target=self._monitor_loop, daemon=True).start()
        threading.Thread(target=self._monitor_firewall_logs, daemon=True).start()
        threading.Thread(target=self._update_metrics, daemon=True).start()
        threading.Thread(target=self._update_local_listening, daemon=True).start()  # New thread for local listening

    def stop(self):
        self.running = False
        if self.conn:
            self.conn.close()
        logging.info("IDS monitoring stopped.")
        if self.log_callback:
            self.log_callback("IDS monitoring stopped.\n", "info")

    def _check_alert_cooldown(self, alert_key):
        current_time = time.time()
        if current_time - self.alert_history[alert_key] < ALERT_COOLDOWN:
            return False
        self.alert_history[alert_key] = current_time
        return True

    def _monitor_loop(self):
        while self.running:
            current_time = time.time()
            if current_time - self.last_clear_time > CLEAR_INTERVAL:
                self.syn_tracker.clear()
                self.port_tracker.clear()
                self.last_clear_time = current_time

            try:
                raw_buffer, _ = self.conn.recvfrom(65535)
                self.packet_count += 1
                if DEBUG_MODE:
                    logging.debug(f"Raw packet (first 20 bytes): {raw_buffer[:20].hex()}")
            except (OSError, socket.timeout):
                time.sleep(0.01)
                continue

            try:
                iph = struct.unpack('!BBHHHBBH4s4s', raw_buffer[:20])
            except struct.error:
                continue

            ihl = iph[0] & 0xF
            iph_length = ihl * 4
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            if protocol == 1:  # ICMP
                icmp_offset = iph_length
                try:
                    icmph = struct.unpack('!BBHHH', raw_buffer[icmp_offset:icmp_offset + 8])
                    icmp_type = icmph[0]
                    icmp_code = icmph[1]
                    if icmp_type == 3:
                        alert_key = f"icmp_{src_ip}_{dst_ip}_{icmp_type}_{icmp_code}"
                        if self._check_alert_cooldown(alert_key):
                            alert = f"Network Error Detected: ICMP Destination Unreachable (Type: {icmp_type}, Code: {icmp_code}) from {src_ip} to {dst_ip}"
                            self.total_alerts += 1
                            logging.warning(alert)
                            self.log_callback(alert + "\n", "warning")
                            self.alert_callback(alert)
                except struct.error:
                    continue

            if protocol == 6:  # TCP
                tcp_offset = iph_length
                try:
                    tcph = struct.unpack('!HHLLBBHHH', raw_buffer[tcp_offset:tcp_offset + 20])
                except struct.error:
                    continue

                src_port = tcph[0]
                dst_port = tcph[1]
                flags = tcph[5]
                tcph_length = (tcph[4] >> 4) * 4

                if src_ip == self.local_ip and (flags & 0x12) == 0x12:
                    if src_port not in self.open_ports:
                        service = PORT_SERVICES.get(src_port, "Unknown")
                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                        self.open_ports[src_port] = {'service': service, 'time': timestamp, 'status': 'Open', 'source': 'Detected'}
                        alert_key = f"open_port_{src_port}"
                        if self._check_alert_cooldown(alert_key):
                            alert = f"Open Port Detected: Port {src_port} ({service}) on local machine ({self.local_ip}) at {timestamp}"
                            logging.info(alert)
                            self.log_callback(alert + "\n", "info")
                            self.alert_callback(alert)

                if (flags & 0x02) and not (flags & 0x10):
                    syn_key = (src_ip, dst_ip, dst_port)
                    self.syn_tracker[syn_key] += 1
                    if self.syn_tracker[syn_key] > self.syn_threshold:
                        alert_key = f"syn_flood_{src_ip}_{dst_ip}_{dst_port}"
                        if self._check_alert_cooldown(alert_key):
                            alert = f"Possible SYN Flood Detected: From {src_ip} to {dst_ip}:{dst_port} (SYN count: {self.syn_tracker[syn_key]})"
                            self.total_alerts += 1
                            logging.warning(alert)
                            self.log_callback(alert + "\n", "warning")
                            self.alert_callback(alert)

                self.port_tracker[src_ip].add(dst_port)
                if len(self.port_tracker[src_ip]) > self.port_threshold:
                    alert_key = f"port_scan_{src_ip}"
                    if self._check_alert_cooldown(alert_key):
                        alert = f"Possible Port Scan Detected: From {src_ip} (Scanned {len(self.port_tracker[src_ip])} ports)"
                        self.total_alerts += 1
                        logging.warning(alert)
                        self.log_callback(alert + "\n", "warning")
                        self.alert_callback(alert)

                payload_offset = tcp_offset + tcph_length
                payload = raw_buffer[payload_offset:]
                for keyword in SUSPICIOUS_KEYWORDS:
                    if keyword in payload:
                        alert_key = f"payload_{src_ip}_{dst_ip}_{src_port}_{dst_port}_{keyword.decode()}"
                        if self._check_alert_cooldown(alert_key):
                            alert = f"Suspicious Payload Detected: '{keyword.decode()}' from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                            self.total_alerts += 1
                            logging.warning(alert)
                            self.log_callback(alert + "\n", "warning")
                            self.alert_callback(alert)
                            break

    def _update_local_listening(self):
        while self.running:
            local_ports = {}
            for conn in psutil.net_connections(kind='tcp'):
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    pid = conn.pid if conn.pid else "System"
                    process_name = psutil.Process(pid).name() if pid != "System" else "System"
                    service = PORT_SERVICES.get(port, "Unknown")
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    local_ports[port] = {'service': service, 'time': timestamp, 'status': 'Listening', 'source': 'Local', 'pid': pid, 'process': process_name}

            self.local_listening_ports = local_ports
            # Merge into open_ports if not already detected
            for port, info in local_ports.items():
                if port not in self.open_ports:
                    self.open_ports[port] = info
            time.sleep(LISTENING_REFRESH)

    def _monitor_firewall_logs(self):
        server = 'localhost'
        logtype = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            hand = win32evtlog.OpenEventLog(server, logtype)
            last_event_time = None
            while self.running:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for event in events:
                    event_time = event.TimeGenerated.Format()
                    if last_event_time == event_time:
                        continue
                    last_event_time = event_time
                    event_id = event.EventID & 0xFFFF
                    if event_id in [2004, 2006]:
                        desc = win32evtlogutil.SafeFormatMessage(event, logtype)
                        alert_key = f"firewall_{event_id}_{event_time}"
                        if self._check_alert_cooldown(alert_key):
                            alert = f"Firewall Event Detected: ID {event_id} at {event_time}, Details: {desc[:100]}..."
                            self.total_alerts += 1
                            logging.warning(alert)
                            self.log_callback(alert + "\n", "warning")
                            self.alert_callback(alert)
                time.sleep(1)
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logging.error(f"Firewall log error: {e}")
            if self.log_callback:
                self.log_callback(f"Firewall log error: {e}\n", "error")

    def _update_metrics(self):
        while self.running:
            time.sleep(METRICS_INTERVAL)
            current_time = time.time()
            elapsed = current_time - self.last_metrics_time
            if elapsed > 0:
                self.pps = self.packet_count / elapsed
            if self.pps < 0.1:
                self.log_callback("WARNING: Low PPS. Generate traffic (e.g., 'ping 10.105.155.111' or 'nmap 10.105.155.111') to test. If PPS stays low, change self.local_ip to '127.0.0.1' in code and restart.\n", "warning")
            self.packet_count = 0
            self.last_metrics_time = current_time
            if self.log_callback:
                self.log_callback(f"METRICS: Packets per second: {self.pps:.2f}\n", "info")

    def update_thresholds(self, syn_threshold: int, port_threshold: int):
        self.syn_threshold = syn_threshold
        self.port_threshold = port_threshold
        logging.info(f"Thresholds updated: SYN Flood={self.syn_threshold}, Port Scan={self.port_threshold}")
        self.log_callback(f"Thresholds updated: SYN Flood={self.syn_threshold}, Port Scan={self.port_threshold}\n", "info")

    def update_email_config(self, smtp_server, smtp_port, sender, password, recipient):
        self.email_config = {
            'server': smtp_server,
            'port': smtp_port,
            'sender': sender,
            'password': password,
            'recipient': recipient
        }
        logging.info("Email config updated.")
        self.log_callback("Email config updated.\n", "info")

    def send_email_alert(self, alert):
        if not self.email_config:
            return
        try:
            msg = MIMEText(f"IDS Alert Summary:\n\n{alert}\n\nTotal Alerts: {self.total_alerts}")
            msg['Subject'] = 'IDS Alert Notification'
            msg['From'] = self.email_config['sender']
            msg['To'] = self.email_config['recipient']
            with smtplib.SMTP(self.email_config['server'], self.email_config['port']) as server:
                server.starttls()
                server.login(self.email_config['sender'], self.email_config['password'])
                server.sendmail(self.email_config['sender'], self.email_config['recipient'], msg.as_string())
            logging.info(f"Email alert sent: {alert}")
            self.log_callback(f"Email alert sent: {alert}\n", "info")
        except Exception as e:
            logging.error(f"Email send error: {e}")
            self.log_callback(f"Email send error: {e}\n", "error")

# [Previous imports remain the same...]

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enterprise Intrusion Detection System")
        self.root.geometry("1400x900")
        self.root.configure(bg="#f5f5f5")
        
        # Set window icon (replace with your own icon if available)
        try:
            self.root.iconbitmap('shield.ico')  # Optional: Add a security shield icon
        except:
            pass

        self.ids = IDSMonitor(DEFAULT_SYN_FLOOD_THRESHOLD, DEFAULT_PORT_SCAN_THRESHOLD)

        # Modern styling
        style = ttk.Style()
        style.theme_use('clam')
        
        # Color scheme
        primary_color = "#2c3e50"
        secondary_color = "#3498db"
        accent_color = "#e74c3c"
        light_color = "#ecf0f1"
        dark_color = "#34495e"
        
        # Configure styles
        style.configure("TFrame", background=light_color)
        style.configure("TNotebook", background=light_color)
        style.configure("TNotebook.Tab", padding=[15, 5], font=("Segoe UI", 10, "bold"))
        style.configure("TButton", padding=8, font=("Segoe UI", 10), background=secondary_color, 
                       foreground="white", bordercolor=secondary_color)
        style.map("TButton", background=[('active', '#2980b9')])
        style.configure("TLabel", font=("Segoe UI", 10), background=light_color)
        style.configure("TEntry", font=("Segoe UI", 10))
        style.configure("Treeview", font=("Consolas", 9), rowheight=25)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Alert.TLabel", font=("Segoe UI", 12, "bold"), foreground=accent_color)
        style.configure("Status.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Metric.TLabel", font=("Segoe UI", 11, "bold"), foreground=primary_color)

        # Main container with vertical layout
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Top panel - Metrics and Controls
        top_panel = ttk.Frame(main_container)
        top_panel.pack(fill=tk.X, pady=(0, 10))

        # Metrics frame
        metrics_frame = ttk.Frame(top_panel, style="TFrame")
        metrics_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Status indicator
        status_frame = ttk.Frame(metrics_frame)
        status_frame.pack(fill=tk.X, pady=5)
        ttk.Label(status_frame, text="SYSTEM STATUS:", style="TLabel").pack(side=tk.LEFT)
        self.status_indicator = ttk.Label(status_frame, text="IDLE", style="Alert.TLabel")
        self.status_indicator.pack(side=tk.LEFT, padx=5)
        
        # Metrics display
        metrics_subframe = ttk.Frame(metrics_frame)
        metrics_subframe.pack(fill=tk.X)
        
        ttk.Label(metrics_subframe, text="Network Traffic:", style="TLabel").grid(row=0, column=0, sticky=tk.W)
        self.pps_label = ttk.Label(metrics_subframe, text="0.00 PPS", style="Metric.TLabel")
        self.pps_label.grid(row=0, column=1, sticky=tk.W, padx=10)
        
        ttk.Label(metrics_subframe, text="Alerts:", style="TLabel").grid(row=0, column=2, sticky=tk.W)
        self.alerts_label = ttk.Label(metrics_subframe, text="0", style="Alert.TLabel")
        self.alerts_label.grid(row=0, column=3, sticky=tk.W, padx=10)
        
        ttk.Label(metrics_subframe, text="Open Ports:", style="TLabel").grid(row=0, column=4, sticky=tk.W)
        self.ports_count_label = ttk.Label(metrics_subframe, text="0", style="Metric.TLabel")
        self.ports_count_label.grid(row=0, column=5, sticky=tk.W, padx=10)

        # Control buttons
        control_frame = ttk.Frame(top_panel)
        control_frame.pack(side=tk.RIGHT)

        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Main content area - Notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Dashboard Tab - Vertical layout
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # Top section - Port tables
        tables_frame = ttk.Frame(dashboard_frame)
        tables_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Detected Open Ports Table
        detected_frame = ttk.LabelFrame(tables_frame, text="Detected Open Ports", padding=10)
        detected_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        columns = ("port", "service", "time", "status", "source")
        self.ports_tree = ttk.Treeview(detected_frame, columns=columns, show="headings", height=12)
        
        # Configure columns
        self.ports_tree.heading("port", text="Port", command=lambda: self._sort_treeview(self.ports_tree, "port", False))
        self.ports_tree.column("port", width=80, anchor=tk.CENTER)
        self.ports_tree.heading("service", text="Service", command=lambda: self._sort_treeview(self.ports_tree, "service", False))
        self.ports_tree.column("service", width=120)
        self.ports_tree.heading("time", text="Detection Time", command=lambda: self._sort_treeview(self.ports_tree, "time", False))
        self.ports_tree.column("time", width=180)
        self.ports_tree.heading("status", text="Status", command=lambda: self._sort_treeview(self.ports_tree, "status", False))
        self.ports_tree.column("status", width=100, anchor=tk.CENTER)
        self.ports_tree.heading("source", text="Source", command=lambda: self._sort_treeview(self.ports_tree, "source", False))
        self.ports_tree.column("source", width=120)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(detected_frame, orient=tk.VERTICAL, command=self.ports_tree.yview)
        self.ports_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.ports_tree.pack(fill=tk.BOTH, expand=True)

        # Local Listening Ports Table
        local_frame = ttk.LabelFrame(tables_frame, text="Local Listening Ports", padding=10)
        local_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        local_columns = ("port", "service", "time", "status", "pid", "process")
        self.local_tree = ttk.Treeview(local_frame, columns=local_columns, show="headings", height=12)
        
        # Configure columns
        self.local_tree.heading("port", text="Port", command=lambda: self._sort_treeview(self.local_tree, "port", False))
        self.local_tree.column("port", width=80, anchor=tk.CENTER)
        self.local_tree.heading("service", text="Service", command=lambda: self._sort_treeview(self.local_tree, "service", False))
        self.local_tree.column("service", width=120)
        self.local_tree.heading("time", text="Detection Time", command=lambda: self._sort_treeview(self.local_tree, "time", False))
        self.local_tree.column("time", width=180)
        self.local_tree.heading("status", text="Status", command=lambda: self._sort_treeview(self.local_tree, "status", False))
        self.local_tree.column("status", width=100, anchor=tk.CENTER)
        self.local_tree.heading("pid", text="PID", command=lambda: self._sort_treeview(self.local_tree, "pid", False))
        self.local_tree.column("pid", width=80, anchor=tk.CENTER)
        self.local_tree.heading("process", text="Process", command=lambda: self._sort_treeview(self.local_tree, "process", False))
        self.local_tree.column("process", width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(local_frame, orient=tk.VERTICAL, command=self.local_tree.yview)
        self.local_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.local_tree.pack(fill=tk.BOTH, expand=True)

        # Bottom section - Visualization and logs
        bottom_frame = ttk.Frame(dashboard_frame)
        bottom_frame.pack(fill=tk.BOTH, expand=True)

        # Visualization frame
        vis_frame = ttk.LabelFrame(bottom_frame, text="Network Activity Visualization", padding=10)
        vis_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        # Create figure for visualization
        self.figure = Figure(figsize=(6, 4), dpi=100, facecolor=light_color)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor(light_color)
        self.canvas = FigureCanvasTkAgg(self.figure, vis_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Quick actions frame
        actions_frame = ttk.Frame(bottom_frame, width=200)
        actions_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Label(actions_frame, text="Quick Actions", font=("Segoe UI", 11, "bold")).pack(pady=5)
        ttk.Button(actions_frame, text="Export to CSV", command=self.export_ports_csv).pack(fill=tk.X, pady=5)
        ttk.Button(actions_frame, text="Refresh Now", command=self._refresh_gui).pack(fill=tk.X, pady=5)
        ttk.Button(actions_frame, text="Test Alert", command=lambda: self.send_alert("Test alert notification")).pack(fill=tk.X, pady=5)

        # Logs Tab
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Event Logs")

        # Log display with search functionality
        log_top_frame = ttk.Frame(logs_frame)
        log_top_frame.pack(fill=tk.X, pady=5)

        ttk.Label(log_top_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.log_search_entry = ttk.Entry(log_top_frame, width=30)
        self.log_search_entry.pack(side=tk.LEFT, padx=5)
        self.log_search_entry.bind("<Return>", self.search_logs)

        ttk.Button(log_top_frame, text="Search", command=self.search_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_top_frame, text="Clear", command=self.clear_log_search).pack(side=tk.LEFT, padx=5)

        self.log_text = scrolledtext.ScrolledText(
            logs_frame, 
            wrap=tk.WORD, 
            font=("Consolas", 9),
            padx=10,
            pady=10,
            bg="#ffffff",
            fg="#333333"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for different log levels
        self.log_text.tag_configure("info", foreground="#27ae60")  # Green
        self.log_text.tag_configure("warning", foreground="#f39c12")  # Orange
        self.log_text.tag_configure("error", foreground="#e74c3c")  # Red
        self.log_text.tag_configure("highlight", background="#ffff99")  # Yellow highlight for search

        # Settings Tab
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Configuration")

        # Threshold settings
        threshold_frame = ttk.LabelFrame(settings_frame, text="Detection Thresholds", padding=10)
        threshold_frame.pack(fill=tk.X, pady=5)

        ttk.Label(threshold_frame, text="SYN Flood Threshold:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.syn_entry = ttk.Entry(threshold_frame, width=10)
        self.syn_entry.insert(0, str(DEFAULT_SYN_FLOOD_THRESHOLD))
        self.syn_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(threshold_frame, text="Port Scan Threshold:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.port_entry = ttk.Entry(threshold_frame, width=10)
        self.port_entry.insert(0, str(DEFAULT_PORT_SCAN_THRESHOLD))
        self.port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        self.update_button = ttk.Button(threshold_frame, text="Update Thresholds", command=self.update_thresholds)
        self.update_button.grid(row=0, column=4, padx=5, pady=5)

        # Email notification settings
        email_frame = ttk.LabelFrame(settings_frame, text="Email Notifications", padding=10)
        email_frame.pack(fill=tk.X, pady=5)

        ttk.Label(email_frame, text="SMTP Server:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.smtp_server_entry = ttk.Entry(email_frame, width=30)
        self.smtp_server_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(email_frame, text="Port:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.smtp_port_entry = ttk.Entry(email_frame, width=5)
        self.smtp_port_entry.insert(0, "587")
        self.smtp_port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        ttk.Label(email_frame, text="Sender Email:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.sender_entry = ttk.Entry(email_frame, width=30)
        self.sender_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(email_frame, text="Password:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(email_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)

        ttk.Label(email_frame, text="Recipient Email:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.recipient_entry = ttk.Entry(email_frame, width=30)
        self.recipient_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

        self.update_email_button = ttk.Button(email_frame, text="Update Email Config", command=self.update_email_config)
        self.update_email_button.grid(row=2, column=2, columnspan=2, padx=5, pady=5)

        # System info
        info_frame = ttk.LabelFrame(settings_frame, text="System Information", padding=10)
        info_frame.pack(fill=tk.X, pady=5)

        try:
            hostname = socket_lib.gethostname()
            ip_address = socket_lib.gethostbyname(hostname)
            ttk.Label(info_frame, text=f"Hostname: {hostname}").pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"IP Address: {ip_address}").pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"Monitoring IP: {self.ids.local_ip}").pack(anchor=tk.W)
        except:
            ttk.Label(info_frame, text="Could not retrieve system information").pack(anchor=tk.W)

        # Initialize periodic GUI updates
        self.root.after(1000, self._refresh_gui)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def log_to_gui(self, message: str, tag: str = "info"):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message, tag)
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def search_logs(self, event=None):
        query = self.log_search_entry.get().lower()
        if not query:
            return
            
        self.log_text.tag_remove("highlight", "1.0", tk.END)
        self.log_text.configure(state=tk.NORMAL)
        
        # Count matches
        count = 0
        pos = "1.0"
        while True:
            pos = self.log_text.search(query, pos, nocase=1, stopindex=tk.END)
            if not pos:
                break
            end_pos = f"{pos}+{len(query)}c"
            self.log_text.tag_add("highlight", pos, end_pos)
            count += 1
            pos = end_pos
            
        self.log_text.configure(state=tk.DISABLED)
        messagebox.showinfo("Search Complete", f"Found {count} occurrences of '{query}'")

    def clear_log_search(self):
        self.log_search_entry.delete(0, tk.END)
        self.log_text.tag_remove("highlight", "1.0", tk.END)

    def send_alert(self, alert: str):
        notification.notify(
            title='IDS Alert',
            message=alert,
            app_name='Enterprise IDS',
            timeout=10
        )
        self.ids.send_email_alert(alert)
        self.alerts_label.config(text=str(self.ids.total_alerts))

    def start_monitoring(self):
        self.ids.start(self.log_to_gui, self.send_alert)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_indicator.config(text="ACTIVE", foreground="#27ae60")  # Green

    def stop_monitoring(self):
        self.ids.stop()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_indicator.config(text="IDLE", foreground="#e74c3c")  # Red

    def update_thresholds(self):
        try:
            syn_th = int(self.syn_entry.get())
            port_th = int(self.port_entry.get())
            if syn_th < 1 or port_th < 1:
                raise ValueError("Thresholds must be positive.")
            self.ids.update_thresholds(syn_th, port_th)
            self.log_to_gui(f"Thresholds updated: SYN={syn_th}, Port Scan={port_th}\n", "info")
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))

    def update_email_config(self):
        try:
            smtp_server = self.smtp_server_entry.get()
            smtp_port = int(self.smtp_port_entry.get())
            sender = self.sender_entry.get()
            password = self.password_entry.get()
            recipient = self.recipient_entry.get()
            self.ids.update_email_config(smtp_server, smtp_port, sender, password, recipient)
            self.log_to_gui("Email config updated.\n", "info")
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))

    def clear_logs(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _refresh_gui(self):
        # Update detected open ports table
        self.ports_tree.delete(*self.ports_tree.get_children())
        for port, info in sorted(self.ids.open_ports.items()):
            self.ports_tree.insert("", "end", values=(port, info['service'], info['time'], info['status'], info['source']))

        # Update local listening ports table
        self.local_tree.delete(*self.local_tree.get_children())
        for port, info in sorted(self.ids.local_listening_ports.items()):
            self.local_tree.insert("", "end", values=(port, info['service'], info['time'], info['status'], info['pid'], info['process']))

        # Update chart with better visualization
        services = collections.Counter(info['service'] for info in self.ids.open_ports.values())
        self.ax.clear()
        
        if services:
            colors = plt.cm.Paired(range(len(services)))
            bars = self.ax.bar(services.keys(), services.values(), color=colors)
            self.ax.bar_label(bars, padding=3)
            self.ax.set_xlabel('Service', fontsize=10)
            self.ax.set_ylabel('Count', fontsize=10)
            self.ax.set_title('Open Ports by Service', fontsize=12, pad=20)
            self.ax.tick_params(axis='x', rotation=45, labelsize=9)
            self.ax.grid(True, linestyle='--', alpha=0.6)
        else:
            self.ax.text(0.5, 0.5, 'No open ports detected', 
                        ha='center', va='center', fontsize=12,
                        bbox=dict(facecolor='white', alpha=0.5))
            self.ax.set_xticks([])
            self.ax.set_yticks([])
            
        self.figure.tight_layout()
        self.canvas.draw()

        # Update metrics
        self.pps_label.config(text=f"{self.ids.pps:.2f} PPS")
        self.alerts_label.config(text=str(self.ids.total_alerts))
        self.ports_count_label.config(text=str(len(self.ids.open_ports)))
        
        self.root.after(1000, self._refresh_gui)

    def export_ports_csv(self):
        if not self.ids.open_ports:
            messagebox.showinfo("Export", "No open ports to export.")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="open_ports.csv"
        )
        
        if file_path:
            df = pd.DataFrame.from_dict(self.ids.open_ports, orient='index')
            df.index.name = 'Port'
            df.to_csv(file_path)
            messagebox.showinfo("Export Successful", f"Open ports exported to:\n{file_path}")

    def _sort_treeview(self, tree, col, descending):
        data = [(tree.set(child, col), child) for child in tree.get_children('')]
        data.sort(reverse=descending)
        
        # Handle numeric sorting for port numbers
        if col == "port" or col == "pid":
            try:
                data.sort(key=lambda x: int(x[0]), reverse=descending)
            except ValueError:
                pass
                
        for index, (val, child) in enumerate(data):
            tree.move(child, '', index)
        tree.heading(col, command=lambda: self._sort_treeview(tree, col, not descending))

    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to stop monitoring and exit?"):
            self.ids.stop()
            self.root.destroy()

# [Rest of the code remains the same...]

if __name__ == "__main__":
    # Auto-install dependencies if missing
    try:
        import netifaces
    except ImportError:
        print("Installing netifaces2...")
        os.system("pip install netifaces2")
        import netifaces
    try:
        import psutil
    except ImportError:
        print("Installing psutil...")
        os.system("pip install psutil")
        import psutil
    try:
        import pandas
    except ImportError:
        print("Installing pandas...")
        os.system("pip install pandas")
        import pandas

    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()