import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, wrpcap, ARP, DNS
from scapy.layers.http import HTTP
import threading
import time
import datetime
from collections import defaultdict, deque
import queue

class RealTimePacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Network Packet Sniffer")
        self.root.geometry("1200x800")
        
        # Sniffer control variables
        self.sniffing = False
        self.packet_queue = queue.Queue()
        self.packets = deque(maxlen=10000)  # Limit memory usage
        self.protocol_stats = defaultdict(int)
        self.current_filter = "ip"
        self.update_interval = 250  # ms for UI updates
        
        # Create main UI components
        self.create_widgets()
        self.setup_layout()
        
        # Start the UI update loop
        self.update_ui()
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Control panel
        self.control_frame = ttk.Frame(self.root, padding="10")
        
        self.start_button = ttk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.stop_button = ttk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing, state='disabled')
        self.save_button = ttk.Button(self.control_frame, text="Save Capture", command=self.save_capture, state='disabled')
        self.clear_button = ttk.Button(self.control_frame, text="Clear Display", command=self.clear_display)
        
        # Filter controls
        ttk.Label(self.control_frame, text="Filter:").grid(row=0, column=4, padx=5)
        self.filter_entry = ttk.Entry(self.control_frame, width=30)
        self.filter_entry.insert(0, self.current_filter)
        self.apply_filter_button = ttk.Button(self.control_frame, text="Apply Filter", command=self.apply_filter)
        
        # Packet list
        self.columns = ("No.", "Time", "Size", "Source", "Destination", "Protocol", "Info")
        self.tree = ttk.Treeview(self.root, columns=self.columns, show='headings', selectmode='browse')
        
        # Configure columns
        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, stretch=True)
        
        # Packet details
        self.details_frame = ttk.LabelFrame(self.root, text="Packet Details", padding="10")
        self.details_text = tk.Text(self.details_frame, wrap=tk.WORD, height=10)
        self.details_scroll = ttk.Scrollbar(self.details_frame, command=self.details_text.yview)
        self.details_text.config(yscrollcommand=self.details_scroll.set)
        
        # Statistics
        self.stats_frame = ttk.LabelFrame(self.root, text="Real-Time Statistics", padding="10")
        self.stats_text = tk.Text(self.stats_frame, wrap=tk.WORD, height=20)
        self.stats_text.insert(tk.END, "Statistics will appear here during capture")
        self.stats_text.config(state=tk.DISABLED)
    
    def setup_layout(self):
        """Arrange widgets in the window"""
        # Control panel layout
        self.control_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.start_button.grid(row=0, column=0, padx=5)
        self.stop_button.grid(row=0, column=1, padx=5)
        self.save_button.grid(row=0, column=2, padx=5)
        self.clear_button.grid(row=0, column=3, padx=5)
        ttk.Label(self.control_frame, text="Filter:").grid(row=0, column=4, padx=5)
        self.filter_entry.grid(row=0, column=5, padx=5)
        self.apply_filter_button.grid(row=0, column=6, padx=5)
        
        # Main content layout
        self.tree.grid(row=1, column=0, sticky="nsew")
        self.stats_frame.grid(row=1, column=1, sticky="nsew")
        self.details_frame.grid(row=2, column=0, columnspan=2, sticky="nsew")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=3)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=0)
        
        # Pack details frame contents
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.details_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind events
        self.tree.bind('<<TreeviewSelect>>', self.show_packet_details)
    
    def start_sniffing(self):
        """Start packet capture in a separate thread"""
        if self.sniffing:
            return
        
        self.sniffing = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.save_button.config(state='normal')
        
        # Clear previous data if not continuing
        if not self.packets:
            self.tree.delete(*self.tree.get_children())
            self.protocol_stats.clear()
        
        # Get current filter
        self.current_filter = self.filter_entry.get()
        
        # Start sniffer thread
        self.sniffer_thread = threading.Thread(
            target=self.packet_capture_loop,
            daemon=True
        )
        self.sniffer_thread.start()
    
    def packet_capture_loop(self):
        """Main packet capture loop running in background thread"""
        try:
            sniff(
                prn=self.enqueue_packet,
                store=False,
                filter=self.current_filter,
                stop_filter=lambda x: not self.sniffing
            )
        except Exception as e:
            self.packet_queue.put(("ERROR", str(e)))
    
    def enqueue_packet(self, packet):
        """Process packet and add to queue for UI thread"""
        if not self.sniffing:
            return
        
        try:
            # Basic packet info
            timestamp = datetime.datetime.now()
            protocol = self.get_protocol(packet)
            src, dst = self.get_addresses(packet)
            info = self.get_packet_info(packet, protocol)
            
            # Update protocol stats
            self.protocol_stats[protocol] += 1
            
            # Create packet info dict
            packet_info = {
                "no": len(self.packets) + 1,
                "time": timestamp.strftime('%H:%M:%S.%f')[:-3],
                "size": len(packet),
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "info": info,
                "packet": packet
            }
            
            # Add to queue for UI thread
            self.packet_queue.put(("PACKET", packet_info))
            
        except Exception as e:
            self.packet_queue.put(("ERROR", f"Packet processing error: {str(e)}"))
    
    def update_ui(self):
        """Periodic UI update from the main thread"""
        # Process all pending packets
        while not self.packet_queue.empty():
            item_type, data = self.packet_queue.get()
            
            if item_type == "PACKET":
                self.process_packet_for_ui(data)
            elif item_type == "ERROR":
                messagebox.showerror("Error", data)
                self.stop_sniffing()
        
        # Update statistics periodically
        if self.sniffing and len(self.packets) % 10 == 0:
            self.update_stats_display()
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_ui)
    
    def process_packet_for_ui(self, packet_info):
        """Update UI with new packet information"""
        self.packets.append(packet_info)
        
        # Add to treeview
        self.tree.insert("", "end", values=(
            packet_info["no"],
            packet_info["time"],
            packet_info["size"],
            packet_info["src"],
            packet_info["dst"],
            packet_info["protocol"],
            packet_info["info"]
        ))
        
        # Auto-scroll if at bottom
        if self.tree.yview()[1] > 0.95:
            self.tree.see(self.tree.get_children()[-1])
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.sniffing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.update_stats_display()
    
    def show_packet_details(self, event):
        """Show detailed packet information when selected"""
        selected = self.tree.selection()
        if not selected:
            return
        
        item = self.tree.item(selected[0])
        packet_num = item['values'][0] - 1  # Convert to 0-based index
        
        if 0 <= packet_num < len(self.packets):
            packet = self.packets[packet_num]['packet']
            self.display_packet_details(packet)
    
    def display_packet_details(self, packet):
        """Show detailed packet information"""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        # Basic info
        self.details_text.insert(tk.END, f"=== Packet Summary ===\n")
        self.details_text.insert(tk.END, f"Time: {datetime.datetime.now()}\n")
        self.details_text.insert(tk.END, f"Length: {len(packet)} bytes\n")
        self.details_text.insert(tk.END, f"Protocol: {self.get_protocol(packet)}\n\n")
        
        # Show packet layers
        self.details_text.insert(tk.END, "=== Protocol Layers ===\n")
        for layer in packet.layers():
            self.details_text.insert(tk.END, f"- {layer.__name__}\n")
        
        # Detailed packet dump
        self.details_text.insert(tk.END, "\n=== Raw Packet ===\n")
        self.details_text.insert(tk.END, packet.show(dump=True))
        
        self.details_text.config(state=tk.DISABLED)
        self.details_text.see(tk.END)
    
    def update_stats_display(self):
        """Update statistics panel"""
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        
        total_packets = len(self.packets)
        self.stats_text.insert(tk.END, f"=== Capture Statistics ===\n")
        self.stats_text.insert(tk.END, f"Total Packets: {total_packets}\n")
        
        if total_packets > 0:
            self.stats_text.insert(tk.END, f"Capture Duration: {self.get_capture_duration()}\n\n")
            
            self.stats_text.insert(tk.END, "=== Protocol Distribution ===\n")
            for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
                percent = (count / total_packets) * 100
                self.stats_text.insert(tk.END, f"{proto}: {count} ({percent:.1f}%)\n")
            
            # Calculate packets/second
            if len(self.packets) > 1:
                first_packet_time = self.packets[0]['packet'].time
                last_packet_time = self.packets[-1]['packet'].time
                duration = last_packet_time - first_packet_time
                if duration > 0:
                    rate = total_packets / duration
                    self.stats_text.insert(tk.END, f"\nCapture Rate: {rate:.1f} packets/sec\n")
        
        self.stats_text.config(state=tk.DISABLED)
    
    def get_capture_duration(self):
        """Calculate current capture duration"""
        if not self.packets:
            return "0s"
        
        first_time = self.packets[0]['packet'].time
        last_time = time.time() if self.sniffing else self.packets[-1]['packet'].time
        duration = last_time - first_time
        
        if duration < 60:
            return f"{duration:.2f} seconds"
        else:
            return f"{duration/60:.2f} minutes"
    
    def apply_filter(self):
        """Apply new filter expression"""
        new_filter = self.filter_entry.get()
        if not new_filter:
            messagebox.showwarning("Warning", "Please enter a filter expression")
            return
        
        self.current_filter = new_filter
        
        if self.sniffing:
            messagebox.showinfo("Info", "Filter will be applied after restarting capture")
    
    def save_capture(self):
        """Save captured packets to file"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to save")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                packets = [p['packet'] for p in self.packets]
                wrpcap(file_path, packets)
                messagebox.showinfo("Success", f"Saved {len(packets)} packets to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save capture: {str(e)}")
    
    def clear_display(self):
        """Clear all captured data"""
        if self.sniffing:
            if not messagebox.askyesno("Confirm", "Stop current capture and clear display?"):
                return
            self.stop_sniffing()
        
        self.packets.clear()
        self.protocol_stats.clear()
        self.tree.delete(*self.tree.get_children())
        
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
        
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, "Statistics will appear here during capture")
        self.stats_text.config(state=tk.DISABLED)
    
    # Protocol detection helpers
    def get_protocol(self, packet):
        """Determine the protocol of a packet"""
        if TCP in packet:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                return "HTTP"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return "HTTPS"
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        elif ARP in packet:
            return "ARP"
        elif DNS in packet:
            return "DNS"
        return "Other"
    
    def get_addresses(self, packet):
        """Extract source and destination addresses"""
        if IP in packet:
            src_port = packet.sport if hasattr(packet, 'sport') else ''
            dst_port = packet.dport if hasattr(packet, 'dport') else ''
            src = f"{packet[IP].src}:{src_port}" if src_port else packet[IP].src
            dst = f"{packet[IP].dst}:{dst_port}" if dst_port else packet[IP].dst
        elif Ether in packet:
            src = packet[Ether].src
            dst = packet[Ether].dst
        else:
            src = "Unknown"
            dst = "Unknown"
        return src, dst
    
    def get_packet_info(self, packet, protocol):
        """Get protocol-specific information"""
        info = ""
        if TCP in packet:
            info = f"TCP {packet[TCP].sport}→{packet[TCP].dport} Flags:{packet[TCP].flags}"
        elif UDP in packet:
            info = f"UDP {packet[UDP].sport}→{packet[UDP].dport}"
        elif ICMP in packet:
            info = f"ICMP type:{packet[ICMP].type}"
        elif ARP in packet:
            info = f"ARP {packet[ARP].op}"
        return info

if __name__ == "__main__":
    root = tk.Tk()
    app = RealTimePacketSniffer(root)
    root.mainloop()