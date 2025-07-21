import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import json
import csv
import os
from datetime import datetime
import pkg_resources
import requests
from concurrent.futures import ThreadPoolExecutor
import logging

class VulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Pro Vulnerability Scanner")
        self.root.geometry("800x600")
        self.root.configure(bg="#2b2b2b")

        # Setup logging
        logging.basicConfig(filename='vuln_scanner.log', level=logging.INFO,
                          format='%(asctime)s - %(levelname)s - %(message)s')

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', background='#4a4a4a', foreground='white', padding=10)
        style.configure('TLabel', background='#2b2b2b', foreground='white')
        style.configure('TEntry', fieldbackground='#3c3c3c', foreground='white')
        style.configure('TFrame', background='#2b2b2b')

        # Main frame
        self.main_frame = ttk.Frame(root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Target input
        self.target_frame = ttk.Frame(self.main_frame)
        self.target_frame.pack(fill=tk.X, pady=5)
        self.label_target = ttk.Label(self.target_frame, text="Target(s) (IP/Domain, comma-separated):")
        self.label_target.pack(side=tk.LEFT)
        self.entry_target = ttk.Entry(self.target_frame, width=50)
        self.entry_target.pack(side=tk.LEFT, padx=10)

        # Port range input
        self.port_frame = ttk.Frame(self.main_frame)
        self.port_frame.pack(fill=tk.X, pady=5)
        self.label_ports = ttk.Label(self.port_frame, text="Port Range (e.g., 1-1000):")
        self.label_ports.pack(side=tk.LEFT)
        self.entry_ports = ttk.Entry(self.port_frame, width=20)
        self.entry_ports.pack(side=tk.LEFT, padx=10)

        # Buttons frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X, pady=10)
        self.scan_button = ttk.Button(self.button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        self.report_button = ttk.Button(self.button_frame, text="Generate Report", command=self.generate_report)
        self.report_button.pack(side=tk.LEFT, padx=5)
        self.history_button = ttk.Button(self.button_frame, text="View History", command=self.view_history)
        self.history_button.pack(side=tk.LEFT, padx=5)

        # Status label
        self.status_label = ttk.Label(self.main_frame, text="Status: Ready")
        self.status_label.pack(pady=5)

        # Progress bar
        self.progress = ttk.Progressbar(self.main_frame, length=600, mode='determinate')
        self.progress.pack(pady=10)

        # Result display
        self.result_text = scrolledtext.ScrolledText(self.main_frame, width=80, height=20, 
                                                   bg='#3c3c3c', fg='white', insertbackground='white')
        self.result_text.pack(pady=10)

        self.results = []
        self.scan_thread = None
        self.is_scanning = False
        self.history = []

    def validate_inputs(self, targets, port_range):
        try:
            start_port, end_port = map(int, port_range.split('-'))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                return False, "Invalid port range. Use format: 1-1000"
            if not targets:
                return False, "Please enter at least one target."
            return True, ""
        except ValueError:
            return False, "Invalid port range. Use format: 1-1000"

    def scan_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = self.get_service_name(port)
                return {"port": port, "service": service}
            sock.close()
            return None
        except Exception as e:
            logging.error(f"Error scanning {target}:{port} - {str(e)}")
            return None

    def get_service_name(self, port):
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
            443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Alt"
        }
        return common_ports.get(port, "Unknown")

    def check_software_versions(self):
        outdated = []
        installed_packages = {pkg.key: pkg.version for pkg in pkg_resources.working_set}
        for pkg_name, current_version in installed_packages.items():
            try:
                response = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=5)
                latest_version = response.json()['info']['version']
                if current_version != latest_version:
                    outdated.append({
                        "package": pkg_name,
                        "current_version": current_version,
                        "latest_version": latest_version
                    })
            except Exception as e:
                logging.error(f"Error checking package {pkg_name}: {str(e)}")
        return outdated

    def scan_target(self, target, start_port, end_port):
        target_results = {"target": target, "open_ports": [], "outdated_software": []}
        total_ports = end_port - start_port + 1
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.scan_port, target, port) for port in range(start_port, end_port + 1)]
            for i, future in enumerate(futures):
                result = future.result()
                if result:
                    target_results["open_ports"].append(result)
                self.progress['value'] = (i + 1) / total_ports * 50
                self.root.update()
        return target_results

    def start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "Please wait for the current scan to complete.")
            return

        targets = [t.strip() for t in self.entry_target.get().split(',')]
        port_range = self.entry_ports.get().strip()

        is_valid, error_msg = self.validate_inputs(targets, port_range)
        if not is_valid:
            messagebox.showerror("Input Error", error_msg)
            return

        start_port, end_port = map(int, port_range.split('-'))
        self.results = []
        self.result_text.delete(1.0, tk.END)
        self.scan_button.config(state='disabled')
        self.is_scanning = True
        self.status_label.config(text="Status: Scanning...")

        def scan_thread():
            try:
                # Scan each target
                for target in targets:
                    self.result_text.insert(tk.END, f"\nScanning {target}...\n")
                    target_results = self.scan_target(target, start_port, end_port)
                    target_results["outdated_software"] = self.check_software_versions()
                    self.results.append(target_results)
                    self.progress['value'] = 100
                    self.root.update()

                    # Display results
                    self.result_text.insert(tk.END, f"\nResults for {target}:\n")
                    self.result_text.insert(tk.END, "Open Ports:\n")
                    for port_info in target_results["open_ports"]:
                        self.result_text.insert(tk.END, f"Port {port_info['port']}: {port_info['service']}\n")
                    self.result_text.insert(tk.END, "\nOutdated Software:\n")
                    for pkg in target_results["outdated_software"]:
                        self.result_text.insert(tk.END, f"{pkg['package']}: {pkg['current_version']} (Latest: {pkg['latest_version']})\n")

                # Save to history
                self.history.append({
                    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "results": self.results
                })

            except Exception as e:
                logging.error(f"Scan error: {str(e)}")
                messagebox.showerror("Error", f"Scan failed: {str(e)}")
            finally:
                self.scan_button.config(state='normal')
                self.is_scanning = False
                self.status_label.config(text="Status: Scan Complete")
                self.progress['value'] = 0

        self.scan_thread = threading.Thread(target=scan_thread, daemon=True)
        self.scan_thread.start()

    def generate_report(self):
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to generate report.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "targets": self.results
        }

        # JSON Report
        json_file = f"vuln_report_{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(report, f, indent=4)

        # TXT Report
        txt_file = f"vuln_report_{timestamp}.txt"
        with open(txt_file, "w") as f:
            f.write(f"Vulnerability Scan Report\n")
            f.write(f"Time: {report['scan_time']}\n\n")
            for target_data in report["targets"]:
                f.write(f"Target: {target_data['target']}\n")
                f.write("Open Ports:\n")
                for port_info in target_data["open_ports"]:
                    f.write(f"Port {port_info['port']}: {port_info['service']}\n")
                f.write("\nOutdated Software:\n")
                for pkg in target_data["outdated_software"]:
                    f.write(f"{pkg['package']}: {pkg['current_version']} (Latest: {pkg['latest_version']})\n")
                f.write("\n" + "="*50 + "\n")

        # CSV Report
        csv_file = f"vuln_report_{timestamp}.csv"
        with open(csv_file, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Port", "Service", "Package", "Current Version", "Latest Version"])
            for target_data in self.results:
                target = target_data["target"]
                for port_info in target_data["open_ports"]:
                    writer.writerow([target, port_info["port"], port_info["service"], "", "", ""])
                for pkg in target_data["outdated_software"]:
                    writer.writerow([target, "", "", pkg["package"], pkg["current_version"], pkg["latest_version"]])

        messagebox.showinfo("Report Generated", f"Reports saved as:\n{json_file}\n{txt_file}\n{csv_file}")
        logging.info(f"Reports generated: {json_file}, {txt_file}, {csv_file}")

    def view_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Scan History")
        history_window.geometry("600x400")
        history_window.configure(bg="#2b2b2b")

        history_text = scrolledtext.ScrolledText(history_window, width=70, height=20,
                                               bg='#3c3c3c', fg='white', insertbackground='white')
        history_text.pack(pady=10)

        for scan in self.history:
            history_text.insert(tk.END, f"Scan Time: {scan['scan_time']}\n")
            for target_data in scan["results"]:
                history_text.insert(tk.END, f"\nTarget: {target_data['target']}\n")
                history_text.insert(tk.END, "Open Ports:\n")
                for port_info in target_data["open_ports"]:
                    history_text.insert(tk.END, f"Port {port_info['port']}: {port_info['service']}\n")
                history_text.insert(tk.END, "\nOutdated Software:\n")
                for pkg in target_data["outdated_software"]:
                    history_text.insert(tk.END, f"{pkg['package']}: {pkg['current_version']} (Latest: {pkg['latest_version']})\n")
                history_text.insert(tk.END, "\n" + "="*50 + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScanner(root)
    root.mainloop()