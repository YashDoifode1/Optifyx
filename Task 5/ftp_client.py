import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from ftplib import FTP, error_perm
import os
import threading

class FTPClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Python FTP Client")
        self.root.geometry("900x650")
        
        # FTP connection variables
        self.ftp = None
        self.connected = False
        self.current_dir = "/"
        self.local_current_dir = os.path.expanduser("~")
        
        # Create UI
        self.create_connection_frame()
        self.create_file_explorer()
        self.create_status_bar()
        
        # Disable file operations initially
        self.toggle_file_operations(False)
    
    def create_connection_frame(self):
        """Create the connection settings frame"""
        connection_frame = ttk.LabelFrame(self.root, text="FTP Connection", padding=10)
        connection_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Server address
        ttk.Label(connection_frame, text="Server:").grid(row=0, column=0, sticky=tk.W)
        self.server_entry = ttk.Entry(connection_frame, width=30)
        self.server_entry.grid(row=0, column=1, padx=5)
        self.server_entry.insert(0, "localhost")  # Default value
        
        # Port
        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
        self.port_entry = ttk.Entry(connection_frame, width=8)
        self.port_entry.grid(row=0, column=3, padx=5)
        self.port_entry.insert(0, "21")  # Default FTP port
        
        # Username
        ttk.Label(connection_frame, text="Username:").grid(row=1, column=0, sticky=tk.W)
        self.user_entry = ttk.Entry(connection_frame, width=30)
        self.user_entry.grid(row=1, column=1, padx=5, pady=5)
        self.user_entry.insert(0, "anonymous")  # Default FTP user
        
        # Password
        ttk.Label(connection_frame, text="Password:").grid(row=1, column=2, sticky=tk.W)
        self.pass_entry = ttk.Entry(connection_frame, width=15, show="*")
        self.pass_entry.grid(row=1, column=3, padx=5, pady=5)
        self.pass_entry.insert(0, "anonymous@")  # Default FTP password
        
        # Connect/Disconnect button
        self.connect_btn = ttk.Button(connection_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=2, column=3, sticky=tk.E, pady=5)
    
    def create_file_explorer(self):
        """Create the file explorer frame with enhanced buttons"""
        explorer_frame = ttk.LabelFrame(self.root, text="File Explorer", padding=10)
        explorer_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Local files frame
        local_frame = ttk.Frame(explorer_frame)
        local_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Local navigation buttons
        local_nav_frame = ttk.Frame(local_frame)
        local_nav_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(local_nav_frame, text="↑ Up", command=self.local_nav_up).pack(side=tk.LEFT, padx=2)
        ttk.Button(local_nav_frame, text="🏠 Home", command=self.local_nav_home).pack(side=tk.LEFT, padx=2)
        ttk.Button(local_nav_frame, text="↻ Refresh", command=self.refresh_local).pack(side=tk.LEFT, padx=2)
        
        ttk.Label(local_frame, text="Local System").pack(anchor=tk.W)
        self.local_tree = ttk.Treeview(local_frame)
        self.local_tree.pack(fill=tk.BOTH, expand=True)
        
        # Remote files frame
        remote_frame = ttk.Frame(explorer_frame)
        remote_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Remote navigation buttons
        remote_nav_frame = ttk.Frame(remote_frame)
        remote_nav_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(remote_nav_frame, text="↑ Up", command=self.remote_nav_up).pack(side=tk.LEFT, padx=2)
        ttk.Button(remote_nav_frame, text="🏠 Home", command=self.remote_nav_home).pack(side=tk.LEFT, padx=2)
        ttk.Button(remote_nav_frame, text="↻ Refresh", command=self.refresh_remote).pack(side=tk.LEFT, padx=2)
        
        ttk.Label(remote_frame, text="Remote Server").pack(anchor=tk.W)
        self.remote_tree = ttk.Treeview(remote_frame)
        self.remote_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbars
        for tree, frame in [(self.local_tree, local_frame), (self.remote_tree, remote_frame)]:
            scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            scroll.pack(side=tk.RIGHT, fill=tk.Y)
            tree.configure(yscrollcommand=scroll.set)
        
        # File operation buttons (centered between panes)
        op_frame = ttk.Frame(explorer_frame)
        op_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # Operation buttons with better organization
        ttk.Label(op_frame, text="File Operations").pack(pady=(10, 5))
        
        self.upload_btn = ttk.Button(op_frame, text="↑ Upload", command=self.upload_file, state=tk.DISABLED)
        self.upload_btn.pack(fill=tk.X, pady=2)
        
        self.download_btn = ttk.Button(op_frame, text="↓ Download", command=self.download_file, state=tk.DISABLED)
        self.download_btn.pack(fill=tk.X, pady=2)
        
        ttk.Separator(op_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        self.delete_btn = ttk.Button(op_frame, text="✖ Delete", command=self.delete_file, state=tk.DISABLED)
        self.delete_btn.pack(fill=tk.X, pady=2)
        
        self.new_folder_btn = ttk.Button(op_frame, text="📁 New Folder", command=self.create_remote_folder, state=tk.DISABLED)
        self.new_folder_btn.pack(fill=tk.X, pady=2)
        
        # Configure treeviews
        for tree in [self.local_tree, self.remote_tree]:
            tree["columns"] = ("size", "type", "modified")
            tree.heading("#0", text="Name")
            tree.heading("size", text="Size")
            tree.heading("type", text="Type")
            tree.heading("modified", text="Modified")
            
            tree.column("#0", width=200)
            tree.column("size", width=80, anchor=tk.E)
            tree.column("type", width=80)
            tree.column("modified", width=120)
        
        # Bind events
        self.local_tree.bind("<Double-1>", self.on_local_double_click)
        self.remote_tree.bind("<Double-1>", self.on_remote_double_click)
        self.local_tree.bind("<<TreeviewSelect>>", self.on_local_select)
        self.remote_tree.bind("<<TreeviewSelect>>", self.on_remote_select)
        
        # Populate local tree
        self.populate_local_tree(self.local_current_dir)
    
    def create_status_bar(self):
        """Create the status bar at the bottom"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=5, pady=5)
    
    # Navigation methods
    def local_nav_up(self):
        """Navigate up in local directory"""
        parent = os.path.dirname(self.local_current_dir)
        if parent != self.local_current_dir:  # Not at root
            self.local_current_dir = parent
            self.populate_local_tree(self.local_current_dir)
    
    def local_nav_home(self):
        """Navigate to home directory in local"""
        self.local_current_dir = os.path.expanduser("~")
        self.populate_local_tree(self.local_current_dir)
    
    def remote_nav_up(self):
        """Navigate up in remote directory"""
        if not self.connected:
            return
        
        if self.current_dir != "/":
            parent = os.path.dirname(self.current_dir)
            if parent == "/":
                parent = "/"
            self.populate_remote_tree(parent)
    
    def remote_nav_home(self):
        """Navigate to home directory in remote"""
        if not self.connected:
            return
        
        self.populate_remote_tree("/")
    
    def refresh_local(self):
        """Refresh local file list"""
        self.populate_local_tree(self.local_current_dir)
    
    def refresh_remote(self):
        """Refresh remote file list"""
        if self.connected:
            self.populate_remote_tree(self.current_dir)
    
    def toggle_connection(self):
        """Connect or disconnect from FTP server"""
        if self.connected:
            self.disconnect()
        else:
            self.connect()
    
    def connect(self):
        """Connect to FTP server"""
        server = self.server_entry.get()
        port = int(self.port_entry.get())
        username = self.user_entry.get()
        password = self.pass_entry.get()
        
        try:
            self.status_var.set(f"Connecting to {server}...")
            self.root.update()
            
            # Connect in a separate thread to avoid UI freezing
            threading.Thread(target=self._connect_thread, args=(server, port, username, password), daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            self.status_var.set("Connection failed")
    
    def _connect_thread(self, server, port, username, password):
        """Thread for FTP connection"""
        try:
            self.ftp = FTP()
            self.ftp.connect(server, port)
            self.ftp.login(username, password)
            
            # Update UI in main thread
            self.root.after(0, self._connection_successful)
        except Exception as e:
            self.root.after(0, self._connection_failed, str(e))
    
    def _connection_successful(self):
        """Called when connection is successful"""
        self.connected = True
        self.connect_btn.config(text="Disconnect")
        self.toggle_file_operations(True)
        self.status_var.set(f"Connected to {self.server_entry.get()}")
        
        # Enable remote operations
        self.new_folder_btn.config(state=tk.NORMAL)
        
        # Populate remote tree
        self.populate_remote_tree()
    
    def _connection_failed(self, error):
        """Called when connection fails"""
        messagebox.showerror("Connection Error", f"Failed to connect: {error}")
        self.status_var.set("Connection failed")
        if self.ftp:
            try:
                self.ftp.quit()
            except:
                pass
            self.ftp = None
    
    def disconnect(self):
        """Disconnect from FTP server"""
        try:
            if self.ftp:
                self.ftp.quit()
        except:
            pass
        
        self.ftp = None
        self.connected = False
        self.connect_btn.config(text="Connect")
        self.toggle_file_operations(False)
        self.status_var.set("Disconnected")
        
        # Disable remote operations
        self.new_folder_btn.config(state=tk.DISABLED)
        
        # Clear remote tree
        self.remote_tree.delete(*self.remote_tree.get_children())
    
    def toggle_file_operations(self, enabled):
        """Enable/disable file operation buttons"""
        state = tk.NORMAL if enabled else tk.DISABLED
        self.download_btn.config(state=state)
        self.upload_btn.config(state=state)
        self.delete_btn.config(state=state)
    
    def populate_local_tree(self, path=None):
        """Populate local file tree"""
        if path is None:
            path = os.path.expanduser("~")  # Start at user's home directory
        
        self.local_tree.delete(*self.local_tree.get_children())
        self.local_tree.heading("#0", text=f"Local: {path}")
        self.local_current_dir = path
        
        try:
            # Add parent directory entry
            parent = os.path.dirname(path)
            if parent != path:  # Not at root
                self.local_tree.insert("", "end", text="..", values=("", "Directory", ""), 
                                     iid=parent, tags=("directory",))
            
            # List directory contents
            for item in os.listdir(path):
                full_path = os.path.join(path, item)
                if os.path.isdir(full_path):
                    self.local_tree.insert("", "end", text=item, values=("", "Directory", ""), 
                                         iid=full_path, tags=("directory",))
                else:
                    size = os.path.getsize(full_path)
                    modified = os.path.getmtime(full_path)
                    self.local_tree.insert("", "end", text=item, 
                                         values=(self.format_size(size), "File", 
                                                 self.format_time(modified)), 
                                         iid=full_path, tags=("file",))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list local directory: {str(e)}")
    
    def populate_remote_tree(self, path=None):
        """Populate remote file tree"""
        if not self.connected:
            return
            
        if path is None:
            path = self.ftp.pwd()
        
        self.current_dir = path
        self.remote_tree.delete(*self.remote_tree.get_children())
        self.remote_tree.heading("#0", text=f"Remote: {path}")
        
        try:
            # Add parent directory entry
            if path != "/":
                parent = os.path.dirname(path)
                if parent == "/":
                    parent = "/"
                self.remote_tree.insert("", "end", text="..", values=("", "Directory", ""), 
                                       iid=parent, tags=("directory",))
            
            # List directory contents
            items = []
            self.ftp.dir(path, items.append)
            
            for item in items:
                # Parse FTP directory listing (this is a simple parser, may not work with all servers)
                parts = item.split()
                if len(parts) < 9:
                    continue
                
                name = " ".join(parts[8:])
                is_dir = parts[0].startswith("d")
                size = parts[4] if not is_dir else ""
                file_type = "Directory" if is_dir else "File"
                
                self.remote_tree.insert("", "end", text=name, 
                                       values=(size, file_type, " ".join(parts[5:8])), 
                                       iid=os.path.join(path, name), 
                                       tags=("directory" if is_dir else "file",))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list remote directory: {str(e)}")
    
    def on_local_double_click(self, event):
        """Handle double click on local tree"""
        item = self.local_tree.focus()
        if item:
            tags = self.local_tree.item(item, "tags")
            if "directory" in tags:
                self.populate_local_tree(item)
    
    def on_remote_double_click(self, event):
        """Handle double click on remote tree"""
        if not self.connected:
            return
            
        item = self.remote_tree.focus()
        if item:
            tags = self.remote_tree.item(item, "tags")
            if "directory" in tags:
                self.populate_remote_tree(item)
    
    def on_local_select(self, event):
        """Handle selection in local tree"""
        item = self.local_tree.focus()
        if item:
            tags = self.local_tree.item(item, "tags")
            self.upload_btn.config(state=tk.NORMAL if "file" in tags and self.connected else tk.DISABLED)
    
    def on_remote_select(self, event):
        """Handle selection in remote tree"""
        if not self.connected:
            return
            
        item = self.remote_tree.focus()
        if item:
            tags = self.remote_tree.item(item, "tags")
            self.download_btn.config(state=tk.NORMAL if "file" in tags else tk.DISABLED)
            self.delete_btn.config(state=tk.NORMAL)
    
    def download_file(self):
        """Download selected file from server"""
        if not self.connected:
            return
            
        remote_item = self.remote_tree.focus()
        if not remote_item:
            return
            
        tags = self.remote_tree.item(remote_item, "tags")
        if "directory" in tags:
            messagebox.showwarning("Download", "Please select a file to download")
            return
        
        remote_path = remote_item
        filename = os.path.basename(remote_path)
        
        # Get local directory from local tree
        local_dir = self.local_current_dir
        
        # Ask for confirmation
        local_path = os.path.join(local_dir, filename)
        if os.path.exists(local_path):
            if not messagebox.askyesno("Confirm", f"File {filename} already exists. Overwrite?"):
                return
        
        # Download in a separate thread
        threading.Thread(target=self._download_thread, args=(remote_path, local_path), daemon=True).start()
    
    def _download_thread(self, remote_path, local_path):
        """Thread for downloading a file"""
        try:
            self.status_var.set(f"Downloading {os.path.basename(remote_path)}...")
            self.root.update()
            
            with open(local_path, "wb") as f:
                self.ftp.retrbinary(f"RETR {remote_path}", f.write)
            
            self.root.after(0, self._download_complete, local_path)
        except Exception as e:
            self.root.after(0, self._download_failed, str(e))
    
    def _download_complete(self, local_path):
        """Called when download completes successfully"""
        self.status_var.set(f"Download complete: {local_path}")
        self.populate_local_tree(os.path.dirname(local_path))
        messagebox.showinfo("Download", "File downloaded successfully")
    
    def _download_failed(self, error):
        """Called when download fails"""
        messagebox.showerror("Download Error", f"Failed to download file: {error}")
        self.status_var.set("Download failed")
    
    def upload_file(self):
        """Upload selected file to server"""
        if not self.connected:
            return
            
        local_item = self.local_tree.focus()
        if not local_item:
            return
            
        tags = self.local_tree.item(local_item, "tags")
        if "directory" in tags:
            messagebox.showwarning("Upload", "Please select a file to upload")
            return
        
        local_path = local_item
        filename = os.path.basename(local_path)
        remote_dir = self.current_dir
        
        # Check if file already exists on server
        remote_path = os.path.join(remote_dir, filename)
        try:
            # Try to get file size (will raise error_perm if file doesn't exist)
            size = self.ftp.size(remote_path)
            if size >= 0 and not messagebox.askyesno("Confirm", f"File {filename} already exists on server. Overwrite?"):
                return
        except error_perm:
            pass  # File doesn't exist, proceed with upload
        
        # Upload in a separate thread
        threading.Thread(target=self._upload_thread, args=(local_path, remote_path), daemon=True).start()
    
    def _upload_thread(self, local_path, remote_path):
        """Thread for uploading a file"""
        try:
            self.status_var.set(f"Uploading {os.path.basename(local_path)}...")
            self.root.update()
            
            with open(local_path, "rb") as f:
                self.ftp.storbinary(f"STOR {remote_path}", f)
            
            self.root.after(0, self._upload_complete, remote_path)
        except Exception as e:
            self.root.after(0, self._upload_failed, str(e))
    
    def _upload_complete(self, remote_path):
        """Called when upload completes successfully"""
        self.status_var.set(f"Upload complete: {remote_path}")
        self.populate_remote_tree(os.path.dirname(remote_path))
        messagebox.showinfo("Upload", "File uploaded successfully")
    
    def _upload_failed(self, error):
        """Called when upload fails"""
        messagebox.showerror("Upload Error", f"Failed to upload file: {error}")
        self.status_var.set("Upload failed")
    
    def delete_file(self):
        """Delete selected file or directory from server"""
        if not self.connected:
            return
            
        remote_item = self.remote_tree.focus()
        if not remote_item:
            return
            
        tags = self.remote_tree.item(remote_item, "tags")
        name = os.path.basename(remote_item)
        
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {name}?"):
            return
        
        try:
            if "directory" in tags:
                self.ftp.rmd(remote_item)
            else:
                self.ftp.delete(remote_item)
            
            self.status_var.set(f"Deleted: {name}")
            self.populate_remote_tree(os.path.dirname(remote_item))
        except Exception as e:
            messagebox.showerror("Delete Error", f"Failed to delete: {str(e)}")
            self.status_var.set("Delete failed")
    
    def create_remote_folder(self):
        """Create a new folder on the remote server"""
        if not self.connected:
            return
            
        folder_name = simpledialog.askstring("New Folder", "Enter folder name:")
        if not folder_name:
            return
        
        remote_path = os.path.join(self.current_dir, folder_name)
        
        try:
            self.ftp.mkd(remote_path)
            self.status_var.set(f"Created folder: {remote_path}")
            self.populate_remote_tree(self.current_dir)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create folder: {str(e)}")
            self.status_var.set("Create folder failed")
    
    def refresh_lists(self):
        """Refresh both local and remote file lists"""
        self.refresh_local()
        self.refresh_remote()
    
    @staticmethod
    def format_size(size):
        """Format file size in human-readable format"""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    @staticmethod
    def format_time(timestamp):
        """Format timestamp to readable date"""
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

if __name__ == "__main__":
    root = tk.Tk()
    app = FTPClient(root)
    root.mainloop()