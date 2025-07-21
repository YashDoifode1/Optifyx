import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as ttk
import random
import string
import logging
import json
import os
from datetime import datetime

# Configure logging
logging.basicConfig(filename='cipher_tool.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class CustomTooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
    
    def show_tooltip(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip, text=self.text, background="yellow", relief="solid", borderwidth=1)
        label.pack()
    
    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class VigenereCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vigenère Cipher Tool")
        self.root.geometry("700x800")
        self.root.minsize(700, 800)
        
        # Apply modern theme
        self.style = ttk.Style("darkly")
        
        # Load icons (replace with your icon paths or remove)
        try:
            self.encrypt_icon = tk.PhotoImage(file="encrypt.png")
            self.decrypt_icon = tk.PhotoImage(file="decrypt.png")
            self.clear_icon = tk.PhotoImage(file="clear.png")
            self.copy_icon = tk.PhotoImage(file="copy.png")
        except:
            self.encrypt_icon = self.decrypt_icon = self.clear_icon = self.copy_icon = None
        
        # Menu bar
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)
        help_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Cipher mode selection
        ttk.Label(self.main_frame, text="Cipher Mode:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.cipher_mode = tk.StringVar(value="Vigenère")
        cipher_combo = ttk.Combobox(self.main_frame, textvariable=self.cipher_mode, values=["Vigenère", "Caesar"], state="readonly", width=15)
        cipher_combo.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Input text
        ttk.Label(self.main_frame, text="Input Text:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.input_text = tk.Text(self.main_frame, height=4, width=60)
        self.input_text.grid(row=2, column=0, columnspan=3, pady=5)
        ttk.Button(self.main_frame, text="Load File", command=self.load_file).grid(row=2, column=3, padx=5)
        
        # Key
        ttk.Label(self.main_frame, text="Key:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(self.main_frame, width=30)
        self.key_entry.grid(row=4, column=0, pady=5)
        self.key_entry.bind("<KeyRelease>", self.validate_key_real_time)
        ttk.Button(self.main_frame, text="Generate Key", command=self.generate_key).grid(row=4, column=1, pady=5)
        ttk.Button(self.main_frame, text="Save Key", command=self.save_key).grid(row=4, column=2, pady=5)
        ttk.Button(self.main_frame, text="Load Key", command=self.load_key).grid(row=4, column=3, pady=5)
        
        # Key strength indicator
        self.key_strength = ttk.Label(self.main_frame, text="Key Strength: None", foreground="red")
        self.key_strength.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Custom alphabet
        ttk.Label(self.main_frame, text="Custom Alphabet (optional):").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.alphabet_entry = ttk.Entry(self.main_frame, width=50)
        self.alphabet_entry.grid(row=7, column=0, columnspan=3, pady=5)
        self.alphabet_entry.insert(0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        
        # Buttons
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=8, column=0, columnspan=4, pady=20)
        
        ttk.Button(self.button_frame, text="Encrypt", image=self.encrypt_icon, compound=tk.LEFT,
                   command=self.encrypt).grid(row=0, column=0, padx=10)
        ttk.Button(self.button_frame, text="Decrypt", image=self.decrypt_icon, compound=tk.LEFT,
                   command=self.decrypt).grid(row=0, column=1, padx=10)
        ttk.Button(self.button_frame, text="Clear", image=self.clear_icon, compound=tk.LEFT,
                   command=self.clear).grid(row=0, column=2, padx=10)
        ttk.Button(self.button_frame, text="Copy Result", image=self.copy_icon, compound=tk.LEFT,
                   command=self.copy_to_clipboard).grid(row=0, column=3, padx=10)
        ttk.Button(self.button_frame, text="Save Result", command=self.save_result).grid(row=0, column=4, padx=10)
        
        # Output
        ttk.Label(self.main_frame, text="Result:").grid(row=9, column=0, sticky=tk.W, pady=5)
        self.output_text = tk.Text(self.main_frame, height=4, width=60, state='disabled')
        self.output_text.grid(row=10, column=0, columnspan=3, pady=5)
        
        # History
        ttk.Label(self.main_frame, text="History:").grid(row=11, column=0, sticky=tk.W, pady=5)
        self.history_list = tk.Listbox(self.main_frame, height=6, width=60)
        self.history_list.grid(row=12, column=0, columnspan=3, pady=5)
        
        # Tooltips
        CustomTooltip(self.input_text, "Enter text to encrypt or decrypt")
        CustomTooltip(self.key_entry, "Enter the encryption/decryption key (letters for Vigenère, number for Caesar)")
        CustomTooltip(self.alphabet_entry, "Enter custom alphabet or leave as default (A-Z)")
        CustomTooltip(cipher_combo, "Select cipher mode: Vigenère or Caesar")
        
        # Keyboard shortcuts
        self.root.bind("<Control-e>", lambda e: self.encrypt())
        self.root.bind("<Control-d>", lambda e: self.decrypt())
        self.root.bind("<Control-c>", lambda e: self.clear())
        self.root.bind("<Control-y>", lambda e: self.copy_to_clipboard())
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        
        # History storage
        self.history = []
    
    def vigenere_cipher(self, text, key, mode='encrypt', alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        result = ""
        key = key.upper()
        text = text.upper()
        key_index = 0
        
        for char in text:
            if char in alphabet:
                char_val = alphabet.index(char)
                key_val = alphabet.index(key[key_index % len(key)])
                if mode == 'encrypt':
                    new_val = (char_val + key_val) % len(alphabet)
                else:
                    new_val = (char_val - key_val) % len(alphabet)
                result += alphabet[new_val]
                key_index += 1
            else:
                result += char
        return result
    
    def caesar_cipher(self, text, key, mode='encrypt', alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        try:
            shift = int(key) if mode == 'encrypt' else -int(key)
        except ValueError:
            raise ValueError("Caesar cipher key must be a number")
        result = ""
        text = text.upper()
        for char in text:
            if char in alphabet:
                char_val = alphabet.index(char)
                new_val = (char_val + shift) % len(alphabet)
                result += alphabet[new_val]
            else:
                result += char
        return result
    
    def generate_key(self):
        key_length = 12
        key = ''.join(random.choice(string.ascii_uppercase) for _ in range(key_length))
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        self.validate_key_real_time(None)
    
    def save_key(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "No key to save")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump({"key": key}, f)
                messagebox.showinfo("Success", "Key saved successfully")
            except Exception as e:
                logging.error(f"Failed to save key: {str(e)}")
                messagebox.showerror("Error", f"Failed to save key: {str(e)}")
    
    def load_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    self.key_entry.delete(0, tk.END)
                    self.key_entry.insert(0, data["key"])
                    self.validate_key_real_time(None)
            except Exception as e:
                logging.error(f"Failed to load key: {str(e)}")
                messagebox.showerror("Error", f"Failed to load key: {str(e)}")
    
    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    text = f.read()
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert(tk.END, text)
            except Exception as e:
                logging.error(f"Failed to load file: {str(e)}")
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def save_result(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if not result:
            messagebox.showerror("Error", "No result to save")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(result)
                messagebox.showinfo("Success", "Result saved successfully")
            except Exception as e:
                logging.error(f"Failed to save result: {str(e)}")
                messagebox.showerror("Error", f"Failed to save result: {str(e)}")
    
    def copy_to_clipboard(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Success", "Result copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No result to copy!")
    
    def validate_key_real_time(self, event):
        key = self.key_entry.get().strip()
        mode = self.cipher_mode.get()
        if not key:
            self.key_strength.config(text="Key Strength: None", foreground="red")
        elif mode == "Caesar":
            try:
                int(key)
                self.key_strength.config(text="Key Strength: Valid", foreground="green")
            except ValueError:
                self.key_strength.config(text="Key Strength: Invalid (use number)", foreground="red")
        elif len(key) < 6:
            self.key_strength.config(text="Key Strength: Weak", foreground="orange")
        elif len(set(key.lower())) < 4:
            self.key_strength.config(text="Key Strength: Medium", foreground="yellow")
        else:
            self.key_strength.config(text="Key Strength: Strong", foreground="green")
    
    def validate_input(self):
        text = self.input_text.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        mode = self.cipher_mode.get()
        alphabet = self.alphabet_entry.get().strip()
        
        if not text:
            messagebox.showerror("Error", "Please enter text to encrypt/decrypt")
            return False
        if not key:
            messagebox.showerror("Error", "Please enter a key")
            return False
        if mode == "Vigenère" and not key.isalpha():
            messagebox.showerror("Error", "Vigenère key must contain only letters")
            return False
        if mode == "Caesar":
            try:
                int(key)
            except ValueError:
                messagebox.showerror("Error", "Caesar key must be a number")
                return False
        if not alphabet:
            messagebox.showerror("Error", "Please enter an alphabet")
            return False
        return True
    
    def encrypt(self):
        if not self.validate_input():
            return
        text = self.input_text.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        mode = self.cipher_mode.get()
        alphabet = self.alphabet_entry.get().strip()
        
        try:
            if mode == "Vigenère":
                result = self.vigenere_cipher(text, key, mode='encrypt', alphabet=alphabet)
            else:
                result = self.caesar_cipher(text, key, mode='encrypt', alphabet=alphabet)
            self.output_text.config(state='normal')
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
            self.output_text.config(state='disabled')
            self.add_to_history(f"Encrypted: {text[:20]}... with key {key} -> {result[:20]}...")
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt(self):
        if not self.validate_input():
            return
        text = self.input_text.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        mode = self.cipher_mode.get()
        alphabet = self.alphabet_entry.get().strip()
        
        try:
            if mode == "Vigenère":
                result = self.vigenere_cipher(text, key, mode='decrypt', alphabet=alphabet)
            else:
                result = self.caesar_cipher(text, key, mode='decrypt', alphabet=alphabet)
            self.output_text.config(state='normal')
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
            self.output_text.config(state='disabled')
            self.add_to_history(f"Decrypted: {text[:20]}... with key {key} -> {result[:20]}...")
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def add_to_history(self, entry):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.history.append(f"[{timestamp}] {entry}")
        self.history_list.delete(0, tk.END)
        for item in self.history[-10:]:  # Show last 10 entries
            self.history_list.insert(tk.END, item)
    
    def clear(self):
        self.input_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.alphabet_entry.delete(0, tk.END)
        self.alphabet_entry.insert(0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state='disabled')
        self.key_strength.config(text="Key Strength: None", foreground="red")
    
    def show_about(self):
        messagebox.showinfo("About", "Vigenère Cipher Tool v1.0\nA professional encryption/decryption tool.\nSupports Vigenère and Caesar ciphers.\nDeveloped by xAI.")

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = VigenereCipherApp(root)
    root.mainloop()