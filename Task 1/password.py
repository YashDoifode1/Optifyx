import tkinter as tk
from tkinter import ttk
import re
import string
import random
import math

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass - Password Strength Checker")
        self.root.geometry("550x700")  # Increased height for logo
        self.root.resizable(False, False)
        self.root.configure(bg="#e8ecef")

        # Load common passwords
        self.common_passwords = self.load_common_passwords()

        # Variables
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)

        # Create GUI
        self.setup_gui()

    def load_common_passwords(self):
        """Load common passwords from rockyou.txt"""
        try:
            with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as file:
                return set(line.strip().lower() for line in file if line.strip())
        except FileNotFoundError:
            return set()

    def setup_gui(self):
        """Set up the Tkinter GUI with professional styling and logo"""
        # Main frame
        main_frame = tk.Frame(self.root, bg="#e8ecef", padx=20, pady=20)
        main_frame.pack(expand=True, fill="both")

        # Logo
        try:
            self.logo_image = tk.PhotoImage(file="logo.gif")
            logo_label = tk.Label(main_frame, image=self.logo_image, bg="#e8ecef")
            logo_label.pack(pady=(10, 5))
        except tk.TclError:
            logo_label = tk.Label(
                main_frame, text="[Logo Placeholder]", font=("Arial", 10, "italic"),
                bg="#e8ecef", fg="#2c3e50"
            )
            logo_label.pack(pady=(10, 5))

        # Title (ASCII art as placeholder in comments)
        """
        SecurePass Logo:
         _____
        |  ___|  SecurePass
        | |__    Password Strength Checker
        |___|    v1.1
        """
        title_label = tk.Label(
            main_frame, 
            text="SecurePass\nPassword Strength Checker\nv1.1",
            font=("Arial", 16, "bold"),
            bg="#e8ecef", fg="#2c3e50", justify="center"
        )
        title_label.pack(pady=(0, 20))

        # Password entry frame
        entry_frame = tk.Frame(main_frame, bg="#e8ecef")
        entry_frame.pack(pady=10, fill="x")

        tk.Label(
            entry_frame, text="Password:", font=("Arial", 12, "bold"), bg="#e8ecef", fg="#2c3e50"
        ).pack(anchor="w")
        self.password_entry = tk.Entry(
            entry_frame, textvariable=self.password_var, show="*", font=("Arial", 12),
            width=30, bd=0, bg="#ffffff", highlightthickness=1, highlightcolor="#007bff"
        )
        self.password_entry.pack(pady=5, ipady=6, fill="x")
        self.password_entry.bind("<KeyRelease>", self.evaluate_password)

        # Show password checkbox
        show_password_check = tk.Checkbutton(
            entry_frame, text="Show Password", variable=self.show_password_var,
            command=self.toggle_password_visibility, bg="#e8ecef", font=("Arial", 10),
            fg="#2c3e50", activeforeground="#007bff"
        )
        show_password_check.pack(anchor="w", pady=5)

        # Button frame
        button_frame = tk.Frame(main_frame, bg="#e8ecef")
        button_frame.pack(pady=10)

        # Evaluate button
        evaluate_button = tk.Button(
            button_frame, text="Evaluate Password", command=self.evaluate_password,
            bg="#007bff", fg="white", font=("Arial", 11, "bold"),
            relief="flat", activebackground="#0056b3", cursor="hand2", width=15
        )
        evaluate_button.grid(row=0, column=0, padx=5)
        evaluate_button.bind("<Enter>", lambda e: evaluate_button.config(bg="#0056b3"))
        evaluate_button.bind("<Leave>", lambda e: evaluate_button.config(bg="#007bff"))

        # Generate password button
        generate_button = tk.Button(
            button_frame, text="Generate Password", command=self.generate_password,
            bg="#28a745", fg="white", font=("Arial", 11, "bold"),
            relief="flat", activebackground="#218838", cursor="hand2", width=15
        )
        generate_button.grid(row=0, column=1, padx=5)
        generate_button.bind("<Enter>", lambda e: generate_button.config(bg="#218838"))
        generate_button.bind("<Leave>", lambda e: generate_button.config(bg="#28a745"))

        # Strength label
        self.strength_label = tk.Label(
            main_frame, text="Strength: None", font=("Arial", 12, "bold"),
            bg="#e8ecef", fg="#2c3e50"
        )
        self.strength_label.pack(pady=5)

        # Crack time label
        self.crack_time_label = tk.Label(
            main_frame, text="Time to Crack: N/A", font=("Arial", 10, "italic"),
            bg="#e8ecef", fg="#2c3e50", wraplength=450
        )
        self.crack_time_label.pack(pady=5)

        # Progress bar with custom style
        style = ttk.Style()
        style.configure("Custom.Horizontal.TProgressbar", troughcolor="#e8ecef", background="#28a745")
        self.progress_bar = ttk.Progressbar(
            main_frame, orient="horizontal", length=300, mode="determinate", style="Custom.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(pady=10)

        # Common password warning
        self.common_warning_label = tk.Label(
            main_frame, text="", font=("Arial", 10), bg="#e8ecef", fg="#dc3545",
            wraplength=450
        )
        self.common_warning_label.pack(pady=5)

        # Suggestions text
        self.suggestions_text = tk.Text(
            main_frame, height=8, width=40, font=("Arial", 10),
            bd=0, bg="#ffffff", highlightthickness=1, highlightcolor="#007bff", wrap="word"
        )
        self.suggestions_text.pack(pady=10)
        self.suggestions_text.config(state="disabled")

        # Quit button
        quit_button = tk.Button(
            main_frame, text="Quit", command=self.root.quit,
            bg="#dc3545", fg="white", font=("Arial", 11, "bold"),
            relief="flat", activebackground="#c82333", cursor="hand2", width=10
        )
        quit_button.pack(pady=(20, 0))
        quit_button.bind("<Enter>", lambda e: quit_button.config(bg="#c82333"))
        quit_button.bind("<Leave>", lambda e: quit_button.config(bg="#dc3545"))

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def generate_password(self):
        """Generate a strong random password"""
        length = random.randint(12, 16)
        chars = (
            string.ascii_uppercase + string.ascii_lowercase +
            string.digits + "!@#$%^&*(),.?\":{}|<>"
        )
        while True:
            password = "".join(random.choice(chars) for _ in range(length))
            strength, _, _ = self.check_password_strength(password)
            if (strength == "Strong" and
                not self.has_repetitive_or_sequential(password) and
                password.lower() not in self.common_passwords):
                break
        self.password_var.set(password)
        self.evaluate_password()

    def estimate_crack_time(self, password):
        """Estimate time to crack the password's hash"""
        if not password:
            return "N/A"

        # Estimate character set size based on password content
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26  # Lowercase
        if re.search(r"[A-Z]", password):
            charset_size += 26  # Uppercase
        if re.search(r"\d", password):
            charset_size += 10  # Digits
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            charset_size += 32  # Common special characters

        if charset_size == 0:
            return "N/A"

        # Calculate total combinations
        combinations = charset_size ** len(password)

        # Assume 10 billion hashes per second (modern GPU cracking speed)
        hashes_per_second = 10_000_000_000
        seconds = combinations / hashes_per_second

        # Convert to human-readable format
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.2f} hours"
        elif seconds < 31_536_000:
            return f"{seconds / 86400:.2f} days"
        elif seconds < 31_536_000 * 100:
            return f"{seconds / 31_536_000:.2f} years"
        else:  # For extremely large times
            years = seconds / 31_536_000
            if years > 1_000_000:
                return f"{years / 1_000_000:.2f} million years"
            elif years > 1_000_000_000:
                return f"{years / 1_000_000_000:.2f} billion years"
            else:
                return f"{years:.2f} years"

    def evaluate_password(self, event=None):
        """Evaluate the password strength and update GUI"""
        password = self.password_var.get()
        strength, score, suggestions = self.check_password_strength(password)
        is_common = password.lower() in self.common_passwords

        # Update strength label and progress bar
        colors = {"Weak": "#dc3545", "Medium": "#ffc107", "Strong": "#28a745"}
        self.strength_label.config(text=f"Strength: {strength}", fg=colors[strength])
        self.progress_bar["value"] = score * 20  # Scale score (0-5) to 0-100
        self.progress_bar["style"] = "Custom.Horizontal.TProgressbar"
        style = ttk.Style()
        style.configure("Custom.Horizontal.TProgressbar", background=colors[strength])

        # Update crack time
        crack_time = self.estimate_crack_time(password)
        self.crack_time_label.config(text=f"Time to Crack: {crack_time}")

        # Update common password warning
        if is_common:
            self.common_warning_label.config(
                text="This is a common password. Choose something more unique."
            )
            self.crack_time_label.config(text="Time to Crack: Instant (Common Password)")
        else:
            self.common_warning_label.config(text="")

        # Update suggestions
        self.suggestions_text.config(state="normal")
        self.suggestions_text.delete("1.0", tk.END)
        if suggestions:
            self.suggestions_text.insert(tk.END, "\n".join(suggestions))
        else:
            self.suggestions_text.insert(tk.END, "Password meets all criteria!")
        self.suggestions_text.config(state="disabled")

    def check_password_strength(self, password):
        """Check password strength based on criteria"""
        score = 0
        suggestions = []

        # Length check
        if len(password) >= 8:
            score += 1
        else:
            suggestions.append("Add more characters (at least 8).")

        # Uppercase and lowercase check
        if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
            score += 1
        else:
            suggestions.append("Include both uppercase and lowercase letters.")

        # Digit check
        if re.search(r"\d", password):
            score += 1
        else:
            suggestions.append("Add at least one digit.")

        # Special character check
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            suggestions.append("Add at least one special character.")

        # Check for repetitive or sequential characters
        if not self.has_repetitive_or_sequential(password):
            score += 1
        else:
            suggestions.append("Avoid repetitive or sequential characters (e.g., 'aaaa', '1234').")

        # Determine strength
        if score <= 2:
            strength = "Weak"
        elif score <= 4:
            strength = "Medium"
        else:
            strength = "Strong"

        return strength, score, suggestions

    def has_repetitive_or_sequential(self, password):
        """Check for repetitive or sequential characters"""
        # Check for repetitive characters (e.g., 'aaa')
        for i in range(len(password) - 2):
            if password[i] == password[i + 1] == password[i + 2]:
                return True

        # Check for sequential characters (e.g., '123', 'abc')
        for i in range(len(password) - 2):
            chars = password[i:i + 3].lower()
            if chars in string.ascii_lowercase or chars in "0123456789":
                return True
            # Check for reverse sequences
            if chars[::-1] in string.ascii_lowercase or chars[::-1] in "0123456789":
                return True

        return False

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()