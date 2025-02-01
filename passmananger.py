#!/usr/bin/env python3
import sys
import json
import os
import secrets
import string
import math
import hashlib
import requests
import threading
from collections import Counter
from cryptography.fernet import Fernet

DATA_FILE = 'passwords.json'
KEY_FILE = 'key.key'
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

# Cross-platform file locking
if os.name == 'nt':  # Windows
    import msvcrt
else:  # Unix-like
    import fcntl

def show_warning():
    """Display a warning message before starting the program."""
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.withdraw()  # Hide the root window

    warning_message = (
        "WARNING: This password manager stores your passwords locally on your device.\n\n"
        "Your passwords are NOT saved in the cloud or on any external servers. "
        "If this application or your device encounters any issues (e.g., data corruption, device failure, or accidental deletion), "
        "ALL YOUR PASSWORDS COULD BE LOST PERMANENTLY.\n\n"
        "It is highly recommended to:"
        f"\n1. Regularly back up the following files to a secure location:"
        f"\n   - {os.path.abspath(DATA_FILE)}"
        f"\n   - {os.path.abspath(KEY_FILE)}"
        "\n2. Use additional backup methods (e.g., encrypted USB drives or secure cloud storage) to ensure data safety."
        "\n\nBy proceeding, you acknowledge and accept this risk."
    )

    # Show the warning message
    response = messagebox.showwarning(
        "Important Warning",
        warning_message,
        parent=root
    )

    root.destroy()  # Close the warning window

def generate_key():
    """Generate a new Fernet key and save it to KEY_FILE."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key

def load_key():
    """Load the Fernet key from KEY_FILE; generate one if it doesn't exist."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        return generate_key()

# Initialize the Fernet object using our key
fernet = Fernet(load_key())

def load_data():
    """Load and decrypt stored password data from the JSON file."""
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'rb') as f:
                encrypted = f.read()
                if encrypted:
                    decrypted = fernet.decrypt(encrypted)
                    return json.loads(decrypted.decode('utf-8'))
        except (json.JSONDecodeError, Exception) as e:
            print(f"Error loading or decrypting data file: {e}")
            return {}
    return {}

def save_data(data):
    """Encrypt and save password data to the JSON file."""
    json_data = json.dumps(data, indent=4).encode('utf-8')
    encrypted = fernet.encrypt(json_data)
    with open(DATA_FILE, 'wb') as f:
        if os.name == 'nt':  # Windows
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, len(encrypted))
        else:  # Unix-like
            fcntl.flock(f, fcntl.LOCK_EX)  # Lock the file
        f.write(encrypted)
        if os.name == 'nt':  # Windows
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, len(encrypted))
        else:  # Unix-like
            fcntl.flock(f, fcntl.LOCK_UN)  # Unlock the file

def generate_secure_password(length=12, uppercase=True, lowercase=True, digits=True, special=True, avoid_ambiguous=True, include_spaces=False):
    """Generate a secure random password with customizable options."""
    if length < 4 or length > 128:
        raise ValueError("Password length must be between 4 and 128 characters.")
    
    alphabet = ""
    if uppercase:
        alphabet += string.ascii_uppercase
    if lowercase:
        alphabet += string.ascii_lowercase
    if digits:
        alphabet += string.digits
    if special:
        alphabet += string.punctuation
    if include_spaces:
        alphabet += " "
    
    if avoid_ambiguous:
        ambiguous = "lI1O0"
        alphabet = ''.join(c for c in alphabet if c not in ambiguous)
    
    if not alphabet:
        raise ValueError("At least one character set (uppercase, lowercase, digits, or special) must be selected.")
    
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (not uppercase or any(c in string.ascii_uppercase for c in password)) and \
           (not lowercase or any(c in string.ascii_lowercase for c in password)) and \
           (not digits or any(c in string.digits for c in password)) and \
           (not special or any(c in string.punctuation for c in password)):
            return password

def estimate_crack_time(password):
    """Estimate the time required to crack a given password."""
    if not password:
        return "Instant (no password)"
    
    # Determine character set size
    lowercase = any(c in string.ascii_lowercase for c in password)
    uppercase = any(c in string.ascii_uppercase for c in password)
    digits = any(c in string.digits for c in password)
    symbols = any(c in string.punctuation for c in password)
    spaces = any(c == " " for c in password)
    
    charset_size = 0
    if lowercase:
        charset_size += 26
    if uppercase:
        charset_size += 26
    if digits:
        charset_size += 10
    if symbols:
        charset_size += 32
    if spaces:
        charset_size += 1
    
    if charset_size == 0:
        return "Instant (empty charset)"
    
    # Calculate entropy
    entropy = len(password) * math.log2(charset_size)
    
    # Assume 1 trillion attempts per second
    attempts_per_second = 1e12
    seconds = (0.5 * (2 ** entropy)) / attempts_per_second
    
    # Convert to human-readable time
    intervals = (
        (1e-6, 'Instant'),
        (1, 'milliseconds', 1e3),
        (60, 'seconds', 1),
        (3600, 'minutes', 1/60),
        (86400, 'hours', 1/3600),
        (31536000, 'days', 1/86400),
        (float('inf'), 'years', 1/31536000)
    )
    
    for i in range(1, len(intervals)):
        prev_limit, prev_label = intervals[i-1][0], intervals[i-1][1]
        curr_limit, curr_label, factor = intervals[i]
        if seconds < curr_limit:
            scaled_time = seconds * factor
            if scaled_time < 1000:
                return f"{scaled_time:.2f} {curr_label}"
            else:
                return format_large_time(scaled_time)
    return format_large_time(seconds * 1/31536000)

def format_large_time(years):
    """Format very large time spans into thousands/millions/billions of years."""
    if years < 1e3:
        return f"{years:.2f} years"
    elif years < 1e6:
        return f"{years/1e3:.2f} thousand years"
    elif years < 1e9:
        return f"{years/1e6:.2f} million years"
    elif years < 1e12:
        return f"{years/1e9:.2f} billion years"
    else:
        return f"{years/1e12:.2f} trillion years"

def check_password_leak(password):
    """Check if a password has been leaked using HIBP API."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    try:
        response = requests.get(HIBP_API_URL + prefix)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
                    return f"Password leaked {count} times."
            return "Password not found in any known leaks."
        else:
            return f"Error: API returned status code {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

def analyze_password(password):
    """Analyze password for statistics, entropy, and warnings."""
    stats = {
        "length": len(password),
        "uppercase": sum(1 for c in password if c in string.ascii_uppercase),
        "lowercase": sum(1 for c in password if c in string.ascii_lowercase),
        "digits": sum(1 for c in password if c in string.digits),
        "special": sum(1 for c in password if c in string.punctuation),
        "spaces": sum(1 for c in password if c == " "),
        "entropy": calculate_entropy(password),
        "order_of_magnitude": estimate_order_of_magnitude(password),
        "warnings": check_password_warnings(password),
        "suggestions": suggest_password_improvements(password)
    }
    return stats

def calculate_entropy(password):
    """Calculate the entropy of a password."""
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32
    if any(c == " " for c in password):
        charset_size += 1
    
    if charset_size == 0:
        return 0
    return len(password) * math.log2(charset_size)

def estimate_order_of_magnitude(password):
    """Estimate the order of magnitude of guesses required to crack the password."""
    entropy = calculate_entropy(password)
    return f"2^{entropy:.2f}"

def check_password_warnings(password):
    """Check for common password weaknesses."""
    warnings = []
    if len(password) < 8:
        warnings.append("Password is too short (less than 8 characters).")
    if not any(c in string.ascii_uppercase for c in password):
        warnings.append("Password lacks uppercase letters.")
    if not any(c in string.ascii_lowercase for c in password):
        warnings.append("Password lacks lowercase letters.")
    if not any(c in string.digits for c in password):
        warnings.append("Password lacks digits.")
    if not any(c in string.punctuation for c in password):
        warnings.append("Password lacks special characters.")
    if " " in password:
        warnings.append("Password contains spaces, which may not be supported by all systems.")
    if is_common_sequence(password):
        warnings.append("Password contains a common sequence or pattern.")
    return warnings

def is_common_sequence(password):
    """Check if the password contains common sequences."""
    common_sequences = [
        "123", "abc", "qwerty", "password", "admin", "letmein", "welcome"
    ]
    password_lower = password.lower()
    for seq in common_sequences:
        if seq in password_lower:
            return True
    return False

def suggest_password_improvements(password):
    """Provide suggestions to improve password strength."""
    suggestions = []
    if len(password) < 12:
        suggestions.append("Consider increasing the password length to at least 12 characters.")
    if not any(c in string.ascii_uppercase for c in password):
        suggestions.append("Add uppercase letters to increase complexity.")
    if not any(c in string.ascii_lowercase for c in password):
        suggestions.append("Add lowercase letters to increase complexity.")
    if not any(c in string.digits for c in password):
        suggestions.append("Add digits to increase complexity.")
    if not any(c in string.punctuation for c in password):
        suggestions.append("Add special characters to increase complexity.")
    if is_common_sequence(password):
        suggestions.append("Avoid common sequences or patterns.")
    return suggestions

def cli_mode():
    """CLI interface with advanced password analysis."""
    data = load_data()
    while True:
        print("\n=== Password Manager CLI ===")
        print("1. Add Entry")
        print("2. Delete Entry")
        print("3. List All Accounts")
        print("4. Generate Secure Password")
        print("5. Check Password Leak")
        print("6. Analyze Password")
        print("7. Quit")
        choice = input("Enter your choice (1-7): ").strip()
        
        if choice == '1':
            account = input("Enter account name: ").strip()
            username = input("Enter username: ").strip()
            password = input("Enter password (or leave blank to generate one): ").strip()
            if not password:
                try:
                    length = int(input("Enter desired password length (default 12): ") or "12")
                except ValueError:
                    length = 12
                password = generate_secure_password(length)
                print(f"Generated password: {password}")
                crack_time = estimate_crack_time(password)
                print(f"Estimated crack time: {crack_time}")
                leak_status = check_password_leak(password)
                print(f"Leak check: {leak_status}")
                analysis = analyze_password(password)
                print("Password Analysis:")
                print(f"  Entropy: {analysis['entropy']:.2f} bits")
                print(f"  Order of Magnitude: {analysis['order_of_magnitude']}")
                if analysis['warnings']:
                    print("  Warnings:")
                    for warning in analysis['warnings']:
                        print(f"    - {warning}")
                if analysis['suggestions']:
                    print("  Suggestions:")
                    for suggestion in analysis['suggestions']:
                        print(f"    - {suggestion}")
            else:
                crack_time = estimate_crack_time(password)
                print(f"Estimated crack time: {crack_time}")
                leak_status = check_password_leak(password)
                print(f"Leak check: {leak_status}")
                analysis = analyze_password(password)
                print("Password Analysis:")
                print(f"  Entropy: {analysis['entropy']:.2f} bits")
                print(f"  Order of Magnitude: {analysis['order_of_magnitude']}")
                if analysis['warnings']:
                    print("  Warnings:")
                    for warning in analysis['warnings']:
                        print(f"    - {warning}")
                if analysis['suggestions']:
                    print("  Suggestions:")
                    for suggestion in analysis['suggestions']:
                        print(f"    - {suggestion}")
            data[account] = {"username": username, "password": password}
            save_data(data)
            print(f"Entry for '{account}' added.")
        elif choice == '2':
            account = input("Enter account name to delete: ").strip()
            if account in data:
                del data[account]
                save_data(data)
                print(f"Entry for '{account}' deleted.")
            else:
                print("Account not found.")
        elif choice == '3':
            if data:
                print("Stored Accounts:")
                for account in data:
                    entry = data[account]
                    print(f" - Account: {account}")
                    print(f"   Username: {entry['username']}")
                    print(f"   Password: {entry['password']}")
            else:
                print("No accounts stored.")
        elif choice == '4':
            try:
                length = int(input("Enter desired password length (default 12): ") or "12")
            except ValueError:
                print("Invalid input. Using default length of 12.")
                length = 12
            generated = generate_secure_password(length)
            print(f"Generated Secure Password: {generated}")
            crack_time = estimate_crack_time(generated)
            print(f"Estimated crack time: {crack_time}")
            leak_status = check_password_leak(generated)
            print(f"Leak check: {leak_status}")
            analysis = analyze_password(generated)
            print("Password Analysis:")
            print(f"  Entropy: {analysis['entropy']:.2f} bits")
            print(f"  Order of Magnitude: {analysis['order_of_magnitude']}")
            if analysis['warnings']:
                print("  Warnings:")
                for warning in analysis['warnings']:
                    print(f"    - {warning}")
            if analysis['suggestions']:
                print("  Suggestions:")
                for suggestion in analysis['suggestions']:
                    print(f"    - {suggestion}")
        elif choice == '5':
            password = input("Enter password to check: ").strip()
            leak_status = check_password_leak(password)
            print(f"Leak check: {leak_status}")
        elif choice == '6':
            password = input("Enter password to analyze: ").strip()
            analysis = analyze_password(password)
            print("Password Analysis:")
            print(f"  Entropy: {analysis['entropy']:.2f} bits")
            print(f"  Order of Magnitude: {analysis['order_of_magnitude']}")
            if analysis['warnings']:
                print("  Warnings:")
                for warning in analysis['warnings']:
                    print(f"    - {warning}")
            if analysis['suggestions']:
                print("  Suggestions:")
                for suggestion in analysis['suggestions']:
                    print(f"    - {suggestion}")
        elif choice == '7':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please choose a number between 1 and 7.")

def gui_mode():
    """Enhanced GUI with advanced password analysis."""
    import tkinter as tk
    from tkinter import simpledialog, messagebox
    from tkinter import ttk

    data = load_data()
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("600x500")
    root.minsize(600, 500)  # Set minimum window size
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    
    # Custom Styling
    style = ttk.Style()
    style.theme_use('clam')
    
    # Configure styles
    style.configure("TButton", font=("Helvetica", 12), padding=10, background="#4CAF50", foreground="white")
    style.map("TButton", background=[("active", "#45a049")])
    style.configure("TLabel", font=("Helvetica", 12), background="#f0f0f0")
    style.configure("TFrame", background="#f0f0f0")
    style.configure("Header.TLabel", font=("Helvetica", 16, "bold"), background="#f0f0f0")
    
    main_frame = ttk.Frame(root, padding=20)
    main_frame.pack(expand=True, fill="both")
    
    header_label = ttk.Label(main_frame, text="Password Manager", style="Header.TLabel")
    header_label.pack(pady=10)
    
    def copy_to_clipboard(text):
        root.clipboard_clear()
        root.clipboard_append(text)
        messagebox.showinfo("Copied", "Copied to clipboard!", parent=root)
        threading.Timer(30.0, root.clipboard_clear).start()  # Clear clipboard after 30 seconds
    
    def toggle_password_visibility(entry):
        if entry.cget('show') == '*':
            entry.config(show='')
        else:
            entry.config(show='*')
    
    def add_entry():
        account = simpledialog.askstring("Add Entry", "Enter account name:", parent=root)
        if account:
            username = simpledialog.askstring("Add Entry", "Enter username:", parent=root)
            password = simpledialog.askstring("Add Entry", "Enter password (or leave blank to generate one):", parent=root, show="*")
            if not password:
                try:
                    length = simpledialog.askinteger("Generate Password", "Enter desired password length (default 12):", parent=root, initialvalue=12, minvalue=4)
                except Exception:
                    length = 12
                password = generate_secure_password(length or 12)
                gen_win = tk.Toplevel(root)
                gen_win.title("Generated Password")
                ttk.Label(gen_win, text="Generated Password:", font=("Helvetica", 12)).pack(pady=5)
                pwd_entry = ttk.Entry(gen_win, font=("Helvetica", 12), width=30)
                pwd_entry.insert(0, password)
                pwd_entry.config(state="readonly")
                pwd_entry.pack(pady=5)
                crack_time = estimate_crack_time(password)
                ttk.Label(gen_win, text=f"Estimated crack time: {crack_time}").pack(pady=5)
                leak_status = check_password_leak(password)
                ttk.Label(gen_win, text=f"Leak check: {leak_status}").pack(pady=5)
                analysis = analyze_password(password)
                ttk.Label(gen_win, text="Password Analysis:", font=("Helvetica", 12, "bold")).pack(pady=5)
                ttk.Label(gen_win, text=f"Entropy: {analysis['entropy']:.2f} bits").pack(pady=2)
                ttk.Label(gen_win, text=f"Order of Magnitude: {analysis['order_of_magnitude']}").pack(pady=2)
                if analysis['warnings']:
                    ttk.Label(gen_win, text="Warnings:", font=("Helvetica", 12, "bold")).pack(pady=5)
                    for warning in analysis['warnings']:
                        ttk.Label(gen_win, text=f"- {warning}").pack(pady=2)
                if analysis['suggestions']:
                    ttk.Label(gen_win, text="Suggestions:", font=("Helvetica", 12, "bold")).pack(pady=5)
                    for suggestion in analysis['suggestions']:
                        ttk.Label(gen_win, text=f"- {suggestion}").pack(pady=2)
                copy_btn = ttk.Button(gen_win, text="Copy", command=lambda: copy_to_clipboard(password))
                copy_btn.pack(pady=5)
                ttk.Button(gen_win, text="Close", command=gen_win.destroy).pack(pady=5)
            data[account] = {"username": username, "password": password}
            save_data(data)
            crack_time = estimate_crack_time(password)
            leak_status = check_password_leak(password)
            analysis = analyze_password(password)
            messagebox.showinfo("Success", f"Entry for '{account}' added.\nEstimated crack time: {crack_time}\nLeak check: {leak_status}\nPassword Analysis:\nEntropy: {analysis['entropy']:.2f} bits\nOrder of Magnitude: {analysis['order_of_magnitude']}", parent=root)
    
    def delete_entry():
        account = simpledialog.askstring("Delete Entry", "Enter account name:", parent=root)
        if account:
            if account in data:
                del data[account]
                save_data(data)
                messagebox.showinfo("Deleted", f"Entry for '{account}' deleted.", parent=root)
            else:
                messagebox.showerror("Error", "Account not found.", parent=root)
    
    def list_entries():
        if data:
            list_win = tk.Toplevel(root)
            list_win.title("Stored Accounts")
            list_win.geometry("600x400")
            list_win.minsize(600, 400)
            
            # Create a frame for the list
            list_frame = ttk.Frame(list_win, padding=10)
            list_frame.pack(expand=True, fill="both")
            
            # Add a scrollbar
            scrollbar = ttk.Scrollbar(list_frame)
            scrollbar.pack(side="right", fill="y")
            
            # Create a canvas to hold the list
            canvas = tk.Canvas(list_frame, yscrollcommand=scrollbar.set)
            canvas.pack(side="left", expand=True, fill="both")
            
            # Configure the scrollbar
            scrollbar.config(command=canvas.yview)
            
            # Create a frame inside the canvas to hold the entries
            entries_frame = ttk.Frame(canvas)
            canvas.create_window((0, 0), window=entries_frame, anchor="nw")
            
            # Add entries to the frame
            for account, entry in data.items():
                entry_frame = ttk.Frame(entries_frame, padding=5)
                entry_frame.pack(fill="x", pady=5)
                
                ttk.Label(entry_frame, text=f"Account: {account}", font=("Helvetica", 12, "bold")).pack(anchor="w")
                ttk.Label(entry_frame, text=f"Username: {entry['username']}").pack(anchor="w")
                
                # Password entry with show/hide and copy buttons
                password_frame = ttk.Frame(entry_frame)
                password_frame.pack(anchor="w")
                password_entry = ttk.Entry(password_frame, font=("Helvetica", 12), width=30)
                password_entry.insert(0, entry['password'])
                password_entry.config(show="*")
                password_entry.pack(side="left", padx=5)
                ttk.Button(password_frame, text="Show", command=lambda e=password_entry: toggle_password_visibility(e)).pack(side="left", padx=5)
                ttk.Button(password_frame, text="Copy", command=lambda p=entry['password']: copy_to_clipboard(p)).pack(side="left", padx=5)
                
                # Update button
                ttk.Button(entry_frame, text="Update", command=lambda a=account, u=entry['username'], p=entry['password']: update_entry(a, u, p)).pack(anchor="w", pady=5)
            
            # Update the canvas scroll region
            entries_frame.update_idletasks()
            canvas.config(scrollregion=canvas.bbox("all"))
        else:
            messagebox.showinfo("Stored Accounts", "No accounts stored.", parent=root)
    
    def update_entry(account, username, password):
        update_win = tk.Toplevel(root)
        update_win.title(f"Update Entry for {account}")
        
        ttk.Label(update_win, text="Username:", font=("Helvetica", 12)).grid(row=0, column=0, padx=10, pady=10, sticky="e")
        username_entry = ttk.Entry(update_win, font=("Helvetica", 12), width=30)
        username_entry.insert(0, username)
        username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(update_win, text="Password:", font=("Helvetica", 12)).grid(row=1, column=0, padx=10, pady=10, sticky="e")
        password_entry = ttk.Entry(update_win, font=("Helvetica", 12), width=30)
        password_entry.insert(0, password)
        password_entry.config(show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=10)
        ttk.Button(update_win, text="Show", command=lambda: toggle_password_visibility(password_entry)).grid(row=1, column=2, padx=10, pady=10)
        
        ttk.Button(update_win, text="Save", command=lambda: save_updated_entry(account, username_entry.get(), password_entry.get(), update_win)).grid(row=2, column=1, pady=10)
    
    def save_updated_entry(account, username, password, window):
        data[account] = {"username": username, "password": password}
        save_data(data)
        messagebox.showinfo("Success", f"Entry for '{account}' updated.", parent=root)
        window.destroy()
    
    def generate_password_gui():
        try:
            length = simpledialog.askinteger("Generate Password", "Enter desired password length (default 12):", parent=root, initialvalue=12, minvalue=4)
        except Exception:
            length = 12
        generated = generate_secure_password(length or 12)
        gen_win = tk.Toplevel(root)
        gen_win.title("Generated Secure Password")
        ttk.Label(gen_win, text="Generated Password:", font=("Helvetica", 12)).pack(pady=5)
        pwd_entry = ttk.Entry(gen_win, font=("Helvetica", 12), width=30)
        pwd_entry.insert(0, generated)
        pwd_entry.config(state="readonly")
        pwd_entry.pack(pady=5)
        crack_time = estimate_crack_time(generated)
        ttk.Label(gen_win, text=f"Estimated crack time: {crack_time}").pack(pady=5)
        leak_status = check_password_leak(generated)
        ttk.Label(gen_win, text=f"Leak check: {leak_status}").pack(pady=5)
        analysis = analyze_password(generated)
        ttk.Label(gen_win, text="Password Analysis:", font=("Helvetica", 12, "bold")).pack(pady=5)
        ttk.Label(gen_win, text=f"Entropy: {analysis['entropy']:.2f} bits").pack(pady=2)
        ttk.Label(gen_win, text=f"Order of Magnitude: {analysis['order_of_magnitude']}").pack(pady=2)
        if analysis['warnings']:
            ttk.Label(gen_win, text="Warnings:", font=("Helvetica", 12, "bold")).pack(pady=5)
            for warning in analysis['warnings']:
                ttk.Label(gen_win, text=f"- {warning}").pack(pady=2)
        if analysis['suggestions']:
            ttk.Label(gen_win, text="Suggestions:", font=("Helvetica", 12, "bold")).pack(pady=5)
            for suggestion in analysis['suggestions']:
                ttk.Label(gen_win, text=f"- {suggestion}").pack(pady=2)
        copy_btn = ttk.Button(gen_win, text="Copy", command=lambda: copy_to_clipboard(generated))
        copy_btn.pack(pady=5)
        ttk.Button(gen_win, text="Close", command=gen_win.destroy).pack(pady=5)
    
    def check_password_leak_gui():
        password = simpledialog.askstring("Check Password Leak", "Enter password to check:", parent=root, show="*")
        if password:
            leak_status = check_password_leak(password)
            messagebox.showinfo("Leak Check", leak_status, parent=root)
    
    def analyze_password_gui():
        password = simpledialog.askstring("Analyze Password", "Enter password to analyze:", parent=root, show="*")
        if password:
            analysis = analyze_password(password)
            analysis_win = tk.Toplevel(root)
            analysis_win.title("Password Analysis")
            ttk.Label(analysis_win, text="Password Analysis:", font=("Helvetica", 12, "bold")).pack(pady=5)
            ttk.Label(analysis_win, text=f"Entropy: {analysis['entropy']:.2f} bits").pack(pady=2)
            ttk.Label(analysis_win, text=f"Order of Magnitude: {analysis['order_of_magnitude']}").pack(pady=2)
            if analysis['warnings']:
                ttk.Label(analysis_win, text="Warnings:", font=("Helvetica", 12, "bold")).pack(pady=5)
                for warning in analysis['warnings']:
                    ttk.Label(analysis_win, text=f"- {warning}").pack(pady=2)
            if analysis['suggestions']:
                ttk.Label(analysis_win, text="Suggestions:", font=("Helvetica", 12, "bold")).pack(pady=5)
                for suggestion in analysis['suggestions']:
                    ttk.Label(analysis_win, text=f"- {suggestion}").pack(pady=2)
            ttk.Button(analysis_win, text="Close", command=analysis_win.destroy).pack(pady=5)
    
    btn_frame = ttk.Frame(main_frame)
    btn_frame.pack(pady=20, fill="x")
    
    btn_add = ttk.Button(btn_frame, text="Add Entry", command=add_entry)
    btn_delete = ttk.Button(btn_frame, text="Delete Entry", command=delete_entry)
    btn_list = ttk.Button(btn_frame, text="List All Accounts", command=list_entries)
    btn_generate = ttk.Button(btn_frame, text="Generate Password", command=generate_password_gui)
    btn_leak_check = ttk.Button(btn_frame, text="Check Password Leak", command=check_password_leak_gui)
    btn_analyze = ttk.Button(btn_frame, text="Analyze Password", command=analyze_password_gui)
    btn_quit = ttk.Button(btn_frame, text="Quit", command=root.quit)
    
    btn_add.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
    btn_delete.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
    btn_list.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
    btn_generate.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
    btn_leak_check.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
    btn_analyze.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
    btn_quit.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
    
    btn_frame.columnconfigure(0, weight=1)
    btn_frame.columnconfigure(1, weight=1)
    
    root.mainloop()

def main():
    # Show the warning message before starting the program
    show_warning()

    if len(sys.argv) > 1 and sys.argv[1].lower() == "cli":
        cli_mode()
    else:
        print("Launching GUI mode. (Pass 'cli' as an argument for CLI mode.)")
        gui_mode()

if __name__ == "__main__":
    main()
