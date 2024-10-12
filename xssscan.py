import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import requests
import threading
import datetime
import time


# Function to load XSS payloads from a file in batches
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


# XSS payloads with bypass techniques
def xss_bypass_payloads(payload):
    return [
        payload,
        payload.replace("<", "&lt;").replace(">", "&gt;"),  # HTML encoding
        payload.replace('"', '&quot;').replace("'", '&#x27;'),  # Quote encoding
        f'%3C{payload}%3E',  # URL encoding
        f'<img src="x" onerror="{payload}">',  # Image tag injection
    ]


# Save the results to a file
def save_results():
    results = results_text.get(1.0, tk.END)
    if results.strip():
        filename = f"xss_scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as file:
            file.write(results)
        messagebox.showinfo("Saved", f"Results saved to '{filename}'")
    else:
        messagebox.showerror("Error", "No results to save.")


# Function to scan for XSS vulnerabilities
def scan_xss():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL")
        return

    # Reset the progress bar and text area
    progress_bar["value"] = 0
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, f"Scanning {url} for XSS vulnerabilities...\n\n")

    # Disable buttons during the scan
    scan_button.config(state="disabled")
    clear_button.config(state="disabled")
    stop_button.config(state="normal")
    pause_button.config(state="normal")
    reset_button.config(state="disabled")
    save_button.config(state="disabled")
    loading_label.config(text="Loading...")

    stop_event.clear()
    is_paused.clear()

    def run_scan():
        batch_size = 100  # Process 100 payloads per batch
        total_payloads = 0
        vulnerabilities_found = False

        for batch in load_payloads('xss.txt', batch_size=batch_size):
            if stop_event.is_set():
                results_text.insert(tk.END, "\nScan stopped.\n")
                break

            # Wait if the scan is paused
            while is_paused.is_set():
                time.sleep(0.1)  # Pause until resumed

            for i, payload in enumerate(batch):
                if stop_event.is_set():
                    results_text.insert(tk.END, "\nScan stopped.\n")
                    break

                # Try XSS filter bypass techniques
                for bypassed_payload in xss_bypass_payloads(payload):
                    try:
                        full_url = f"{url}?q={bypassed_payload}"
                        response = requests.get(full_url)
                        if bypassed_payload in response.text:
                            results_text.insert(tk.END, f"[Vulnerable] Payload: {bypassed_payload}\n")
                            vulnerabilities_found = True
                            results_text.see(tk.END)  # Scroll to the latest result
                        else:
                            continue  # Skip non-vulnerable results
                    except requests.RequestException as e:
                        results_text.insert(tk.END, f"Error scanning with payload {bypassed_payload}: {str(e)}\n")
                        results_text.see(tk.END)  # Scroll to the latest result

                total_payloads += 1

                # Update the progress bar
                progress_bar["value"] += 1
                progress_label.config(text=f"Scan Progress: {total_payloads} payloads tested")

            # Sleep to keep the GUI responsive between batches
            time.sleep(0.1)

        if not vulnerabilities_found:
            results_text.insert(tk.END, "No vulnerabilities found.\n")
        else:
            results_text.insert(tk.END, "\nScan completed. Vulnerabilities found.")
        
        # Enable buttons after scan
        scan_button.config(state="normal")
        clear_button.config(state="normal")
        stop_button.config(state="disabled")
        pause_button.config(state="disabled")
        reset_button.config(state="normal")
        save_button.config(state="normal")
        loading_label.config(text="")

    # Start scanning in a separate thread
    threading.Thread(target=run_scan).start()


# Function to pause or resume the scan
def pause_resume_scan():
    if pause_button['text'] == 'Pause Scan':
        is_paused.set()  # Pause the scan
        pause_button.config(text="Resume Scan")
    else:
        is_paused.clear()  # Resume the scan
        pause_button.config(text="Pause Scan")


# Function to clear the results
def clear_results():
    results_text.delete(1.0, tk.END)


# Function to stop the scan
def stop_scan():
    stop_event.set()
    stop_button.config(state="disabled")


# Function to reset the GUI
def reset_gui():
    url_entry.delete(0, tk.END)
    clear_results()
    progress_bar["value"] = 0
    progress_label.config(text="Scan Progress: 0 payloads tested")
    stop_event.clear()
    scan_button.config(state="normal")
    clear_button.config(state="normal")
    stop_button.config(state="disabled")
    pause_button.config(state="disabled", text="Pause Scan")
    reset_button.config(state="disabled")
    save_button.config(state="disabled")
    loading_label.config(text="")


# Dark mode switch
def toggle_theme():
    if style.theme_use() == "default":
        style.theme_use("clam")
        root.config(bg="black")
        url_label.config(bg="black", fg="white")
        loading_label.config(bg="black", fg="white")
        progress_label.config(bg="black", fg="white")
        theme_button.config(text="Switch to Light Mode")
    else:
        style.theme_use("default")
        root.config(bg="white")
        url_label.config(bg="white", fg="black")
        loading_label.config(bg="white", fg="black")
        progress_label.config(bg="white", fg="black")
        theme_button.config(text="Switch to Dark Mode")


# Load XSS payloads
payload_file_path = 'xss.txt'

# Events for stopping and pausing the scan
stop_event = threading.Event()
is_paused = threading.Event()

# Create the main window
root = tk.Tk()
root.title("XSS Scanner")
root.geometry("700x600")

style = ttk.Style()
style.theme_use("default")  # Start with light mode

# URL Label and Entry
url_label = tk.Label(root, text="Enter URL to scan:")
url_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
url_entry = tk.Entry(root, width=70)
url_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

# Buttons: Scan, Stop, Clear, Save, Reset, Pause, Theme
scan_button = tk.Button(root, text="Scan for XSS", command=scan_xss)
scan_button.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

stop_button = tk.Button(root, text="Stop Scan", command=stop_scan, state="disabled")
stop_button.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

pause_button = tk.Button(root, text="Pause Scan", command=pause_resume_scan, state="disabled")
pause_button.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

clear_button = tk.Button(root, text="Clear Results", command=clear_results)
clear_button.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

save_button = tk.Button(root, text="Save Results", command=save_results, state="disabled")
save_button.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

reset_button = tk.Button(root, text="Reset", command=reset_gui, state="disabled")
reset_button.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

theme_button = tk.Button(root, text="Switch to Dark Mode", command=toggle_theme)
theme_button.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

# Loading Label
loading_label = tk.Label(root, text="", fg="blue")
loading_label.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="w")

# Progress Bar and Label
progress_bar = ttk.Progressbar(root, length=500, mode='determinate')
progress_bar.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
progress_label = tk.Label(root, text="Scan Progress: 0 payloads tested")
progress_label.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky="w")

# Text area for results
results_text = tk.Text(root, wrap="word", height=20, width=80)
results_text.grid(row=8, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

root.mainloop()
