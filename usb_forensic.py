import os
import time
import win32file
import win32con
import threading
import hashlib
import tkinter as tk
from tkinter import scrolledtext

def load_virus_hashes():
    """Load virus hashes and associated info from files."""
    virus_hash_file = "C:\\Users\\javal\\Videos\PYTHON\\cloud automation\\virusHash.unibit"
    virus_info_file = "C:\\Users\\javal\\Videos\PYTHON\\cloud automation\\virusInfo.unibit"
    
    with open(virus_hash_file, "r") as vh, open(virus_info_file, "r") as vi:
        virus_hashes = [line.strip() for line in vh.readlines()]
        virus_info = [line.strip() for line in vi.readlines()]
    
    return dict(zip(virus_hashes, virus_info))

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a given file."""
    try:
        with open(file_path, "rb") as f:
            sha256_hash = hashlib.sha256()
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def get_usb_drives():
    """Detects available USB drives."""
    drives = []
    bitmask = win32file.GetLogicalDrives()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if bitmask & 1:
            drive_path = f"{letter}:\\"
            try:
                drive_type = win32file.GetDriveType(drive_path)
                if drive_type == win32con.DRIVE_REMOVABLE:
                    drives.append(drive_path)
            except Exception:
                pass
        bitmask >>= 1
    return drives

def monitor_usb(log_widget, stop_event, virus_data):
    log_widget.insert(tk.END, "Waiting for USB drives...\n")
    while not stop_event.is_set():
        usb_drives = get_usb_drives()
        if usb_drives:
            for drive in usb_drives:
                log_widget.insert(tk.END, f"Monitoring {drive}\n")
                log_widget.yview(tk.END)
                for root, _, files in os.walk(drive):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_hash = calculate_sha256(file_path)
                        if file_hash:
                            log_widget.insert(tk.END, f"[FILE] {file_path} | SHA-256: {file_hash}\n")
                            if file_hash in virus_data:
                                log_widget.insert(tk.END, f"[ALERT] {file_path} - {virus_data[file_hash]}\n", "alert")
                        else:
                            log_widget.insert(tk.END, f"[ACCESS] {file_path}\n")
                        log_widget.yview(tk.END)
        else:
            log_widget.insert(tk.END, "No USB drives detected.\n")
            log_widget.yview(tk.END)
        time.sleep(2)  # Check every 2 seconds

def start_monitoring(log_widget, stop_event, virus_data):
    stop_event.clear()
    threading.Thread(target=monitor_usb, args=(log_widget, stop_event, virus_data), daemon=True).start()

def stop_monitoring(stop_event):
    stop_event.set()

def create_gui():
    root = tk.Tk()
    root.title("USB Monitor with Malware Detection")
    root.geometry("600x400")
    
    log_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, width=70)
    log_widget.pack(pady=10)
    log_widget.tag_config("alert", foreground="red")
    
    stop_event = threading.Event()
    virus_data = load_virus_hashes()
    
    start_button = tk.Button(root, text="Start Monitoring", command=lambda: start_monitoring(log_widget, stop_event, virus_data))
    start_button.pack(side=tk.LEFT, padx=10, pady=10)
    
    stop_button = tk.Button(root, text="Stop Monitoring", command=lambda: stop_monitoring(stop_event))
    stop_button.pack(side=tk.RIGHT, padx=10, pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
