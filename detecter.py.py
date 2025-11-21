import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import os
import ctypes

class RogueHunterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Rogue Process Hunter & Killer v2.0")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")

        # --- Admin Check ---
        self.is_admin = self.check_admin()
        
        # --- Database of Legit Processes ---
        # Format: "process_name": ["list", "of", "valid", "paths"]
        # Note: We store everything in lowercase for comparison
        self.SYSTEM_WHITELIST = {
            "svchost.exe":  [r"c:\windows\system32\svchost.exe", r"c:\windows\syswow64\svchost.exe"],
            "lsass.exe":    [r"c:\windows\system32\lsass.exe"],
            "winlogon.exe": [r"c:\windows\system32\winlogon.exe"],
            "csrss.exe":    [r"c:\windows\system32\csrss.exe"],
            "services.exe": [r"c:\windows\system32\services.exe"],
            "explorer.exe": [r"c:\windows\explorer.exe"], # Note: Explorer is usually in Windows root
            "taskmgr.exe":  [r"c:\windows\system32\taskmgr.exe"],
            "spoolsv.exe":  [r"c:\windows\system32\spoolsv.exe"]
        }

        self.create_widgets()
        
        if not self.is_admin:
            self.status_var.set("WARNING: Not running as Admin. Process termination may fail.")
            self.status_label.config(fg="red")
        else:
            self.status_var.set("System Guard Ready. Database loaded.")

    def check_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def create_widgets(self):
        # 1. Header
        header_frame = tk.Frame(self.root, bg="#222", pady=15)
        header_frame.pack(fill="x")
        
        title_label = tk.Label(header_frame, text="🛡️ SYSTEM INTEGRITY GUARD", 
                               font=("Segoe UI", 18, "bold"), bg="#222", fg="#00ff00")
        title_label.pack()
        
        subtitle_label = tk.Label(header_frame, text="Detects Fake System Processes (Masquerading)", 
                                  font=("Segoe UI", 10), bg="#222", fg="#ccc")
        subtitle_label.pack()

        # 2. Treeview
        list_frame = tk.Frame(self.root, padx=10, pady=10, bg="#f0f0f0")
        list_frame.pack(fill="both", expand=True)

        tree_scroll = tk.Scrollbar(list_frame)
        tree_scroll.pack(side="right", fill="y")

        cols = ("PID", "Name", "Status", "Path")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings", 
                                 yscrollcommand=tree_scroll.set, height=15)
        
        self.tree.heading("PID", text="PID")
        self.tree.column("PID", width=60, anchor="center")
        self.tree.heading("Name", text="Process Name")
        self.tree.column("Name", width=120, anchor="w")
        self.tree.heading("Status", text="Analysis")
        self.tree.column("Status", width=100, anchor="center")
        self.tree.heading("Path", text="Actual Path")
        self.tree.column("Path", width=400, anchor="w")
        
        self.tree.pack(fill="both", expand=True)
        tree_scroll.config(command=self.tree.yview)

        self.tree.tag_configure("rogue", background="#ffcccc", foreground="red")
        self.tree.tag_configure("clean", background="white", foreground="gray")

        # 3. Buttons
        btn_frame = tk.Frame(self.root, pady=15, bg="#f0f0f0")
        btn_frame.pack(fill="x")

        scan_btn = tk.Button(btn_frame, text="🔍 Deep Scan", command=self.scan_system,
                             font=("Segoe UI", 11, "bold"), bg="#0078D7", fg="white", width=15)
        scan_btn.pack(side="left", padx=20)

        kill_btn = tk.Button(btn_frame, text="💀 Neutralize Threat", command=self.kill_selected,
                             font=("Segoe UI", 11, "bold"), bg="#D70000", fg="white", width=18)
        kill_btn.pack(side="right", padx=20)

        # 4. Status
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(self.root, textvariable=self.status_var, 
                                     bd=1, relief="sunken", anchor="w", bg="#e1e1e1")
        self.status_label.pack(side="bottom", fill="x")

    def scan_system(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.status_var.set("Scanning active processes...")
        self.root.update()

        rogue_count = 0
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    p_info = proc.info
                    
                    # Handle None types for zombies/access denied
                    if not p_info['name'] or not p_info['exe']:
                        continue

                    p_name = p_info['name'].lower()
                    p_path = p_info['exe'].lower()
                    p_pid = p_info['pid']

                    # --- LOGIC CORE ---
                    # Check if the process name is in our "Watchlist"
                    if p_name in self.SYSTEM_WHITELIST:
                        
                        # Check if the path is in the allowed list for that specific name
                        allowed_paths = self.SYSTEM_WHITELIST[p_name]
                        
                        is_legit = False
                        for valid_path in allowed_paths:
                            if p_path == valid_path: # Exact match
                                is_legit = True
                                break
                        
                        if not is_legit:
                            # IT IS A MIMIC!
                            self.tree.insert("", "end", values=(p_pid, p_info['name'], "MALICIOUS", p_path), tags=("rogue",))
                            rogue_count += 1
                        else:
                            # Optional: Uncomment to see legit system files
                            # self.tree.insert("", "end", values=(p_pid, p_info['name'], "Verified", p_path), tags=("clean",))
                            pass

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            if rogue_count == 0:
                self.status_var.set("Scan Complete: System Secure.")
                messagebox.showinfo("Clean", "No masquerading processes detected.")
            else:
                self.status_var.set(f"ALERT: {rogue_count} masquerading processes detected!")
                messagebox.showwarning("Threat Detected", f"Found {rogue_count} processes mimicking system files.\nCheck the list immediately.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def kill_selected(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Select a threat to terminate.")
            return

        confirm = messagebox.askyesno("Confirm", "Terminate selected process?")
        if not confirm:
            return

        for item in selected_item:
            values = self.tree.item(item, 'values')
            pid = int(values[0])
            try:
                p = psutil.Process(pid)
                p.kill()
                p.wait(3)
                self.tree.delete(item)
                self.status_var.set(f"Threat neutralized (PID: {pid})")
                messagebox.showinfo("Success", f"Process {pid} terminated.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = RogueHunterApp(root)
    root.mainloop()
