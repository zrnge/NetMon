import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import time
from datetime import datetime, timedelta
import socket 
import os
import sys
import json 
import re 

# --- Configuration ---
UPDATE_INTERVAL = 2000 # Update frequency in milliseconds
MAX_COL_WIDTH = 150
BASELINE_FILE = "network_baseline.json" # Default file name for the baseline

# --- Theme Configuration ---
THEMES = {
    "Light": {
        "bg": "#F0F0F0", "fg": "#1E1E1E", "tree_bg": "white", 
        "tree_fg": "#1E1E1E", "tree_heading_bg": "#D0D0D0", "tree_heading_fg": "#1E1E1E",
        "control_bg": "#EAEAEA", "button_bg": "#C0C0C0"
    },
    "Dark": {
        "bg": "#1E1E1E", "fg": "#FFFFFF", "tree_bg": "#2D2D30", 
        "tree_fg": "#FFFFFF", "tree_heading_bg": "#4A4A4D", "tree_heading_fg": "#FFFFFF",
        "control_bg": "#252526", "button_bg": "#505050"
    }
}

# Define all possible TCP connection status strings reported by psutil
CONNECTION_STATUSES = [
    'ALL',
    'ESTABLISHED',
    'LISTEN',
    'TIME_WAIT',
    'CLOSE_WAIT',
    'SYN_SENT',
    'SYN_RECV',
    'FIN_WAIT1',
    'FIN_WAIT2',
    'CLOSING',
    'LAST_ACK',
    'NONE' # For UDP/UNIX sockets
]

class NetMonApp: # Renamed class
    """
    A GUI application that monitors and displays live network connections
    using psutil and Tkinter.
    """
    def __init__(self, master):
        self.master = master
        
        # --- Internal State Tracking ---
        # Stores: {tracker_key: (established_datetime_object, pid, process_name)}
        # tracker_key format: (src_ip, src_port, dst_ip, dst_port, protocol)
        self.connection_tracker = {} 
        self.log_file_path = "network_log.txt"
        self.baseline_connections = set() # Stores set of tracker_keys from the baseline
        self.comparison_mode = False # Flag to indicate if comparison is active
        self.menubar = None # Initialize menubar attribute here
        
        # --- Variables for Controls ---
        default_theme_name = self._get_system_default_theme()
        self.current_theme_name = tk.StringVar(value=default_theme_name)
        self.connection_filter = tk.StringVar(value='ALL') 
        self.search_query = tk.StringVar(value='') # New variable for search query

        # --- UI Setup ---
        self.setup_menubar() 
        self._apply_theme(default_theme_name)
        self.setup_ui()
        self.setup_context_menu()
        
        master.title("NetMon v1.1") # Updated application title
        
        # Start the periodic data fetching
        self.fetch_and_update()

    def _get_system_default_theme(self):
        """
        Attempts to guess the system's preferred theme (Dark or Light).
        """
        if sys.platform == "win32":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                # 0 is dark, 1 is light. If 0, use Dark theme.
                if winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0:
                    return "Dark"
            except Exception:
                pass
        
        return "Light" # Default fallback

    def _apply_theme(self, theme_name):
        """Applies colors from the selected theme to the GUI."""
        theme = THEMES[theme_name]
        
        self.master.config(bg=theme["bg"])
        
        # Update style configurations (Treeview)
        style = ttk.Style(self.master)
        style.theme_use("clam")
        
        style.configure("Treeview.Heading", 
                         font=('Inter', 10, 'bold'), 
                         background=theme["tree_heading_bg"], 
                         foreground=theme["tree_heading_fg"])
        style.configure("Treeview", 
                         font=('Inter', 10), 
                         rowheight=25, 
                         background=theme["tree_bg"], 
                         foreground=theme["tree_fg"],
                         fieldbackground=theme["tree_bg"])
                         
        style.configure("New.Treeview", background="#FFA07A" if theme_name == "Light" else "#8B0000", foreground="#1E1E1E" if theme_name == "Light" else "#FFFFFF")

        # Special styling for theme-sensitive widgets
        style.configure("TFrame", background=theme["control_bg"])
        style.configure("TLabel", background=theme["control_bg"], foreground=theme["fg"])
        style.configure("TButton", background=theme["button_bg"], foreground=theme["fg"])
        style.configure("TMenubutton", background=theme["button_bg"], foreground=theme["fg"])
        style.map("TButton", background=[('active', theme["button_bg"])])

        self.master.option_add('*tearoff', tk.FALSE)
        self.master.config(menu=self.menubar, bg=theme["bg"])
        
    def _change_theme(self, *args):
        """Callback for theme change event."""
        self._apply_theme(self.current_theme_name.get())
        self.fetch_and_update() 
        
    def _change_filter(self, *args):
        """Callback for connection filter change event. Triggers data refresh."""
        self.fetch_and_update() 
        
    def _search_changed(self, *args):
        """Callback for search query change event (e.g., Enter key or lost focus)."""
        self.fetch_and_update()

    def show_documentation(self):
        """Displays help documentation in a message box."""
        docs = (
            "--- NetMon Documentation ---\n\n" # Updated Documentation title
            "**1. Connection State Filter**\n"
            "   - Use the 'State Filter' dropdown to view only connections in a specific state (e.g., ESTABLISHED, LISTEN, TIME_WAIT).\n"
            "   - Select **ALL** to view every connection status reported by the system.\n\n"
            "**2. Search Query Filter**\n"
            "   - Enter key-value pairs separated by commas.\n"
            "   - Format: **key:value,key:value**\n"
            "   - Keys supported (case-insensitive): **pid**, **process_name**, **src_ip**, **src_port**, **dst_ip**, **dst_port**, **protocol**.\n"
            "   - Example: `pid:1234,process_name:chrome,dst_ip:8.8.8.8`\n"
            "   - Filtering is case-insensitive and supports partial matches (e.g., 'chrome' matches 'chrome.exe').\n\n"
            "**3. Baseline Feature (File Menu)**\n"
            "   - **Save a Baseline:** Records all current ESTABLISHED connections.\n"
            "   - **Compare to a Baseline:** Highlights any active ESTABLISHED connection that was NOT present in the saved baseline (new connections appear highlighted).\n\n"
            "**4. Right-Click Copy**\n"
            "   - Right-click any row to copy the selected cell value, the entire row, or a whole column."
        )
        messagebox.showinfo("Help Documentation", docs)

    def show_about(self):
        """Displays application information in a message box."""
        about_text = (
            "--- NetMon v1.1 ---\n\n" # Updated About title
            "This is an open-source project, NetMon, designed to provide a graphical, real-time view of all "
            "network connection establishments (IPv4/IPv6, TCP/UDP) on your local machine.\n\n" # Updated description
            "Features include: Theme switching, state filtering, dynamic search, and baseline comparison.\n\n"
            "**Created by:** zrng\n"
            "**GitHub:** github.com/zrnge\n"
            "**License:** Open source for general use and modification."
        )
        messagebox.showinfo("About NetMon", about_text) # Updated messagebox title

    def setup_menubar(self):
        """Sets up the top-level menu bar with File and Help features."""
        self.menubar = tk.Menu(self.master)
        
        # File Menu
        file_menu = tk.Menu(self.menubar, tearoff=0)
        file_menu.add_command(label="Save Baseline", command=self.save_baseline)
        file_menu.add_command(label="Compare to Baseline", command=self.compare_baseline)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        self.menubar.add_cascade(label="File", menu=file_menu)

        # Help Menu (New)
        help_menu = tk.Menu(self.menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        self.menubar.add_cascade(label="Help", menu=help_menu)
        
        self.master.config(menu=self.menubar)

    def setup_ui(self):
        """Sets up the Tkinter Treeview, controls, and main layout."""
        
        # Main container setup
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure(0, weight=0) # Controls row
        self.master.grid_rowconfigure(1, weight=0) # Search row
        self.master.grid_rowconfigure(2, weight=1) # Treeview row

        # --- Controls Frame (Row 0: Theme, Filter, Status, Log) ---
        controls_frame = ttk.Frame(self.master, style="TFrame")
        controls_frame.grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 5))
        controls_frame.columnconfigure(3, weight=1) # Push spacing to the right
        
        # Theme Selector (Col 0, 1)
        ttk.Label(controls_frame, text="Theme:", style="TLabel").grid(row=0, column=0, padx=(0, 5), pady=5, sticky='w')
        theme_options = list(THEMES.keys())
        ttk.OptionMenu(controls_frame, self.current_theme_name, self.current_theme_name.get(), 
                       *theme_options, command=self._change_theme).grid(row=0, column=1, padx=(0, 20), pady=5, sticky='w')
        
        # Connection State Filter (Col 2, 3)
        ttk.Label(controls_frame, text="State Filter:", style="TLabel").grid(row=0, column=2, padx=(5, 5), pady=5, sticky='w')
        ttk.OptionMenu(controls_frame, self.connection_filter, self.connection_filter.get(), 
                       *CONNECTION_STATUSES, command=self._change_filter).grid(row=0, column=3, padx=(0, 20), pady=5, sticky='w')
        
        # Comparison Status Label (Col 4)
        self.status_label = ttk.Label(controls_frame, text="Monitoring Live Connections", style="TLabel")
        self.status_label.grid(row=0, column=4, padx=(5, 10), pady=5, sticky='e')
        
        # Log Button (Col 5)
        log_button = ttk.Button(controls_frame, text="Save Connection Snapshot", command=self.save_log, style="TButton")
        log_button.grid(row=0, column=5, padx=(5, 0), pady=5, sticky='e')
        
        # --- Search Frame (Row 1: Query Search) ---
        search_frame = ttk.Frame(self.master, style="TFrame")
        search_frame.grid(row=1, column=0, sticky='ew', padx=10, pady=(0, 5))
        search_frame.columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text="Search Query (e.g., pid:1234,process_name:chrome):", style="TLabel").grid(row=0, column=0, padx=(0, 5), pady=5, sticky='w')
        
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_query, width=80)
        self.search_entry.grid(row=0, column=1, padx=(0, 5), pady=5, sticky='ew')
        self.search_entry.bind('<Return>', self._search_changed)
        self.search_entry.bind('<FocusOut>', self._search_changed)


        # --- Treeview Setup (Row 2) ---
        
        columns = ("status", "src_ip", "src_port", "dst_ip", "dst_port", 
                   "protocol", "pid", "process_name", "timestamp", "duration")
        
        self.tree = ttk.Treeview(self.master, columns=columns, show="headings")
        self.tree.grid(row=2, column=0, sticky='nsew', padx=10, pady=(0, 10))

        # Define column headings and widths
        self.column_keys = columns 
        self.headings = {
            "status": "Status", "src_ip": "Source IP", "src_port": "Src Port", 
            "dst_ip": "Destination IP", "dst_port": "Dst Port", "protocol": "Proto", 
            "pid": "PID", "process_name": "Process/Service", 
            "timestamp": "Established Time", "duration": "Duration"
        }
        
        col_widths = {
            "status": 90, "src_ip": MAX_COL_WIDTH, "src_port": 60, "dst_ip": MAX_COL_WIDTH, 
            "dst_port": 60, "protocol": 60, "pid": 60, "process_name": 120, 
            "timestamp": 120, "duration": 80
        }

        for col, title in self.headings.items():
            width = col_widths.get(col, 100)
            self.tree.heading(col, text=title, anchor='w')
            self.tree.column(col, anchor='w', width=width, stretch=tk.NO)
        
        self.tree.tag_configure('new_conn', background='#FFA07A')

        # Add scrollbars (adjust row index to 2)
        vsb = ttk.Scrollbar(self.master, orient="vertical", command=self.tree.yview)
        vsb.grid(row=2, column=1, sticky='ns')
        self.tree.configure(yscrollcommand=vsb.set)
        
        hsb = ttk.Scrollbar(self.master, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=3, column=0, sticky='ew', padx=10)
        self.tree.configure(xscrollcommand=hsb.set)

    def setup_context_menu(self):
        """Sets up the right-click context menu and binds it to the Treeview."""
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.tree.bind("<Button-3>", self._show_context_menu)

    # --- Search Query Parsing ---

    def _parse_query(self, query_str):
        """Parses a query string (e.g., 'pid:1234,process_name:chrome') into a dictionary."""
        query = {}
        if not query_str:
            return query
            
        try:
            # Split by comma, then split each part by colon
            parts = query_str.split(',')
            for part in parts:
                if ':' in part:
                    key, value = part.split(':', 1)
                    # Use the lowercase column key, removing spaces
                    key = key.strip().lower().replace('.', '_')
                    # Value should be kept as a string, often lowercased for case-insensitive matching
                    query[key] = value.strip()
        except Exception as e:
            # This is non-critical, but useful for debugging user input issues
            print(f"Error parsing query: {e}")
            messagebox.showwarning("Query Error", f"Failed to parse search query. Please check format.")
            return {}
            
        return query

    # --- Query Matching Logic ---
    
    def _matches_query(self, data, query):
        """Checks if a connection data dictionary matches the parsed query criteria."""
        if not query:
            return True # No query means match all
            
        # Mapping from query key to the data key
        query_map = {
            'pid': 'pid', 
            'process_name': 'process_name', 
            'src_ip': 'src_ip', 
            'src_port': 'src_port',
            'dst_ip': 'dst_ip', 
            'dst_port': 'dst_port',
            'protocol': 'protocol'
        }
        
        for query_key, query_value in query.items():
            data_key = query_map.get(query_key)
            
            if data_key in data:
                # Convert both values to string for generic comparison (PID/Port must be strings)
                data_value = str(data[data_key]).lower()
                
                # Check for substring match (allowing partial search like 'chrome' for 'chrome.exe')
                if query_value.lower() not in data_value:
                    return False
            # If the query key is invalid or not in data, we ignore it rather than failing the filter
            
        return True

    # --- Copy Functions ---
    def _copy_to_clipboard(self, text):
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
            self.master.update()
        except Exception as e:
            messagebox.showerror("Clipboard Error", f"Failed to copy to clipboard: {e}")

    def copy_selected_value(self, column_id):
        selected_items = self.tree.selection()
        if not selected_items:
            return

        item_id = selected_items[0]
        try:
            value = self.tree.item(item_id, 'values')[column_id]
            self._copy_to_clipboard(str(value))
        except IndexError:
            pass 

    def copy_selected_row(self):
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        item_id = selected_items[0]
        values = self.tree.item(item_id, 'values')
        row_text = '\t'.join(map(str, values))
        self._copy_to_clipboard(row_text)

    def copy_column_data(self, column_key):
        header_text = self.headings.get(column_key, column_key)
        column_data = [header_text]
        
        try:
            col_index = self.column_keys.index(column_key)
        except ValueError:
            messagebox.showerror("Copy Error", f"Column key '{column_key}' not found.")
            return

        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, 'values')
            if len(values) > col_index:
                column_data.append(str(values[col_index]))

        column_text = '\n'.join(column_data)
        self._copy_to_clipboard(column_text)

    def _show_context_menu(self, event):
        self.context_menu.delete(0, 'end') 
        region = self.tree.identify_region(event.x, event.y)
        
        if region == 'heading':
            column_id = self.tree.identify_column(event.x)
            column_key = self.column_keys[int(column_id.replace('#', '')) - 1]
            column_name = self.headings.get(column_key, column_key)
            
            self.context_menu.add_command(
                label=f"Copy Column: {column_name}", 
                command=lambda k=column_key: self.copy_column_data(k)
            )
        
        elif region == 'cell' or region == 'row':
            item_id = self.tree.identify_row(event.y)
            if item_id:
                self.tree.selection_set(item_id) 
            
            column_id_str = self.tree.identify_column(event.x)
            column_index = int(column_id_str.replace('#', '')) - 1 
            
            if item_id:
                column_key = self.column_keys[column_index]
                column_name = self.headings.get(column_key, column_key)
                
                self.context_menu.add_command(
                    label=f"Copy Value: {column_name}", 
                    command=lambda c=column_index: self.copy_selected_value(c)
                )
                self.context_menu.add_separator()
                
                self.context_menu.add_command(
                    label="Copy Selected Row (Tab-separated)", 
                    command=self.copy_selected_row
                )
                
                self.context_menu.add_command(
                    label=f"Copy Column: {column_name}", 
                    command=lambda k=column_key: self.copy_column_data(k)
                )

        if self.context_menu.index('end') is not None:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        
    # --- Baseline Logic ---
    
    def save_baseline(self):
        """Captures all current ESTABLISHED connection keys and saves them to a JSON file."""
        current_established_keys = []
        
        try:
            connections = psutil.net_connections('all')
        except TypeError:
            connections = psutil.net_connections() 

        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                l_ip, l_port = self._format_address(conn.laddr)
                r_ip, r_port = self._format_address(conn.raddr)
                
                if conn.family == socket.AF_INET:
                    protocol = "TCP/IPv4"
                elif conn.family == socket.AF_INET6:
                    protocol = "TCP/IPv6"
                else:
                    continue 
                
                tracker_key = (l_ip, l_port, r_ip, r_port, protocol)
                current_established_keys.append(tracker_key)
        
        try:
            savable_keys = [list(key) for key in current_established_keys]
            
            with open(BASELINE_FILE, 'w') as f:
                json.dump(savable_keys, f, indent=4)
                
            self.baseline_connections = set(current_established_keys) 
            self.comparison_mode = False 
            self.status_label.config(text=f"Baseline saved to {BASELINE_FILE}")
            
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save baseline file: {e}")


    def compare_baseline(self):
        """Loads a baseline and enables comparison mode."""
        try:
            with open(BASELINE_FILE, 'r') as f:
                loaded_keys = json.load(f)
                
            self.baseline_connections = set([tuple(key) for key in loaded_keys])
            self.comparison_mode = True
            
            self.status_label.config(text=f"Comparison Mode ON ({len(self.baseline_connections)} baseline entries)")
            self.fetch_and_update() 
            
        except FileNotFoundError:
            messagebox.showwarning("Baseline Missing", f"Baseline file '{BASELINE_FILE}' not found. Please save a baseline first.")
        except json.JSONDecodeError:
            messagebox.showerror("Load Error", f"Failed to read baseline. '{BASELINE_FILE}' is corrupted.")
        except Exception as e:
            messagebox.showerror("Load Error", f"An unexpected error occurred: {e}")


    # --- Utility Functions ---

    def _format_address(self, addr):
        """Formats the (ip, port) tuple into readable strings."""
        if not addr or len(addr) < 2:
            return "N/A", "N/A"
        
        ip = addr.ip if addr.ip else "127.0.0.1" if addr.port else "::1"
        return ip, addr.port

    def _get_process_info(self, pid):
        """Gets the process name for a given PID, handling errors."""
        if pid in (None, 0):
            return "System/N/A"
        try:
            p = psutil.Process(pid)
            return p.name()
        except psutil.NoSuchProcess:
            return f"PID {pid} (Gone)"
        except psutil.AccessDenied:
            return f"PID {pid} (Access Denied)"
        except Exception:
            return f"PID {pid} (Unknown Error)"

    def _format_timedelta(self, td):
        """Formats a timedelta object into a short string (e.g., 0d 05h 30m 15s)."""
        total_seconds = int(td.total_seconds())
        days = total_seconds // (3600 * 24)
        hours = (total_seconds % (3600 * 24)) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        if days > 0:
            return f"{days}d {hours:02}h {minutes:02}m"
        elif hours > 0:
            return f"{hours}h {minutes:02}m {seconds:02}s"
        else:
            return f"{minutes:02}m {seconds:02}s"

    def _log_connection_event(self, data):
        """
        Writes a single connection event to the log file, triggered only 
        when the connection status first becomes 'ESTABLISHED'.
        """
        log_entry = (
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"ESTABLISHED: {data['protocol']} "
            f"PID:{data['pid']} ({data['process_name']}) "
            f"SRC:{data['src_ip']}:{data['src_port']} "
            f"DST:{data['dst_ip']}:{data['dst_port']}\n"
        )
        try:
            with open(self.log_file_path, "a") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Error writing to log file: {e}")

    def save_log(self):
        """
        Saves the current contents of the connection tracker to a file 
        with a unique timestamp, and confirms with the user.
        """
        snapshot_filename = f"network_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(snapshot_filename, "w") as f:
                f.write(f"--- Network Connection Snapshot: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n\n")
                
                # Write header
                f.write(f"{'Status':<15}{'PID':<8}{'Process':<20}{'Source IP:Port':<35}{'Destination IP:Port':<35}{'Duration':<15}{'Timestamp':<15}\n")
                f.write("-" * 140 + "\n")

                for tracker_key, (established_time, pid_val, proc_val) in sorted(self.connection_tracker.items()):
                    # tracker_key format: (l_ip, l_port, r_ip, r_port, protocol)
                    l_ip, l_port, r_ip, r_port, protocol = tracker_key
                    
                    duration = datetime.now() - established_time
                    duration_str = self._format_timedelta(duration)
                    
                    log_line = (
                        f"{'ESTABLISHED':<15}{str(pid_val):<8}{proc_val:<20}"
                        f"{l_ip}:{l_port:<28}"
                        f"{r_ip}:{r_port:<28}"
                        f"{duration_str:<15}"
                        f"{established_time.strftime('%H:%M:%S'):<15}\n"
                    )
                    f.write(log_line)
                
            messagebox.showinfo("Log Saved", f"Connection snapshot saved to:\n{os.path.abspath(snapshot_filename)}")

        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save log file: {e}")

    def fetch_and_update(self):
        """Fetches connection data, updates the tracker, and refreshes the GUI table."""
        try:
            current_time = datetime.now()
            live_connections = {}
            
            # 1. Parse Search Query
            query_str = self.search_query.get()
            parsed_query = self._parse_query(query_str)
            
            # 2. Fetch all connections
            try:
                connections = psutil.net_connections('all')
            except TypeError:
                connections = psutil.net_connections() 
            
            for conn in connections:
                if not conn.laddr or not conn.raddr:
                    continue
                
                l_ip, l_port = self._format_address(conn.laddr)
                r_ip, r_port = self._format_address(conn.raddr)
                
                # Protocol identification logic
                if conn.family == socket.AF_INET:
                    protocol = "TCP/IPv4" if conn.type == socket.SOCK_STREAM else "UDP/IPv4"
                elif conn.family == socket.AF_INET6:
                    protocol = "TCP/IPv6" if conn.type == socket.SOCK_STREAM else "UDP/IPv6"
                else:
                    continue

                tracker_key = (l_ip, l_port, r_ip, r_port, protocol) 
                
                established_time_str = "N/A"
                duration_str = "N/A"
                
                pid_val = conn.pid if conn.pid else "N/A"
                process_name = self._get_process_info(conn.pid)
                
                # --- Connection Tracker Logic ---
                if conn.status == 'ESTABLISHED':
                    if tracker_key not in self.connection_tracker:
                        established_time = current_time
                        self.connection_tracker[tracker_key] = (established_time, pid_val, process_name)
                        data_for_log = {
                            "protocol": protocol, "pid": pid_val, 
                            "process_name": process_name,
                            "src_ip": l_ip, "src_port": l_port, 
                            "dst_ip": r_ip, "dst_port": r_port
                        }
                        self._log_connection_event(data_for_log)
                    else:
                        established_time, pid_val, process_name = self.connection_tracker[tracker_key]
                        
                    established_time_str = established_time.strftime("%H:%M:%S")
                    duration = current_time - established_time
                    duration_str = self._format_timedelta(duration)
                
                elif tracker_key in self.connection_tracker:
                    del self.connection_tracker[tracker_key]
                
                
                # Prepare data dictionary for display and filtering
                data = {
                    "status": conn.status,
                    "src_ip": l_ip, "src_port": str(l_port),
                    "dst_ip": r_ip, "dst_port": str(r_port),
                    "protocol": protocol,
                    "pid": str(pid_val),
                    "process_name": process_name,
                    "timestamp": established_time_str,
                    "duration": duration_str,
                    "is_new": self.comparison_mode and conn.status == 'ESTABLISHED' and tracker_key not in self.baseline_connections
                }

                # 3. Apply Filters
                
                # Filter 3a: Connection State Filter
                selected_filter = self.connection_filter.get()
                if selected_filter != 'ALL' and conn.status != selected_filter:
                    continue
                
                # Filter 3b: Search Query Filter
                if not self._matches_query(data, parsed_query):
                    continue

                # Store the connection if it passed all filters
                live_connections[tracker_key] = data

            # 4. Update Treeview UI
            self.tree.delete(*self.tree.get_children()) 
            
            for data in live_connections.values():
                values = (
                    data["status"], data["src_ip"], data["src_port"], 
                    data["dst_ip"], data["dst_port"], data["protocol"],
                    data["pid"], data["process_name"], 
                    data["timestamp"], data["duration"]
                )
                
                tags = ('new_conn',) if data['is_new'] else ()
                self.tree.insert('', 'end', values=values, tags=tags)
                    
            if self.comparison_mode and self.baseline_connections:
                self.status_label.config(text=f"Comparison: New connections are highlighted!")
            elif self.comparison_mode and not self.baseline_connections:
                 self.status_label.config(text="Comparison Mode: Baseline is empty.")
            elif not self.comparison_mode:
                self.status_label.config(text="Monitoring Live Connections")

        except Exception as e:
            # Prevent the continuous loop from crashing on repeated errors
            print(f"Error during data fetching loop: {e}")
            if "psutil" in str(e):
                self.status_label.config(text="CRITICAL ERROR: psutil access denied or failed.")
            else:
                self.status_label.config(text=f"ERROR: {e.__class__.__name__}")
        
        # Schedule the next update
        self.master.after(UPDATE_INTERVAL, self.fetch_and_update)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetMonApp(root)
    root.mainloop()

# Necessary external package: psutil
# To run this script, you must install psutil: pip install psutil
