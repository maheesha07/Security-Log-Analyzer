"""
Security Log Analyzer - Student Version

A simple Python desktop application that reads security log files and finds
basic suspicious activity such as failed logins and possible brute-force attacks.

Built with Tkinter, regular expressions and Matplotlib.
"""

import csv
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import matplotlib.pyplot as plt


# ----------------------------
# Basic settings
# ----------------------------
BRUTE_FORCE_LIMIT = 5
BRUTE_FORCE_MINUTES = 5

IP_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
LINUX_TIME_PATTERN = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
ISO_TIME_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
APACHE_TIME_PATTERN = re.compile(r"\[(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class SecurityLogAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Log Analyzer")
        self.root.geometry("1250x760")
        self.root.minsize(1000, 650)
        self.root.configure(bg="#111827")

        self.file_path = ""
        self.all_results = []
        self.filtered_results = []

        self.setup_style()
        self.create_gui()

    # ----------------------------
    # GUI
    # ----------------------------
    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background="#1f2937",
            foreground="white",
            fieldbackground="#1f2937",
            rowheight=28,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#374151",
            foreground="white",
            font=("Arial", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#2563eb")])

        style.configure(
            "TCombobox",
            fieldbackground="#1f2937",
            background="#1f2937",
            foreground="black",
        )

    def create_gui(self):
        # Header
        header = tk.Frame(self.root, bg="#0f172a", height=70)
        header.pack(fill="x")

        tk.Label(
            header,
            text="SECURITY LOG ANALYZER",
            font=("Arial", 22, "bold"),
            fg="#22d3ee",
            bg="#0f172a",
        ).pack(side="left", padx=25, pady=18)

        tk.Label(
            header,
            text="Student SOC Tool",
            font=("Arial", 10),
            fg="#94a3b8",
            bg="#0f172a",
        ).pack(side="left", pady=25)

        # Buttons
        button_frame = tk.Frame(self.root, bg="#111827")
        button_frame.pack(fill="x", padx=20, pady=(15, 5))

        self.make_button(button_frame, "Upload Log File", self.upload_file).pack(side="left", padx=5)
        self.make_button(button_frame, "Analyze Logs", self.analyze_logs).pack(side="left", padx=5)
        self.make_button(button_frame, "Clear", self.clear_data).pack(side="left", padx=5)
        self.make_button(button_frame, "Export CSV", self.export_csv).pack(side="left", padx=5)
        self.make_button(button_frame, "Show Charts", self.show_charts).pack(side="left", padx=5)

        self.file_label = tk.Label(
            button_frame,
            text="No file selected",
            fg="#94a3b8",
            bg="#111827",
            font=("Arial", 10),
        )
        self.file_label.pack(side="left", padx=15)

        # Statistics
        stats_frame = tk.Frame(self.root, bg="#111827")
        stats_frame.pack(fill="x", padx=20, pady=10)

        self.stat_labels = {}
        stats = [
            ("Total Logs", "total"),
            ("Failed Logins", "failed"),
            ("Successful Logins", "success"),
            ("Unique IPs", "unique_ips"),
            ("Suspicious IPs", "suspicious"),
            ("Alerts", "alerts"),
        ]

        for title, key in stats:
            card = tk.Frame(stats_frame, bg="#1f2937", padx=15, pady=10)
            card.pack(side="left", fill="x", expand=True, padx=5)

            tk.Label(
                card,
                text=title,
                fg="#94a3b8",
                bg="#1f2937",
                font=("Arial", 9),
            ).pack()

            value = tk.Label(
                card,
                text="0",
                fg="white",
                bg="#1f2937",
                font=("Arial", 18, "bold"),
            )
            value.pack()
            self.stat_labels[key] = value

        # Filters
        filter_frame = tk.Frame(self.root, bg="#111827")
        filter_frame.pack(fill="x", padx=20, pady=5)

        tk.Label(filter_frame, text="Search:", fg="white", bg="#111827").pack(side="left")
        self.search_entry = tk.Entry(
            filter_frame,
            bg="#1f2937",
            fg="white",
            insertbackground="white",
            relief="flat",
            width=30,
        )
        self.search_entry.pack(side="left", padx=(5, 15), ipady=5)
        self.search_entry.bind("<KeyRelease>", lambda event: self.apply_filters())

        tk.Label(filter_frame, text="Severity:", fg="white", bg="#111827").pack(side="left")
        self.severity_box = ttk.Combobox(
            filter_frame,
            values=["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            state="readonly",
            width=12,
        )
        self.severity_box.set("ALL")
        self.severity_box.pack(side="left", padx=5)
        self.severity_box.bind("<<ComboboxSelected>>", lambda event: self.apply_filters())

        tk.Label(filter_frame, text="Date (YYYY-MM-DD):", fg="white", bg="#111827").pack(side="left", padx=(15, 0))
        self.date_entry = tk.Entry(
            filter_frame,
            bg="#1f2937",
            fg="white",
            insertbackground="white",
            relief="flat",
            width=13,
        )
        self.date_entry.pack(side="left", padx=5, ipady=5)
        self.date_entry.bind("<KeyRelease>", lambda event: self.apply_filters())

        # Results table
        table_frame = tk.Frame(self.root, bg="#111827")
        table_frame.pack(fill="both", expand=True, padx=20, pady=(5, 20))

        columns = ("timestamp", "ip", "username", "event", "status", "severity", "description")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        headings = {
            "timestamp": "Timestamp",
            "ip": "IP Address",
            "username": "Username",
            "event": "Event",
            "status": "Status",
            "severity": "Severity",
            "description": "Description",
        }

        widths = {
            "timestamp": 145,
            "ip": 120,
            "username": 100,
            "event": 145,
            "status": 90,
            "severity": 90,
            "description": 360,
        }

        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w")

        scrollbar_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def make_button(self, parent, text, command):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
        )

    # ----------------------------
    # File handling
    # ----------------------------
    def upload_file(self):
        path = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")],
        )

        if path:
            self.file_path = path
            self.file_label.config(text=path.split("/")[-1])

    def read_log_file(self):
        if not self.file_path:
            raise ValueError("Please upload a log file first.")

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as file:
                lines = [line.strip() for line in file if line.strip()]
        except OSError as error:
            raise ValueError("The selected file could not be opened.") from error

        if not lines:
            raise ValueError("The selected log file is empty.")

        return lines

    # ----------------------------
    # Log parsing
    # ----------------------------
    def get_timestamp(self, line):
        """Try a few common timestamp formats."""
        match = ISO_TIME_PATTERN.search(line)
        if match:
            try:
                return datetime.strptime(
                    f"{match.group(1)} {match.group(2)}",
                    "%Y-%m-%d %H:%M:%S",
                )
            except ValueError:
                pass

        match = APACHE_TIME_PATTERN.search(line)
        if match:
            try:
                return datetime.strptime(
                    f"{match.group(1)} {match.group(2)} {match.group(3)} {match.group(4)}",
                    "%d %b %Y %H:%M:%S",
                )
            except ValueError:
                pass

        match = LINUX_TIME_PATTERN.search(line)
        if match:
            try:
                month = MONTHS.get(match.group(1))
                if month:
                    now = datetime.now()
                    hour, minute, second = map(int, match.group(3).split(":"))
                    return datetime(now.year, month, int(match.group(2)), hour, minute, second)
            except ValueError:
                pass

        return None

    def get_ip(self, line):
        match = IP_PATTERN.search(line)
        if match:
            return match.group(0)
        return "N/A"

    def get_username(self, line):
        patterns = [
            r"Failed password for (?:invalid user )?([\w.-]+)",
            r"Accepted \w+ for ([\w.-]+)",
            r"user[=: ]+([\w.-]+)",
            r"username[=: ]+([\w.-]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)

        return "N/A"

    def classify_event(self, line):
        """Classify each log line using simple keyword rules."""
        lower = line.lower()

        failed_words = [
            "failed password",
            "authentication failure",
            "login failed",
            "invalid user",
            "failed login",
        ]
        success_words = [
            "accepted password",
            "accepted publickey",
            "login success",
            "successful login",
        ]
        unauthorized_words = [
            "unauthorized",
            "access denied",
            "permission denied",
            "forbidden",
        ]

        if any(word in lower for word in failed_words):
            return "Failed Login", "FAILED", "MEDIUM", "Failed authentication attempt"

        if any(word in lower for word in success_words):
            return "Successful Login", "SUCCESS", "LOW", "User logged in successfully"

        if any(word in lower for word in unauthorized_words):
            return "Unauthorized Access", "DENIED", "HIGH", "Unauthorized access attempt detected"

        # Common suspicious web requests
        if any(word in lower for word in ["../", "wp-admin", "sqlmap", "union select"]):
            return "Suspicious Request", "SUSPICIOUS", "HIGH", "Suspicious web request detected"

        # Apache response codes
        http_match = re.search(r'"\s(\d{3})\s', line)
        if http_match:
            code = int(http_match.group(1))
            if code in (401, 403):
                return "Unauthorized Access", "DENIED", "HIGH", f"HTTP {code} access attempt"
            return "Web Request", "INFO", "LOW", f"HTTP request returned status {code}"

        return "General Event", "INFO", "LOW", "Normal log activity"

    # ----------------------------
    # Analysis
    # ----------------------------
    def analyze_logs(self):
        try:
            lines = self.read_log_file()
        except ValueError as error:
            messagebox.showerror("Error", str(error))
            return

        results = []

        for line in lines:
            timestamp = self.get_timestamp(line)
            ip = self.get_ip(line)
            username = self.get_username(line)
            event, status, severity, description = self.classify_event(line)

            # A useful log should contain at least an IP or a recognizable event.
            if ip == "N/A" and event == "General Event" and timestamp is None:
                continue

            results.append({
                "timestamp": timestamp,
                "ip": ip,
                "username": username,
                "event": event,
                "status": status,
                "severity": severity,
                "description": description,
                "raw": line,
            })

        if not results:
            messagebox.showerror(
                "Unsupported Log",
                "No recognizable security log entries were found.\n\n"
                "Try a Linux authentication log, Apache access log, or a simple timestamped security log.",
            )
            return

        self.detect_brute_force(results)
        self.detect_success_after_failures(results)

        self.all_results = results
        self.filtered_results = list(results)

        self.update_statistics()
        self.show_results(self.filtered_results)

        messagebox.showinfo("Analysis Complete", f"Analyzed {len(results)} log entries.")

    def detect_brute_force(self, results):
        """Mark 5 or more failed logins from one IP within 5 minutes as critical."""
        failed_by_ip = defaultdict(list)

        for index, item in enumerate(results):
            if item["event"] == "Failed Login" and item["ip"] != "N/A" and item["timestamp"]:
                failed_by_ip[item["ip"]].append((index, item["timestamp"]))

        time_window = timedelta(minutes=BRUTE_FORCE_MINUTES)

        for ip, attempts in failed_by_ip.items():
            attempts.sort(key=lambda value: value[1])

            for start in range(len(attempts)):
                indexes = []
                start_time = attempts[start][1]

                for index, attempt_time in attempts[start:]:
                    if attempt_time - start_time <= time_window:
                        indexes.append(index)
                    else:
                        break

                if len(indexes) >= BRUTE_FORCE_LIMIT:
                    for result_index in indexes:
                        results[result_index]["severity"] = "CRITICAL"
                        results[result_index]["description"] = (
                            f"Possible brute-force attack from {ip}: "
                            f"{len(indexes)} failed logins within {BRUTE_FORCE_MINUTES} minutes"
                        )
                    break

    def detect_success_after_failures(self, results):
        """Raise the severity when a successful login happens after 3+ failures."""
        failures = defaultdict(list)

        ordered = sorted(
            [item for item in results if item["timestamp"]],
            key=lambda item: item["timestamp"],
        )

        for item in ordered:
            ip = item["ip"]
            if ip == "N/A":
                continue

            if item["event"] == "Failed Login":
                failures[ip].append(item["timestamp"])

            elif item["event"] == "Successful Login":
                recent = [
                    time for time in failures[ip]
                    if item["timestamp"] - time <= timedelta(minutes=10)
                ]

                if len(recent) >= 3:
                    item["severity"] = "HIGH"
                    item["description"] = (
                        f"Successful login after {len(recent)} recent failed attempts"
                    )

    # ----------------------------
    # Filters and table
    # ----------------------------
    def apply_filters(self):
        search_text = self.search_entry.get().strip().lower()
        severity = self.severity_box.get()
        date_text = self.date_entry.get().strip()

        filtered = []

        for item in self.all_results:
            if search_text:
                searchable = " ".join([
                    item["ip"],
                    item["username"],
                    item["event"],
                    item["status"],
                    item["severity"],
                    item["description"],
                    item["raw"],
                ]).lower()

                if search_text not in searchable:
                    continue

            if severity != "ALL" and item["severity"] != severity:
                continue

            if date_text:
                if not item["timestamp"] or item["timestamp"].strftime("%Y-%m-%d") != date_text:
                    continue

            filtered.append(item)

        self.filtered_results = filtered
        self.show_results(filtered)

    def show_results(self, results):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for item in results:
            timestamp = item["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if item["timestamp"] else "N/A"

            self.tree.insert(
                "",
                "end",
                values=(
                    timestamp,
                    item["ip"],
                    item["username"],
                    item["event"],
                    item["status"],
                    item["severity"],
                    item["description"],
                ),
            )

    # ----------------------------
    # Statistics
    # ----------------------------
    def update_statistics(self):
        total = len(self.all_results)
        failed = sum(item["event"] == "Failed Login" for item in self.all_results)
        success = sum(item["event"] == "Successful Login" for item in self.all_results)

        ips = [item["ip"] for item in self.all_results if item["ip"] != "N/A"]
        unique_ips = len(set(ips))

        suspicious_ips = {
            item["ip"] for item in self.all_results
            if item["ip"] != "N/A" and item["severity"] in ("HIGH", "CRITICAL")
        }

        alerts = sum(item["severity"] in ("HIGH", "CRITICAL") for item in self.all_results)

        self.stat_labels["total"].config(text=str(total))
        self.stat_labels["failed"].config(text=str(failed))
        self.stat_labels["success"].config(text=str(success))
        self.stat_labels["unique_ips"].config(text=str(unique_ips))
        self.stat_labels["suspicious"].config(text=str(len(suspicious_ips)))
        self.stat_labels["alerts"].config(text=str(alerts))

    # ----------------------------
    # Charts
    # ----------------------------
    def show_charts(self):
        if not self.all_results:
            messagebox.showwarning("No Data", "Analyze a log file first.")
            return

        failed = sum(item["event"] == "Failed Login" for item in self.all_results)
        success = sum(item["event"] == "Successful Login" for item in self.all_results)

        # Chart 1: failed vs successful logins
        plt.figure(figsize=(6, 4))
        plt.bar(["Failed", "Successful"], [failed, success])
        plt.title("Login Attempts")
        plt.ylabel("Number of Events")
        plt.tight_layout()
        plt.show()

        # Chart 2: top IP addresses
        ip_counts = Counter(
            item["ip"] for item in self.all_results if item["ip"] != "N/A"
        ).most_common(5)

        if ip_counts:
            labels = [item[0] for item in ip_counts]
            values = [item[1] for item in ip_counts]

            plt.figure(figsize=(7, 4))
            plt.bar(labels, values)
            plt.title("Top Active IP Addresses")
            plt.ylabel("Number of Events")
            plt.xticks(rotation=30, ha="right")
            plt.tight_layout()
            plt.show()

    # ----------------------------
    # Export and clear
    # ----------------------------
    def export_csv(self):
        if not self.all_results:
            messagebox.showwarning("No Data", "There is no analysis data to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save analysis report",
        )

        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow([
                    "Timestamp",
                    "IP Address",
                    "Username",
                    "Event",
                    "Status",
                    "Severity",
                    "Description",
                ])

                for item in self.all_results:
                    timestamp = item["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if item["timestamp"] else "N/A"
                    writer.writerow([
                        timestamp,
                        item["ip"],
                        item["username"],
                        item["event"],
                        item["status"],
                        item["severity"],
                        item["description"],
                    ])

            messagebox.showinfo("Export Complete", "The CSV report was saved successfully.")
        except OSError:
            messagebox.showerror("Export Error", "The report could not be saved.")

    def clear_data(self):
        self.file_path = ""
        self.all_results = []
        self.filtered_results = []
        self.file_label.config(text="No file selected")
        self.search_entry.delete(0, "end")
        self.date_entry.delete(0, "end")
        self.severity_box.set("ALL")

        for label in self.stat_labels.values():
            label.config(text="0")

        for row in self.tree.get_children():
            self.tree.delete(row)


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityLogAnalyzer(root)
    root.mainloop()
