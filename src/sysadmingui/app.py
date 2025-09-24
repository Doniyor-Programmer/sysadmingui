"""SysAdmin GUI tool implemented with Tkinter."""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import psutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

REFRESH_INTERVAL = 3000  # milliseconds
LOG_POLL_INTERVAL = 1000  # milliseconds


@dataclass
class ServiceStatus:
    """Represents a parsed row from `systemctl list-units`."""

    name: str
    load: str
    active: str
    sub: str
    description: str

    @property
    def friendly_state(self) -> str:
        return f"{self.active}/{self.sub}"


class SysAdminGUI(tk.Tk):
    """Main GUI window for the SysAdmin tool."""

    def __init__(self) -> None:
        super().__init__()
        self.title("SysAdmin Toolkit")
        self.geometry("1000x700")
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        self.dashboard_tab = ttk.Frame(notebook)
        notebook.add(self.dashboard_tab, text="Dashboard")
        self._init_dashboard()

        self.process_tab = ttk.Frame(notebook)
        notebook.add(self.process_tab, text="Processes")
        self._init_process_tab()

        self.service_tab = ttk.Frame(notebook)
        notebook.add(self.service_tab, text="Services")
        self._init_service_tab()

        self.logs_tab = ttk.Frame(notebook)
        notebook.add(self.logs_tab, text="Logs")
        self._init_logs_tab()

        self.after(1000, self._refresh_dashboard)
        self.after(1000, self._refresh_processes)
        self.after(1000, self._refresh_services)

    # ------------------------------------------------------------------
    # Dashboard
    def _init_dashboard(self) -> None:
        frame = self.dashboard_tab

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=2)

        ttk.Label(frame, text="System Overview", font=("TkDefaultFont", 16, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(10, 20)
        )

        self.cpu_usage_var = tk.StringVar()
        self.memory_usage_var = tk.StringVar()
        self.disk_usage_var = tk.StringVar()
        self.load_avg_var = tk.StringVar()
        self.uptime_var = tk.StringVar()

        row = 1
        for label, var in [
            ("CPU Usage", self.cpu_usage_var),
            ("Memory Usage", self.memory_usage_var),
            ("Disk Usage", self.disk_usage_var),
            ("Load Average", self.load_avg_var),
            ("Uptime", self.uptime_var),
        ]:
            ttk.Label(frame, text=label + ":", font=("TkDefaultFont", 12, "bold")).grid(
                row=row, column=0, sticky=tk.W, padx=20, pady=10
            )
            ttk.Label(frame, textvariable=var).grid(row=row, column=1, sticky=tk.W, padx=20)
            row += 1

        self.cpu_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=400, mode="determinate")
        self.cpu_progress.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=20, pady=10)

        self.memory_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=400, mode="determinate")
        self.memory_progress.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=20, pady=10)

        self.disk_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=400, mode="determinate")
        self.disk_progress.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=20, pady=10)

        ttk.Button(frame, text="Refresh", command=self._refresh_dashboard).grid(
            row=row, column=0, columnspan=2, pady=20
        )

    def _refresh_dashboard(self) -> None:
        cpu = psutil.cpu_percent(interval=0.2)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        self.cpu_progress["value"] = cpu
        self.cpu_usage_var.set(f"{cpu:.1f}%")

        self.memory_progress["value"] = memory.percent
        self.memory_usage_var.set(
            f"{memory.used / (1024**3):.2f} GiB / {memory.total / (1024**3):.2f} GiB ({memory.percent:.1f}%)"
        )

        self.disk_progress["value"] = disk.percent
        self.disk_usage_var.set(
            f"{disk.used / (1024**3):.2f} GiB / {disk.total / (1024**3):.2f} GiB ({disk.percent:.1f}%)"
        )

        if hasattr(os, "getloadavg"):
            load = os.getloadavg()
            self.load_avg_var.set(f"{load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}")
        else:
            self.load_avg_var.set("N/A")

        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_hours = uptime_seconds / 3600
        days, rem = divmod(int(uptime_seconds), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        self.uptime_var.set(f"{days}d {hours}h {minutes}m ({uptime_hours:.1f} hours)")

        self.after(REFRESH_INTERVAL, self._refresh_dashboard)

    # ------------------------------------------------------------------
    # Process Tab
    def _init_process_tab(self) -> None:
        frame = self.process_tab
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        columns = ("pid", "name", "cpu", "memory", "user")
        self.process_tree = ttk.Treeview(frame, columns=columns, show="headings")
        self.process_tree.heading("pid", text="PID")
        self.process_tree.heading("name", text="Name")
        self.process_tree.heading("cpu", text="CPU %")
        self.process_tree.heading("memory", text="Memory %")
        self.process_tree.heading("user", text="User")

        self.process_tree.column("pid", width=80, anchor=tk.CENTER)
        self.process_tree.column("name", width=250)
        self.process_tree.column("cpu", width=80, anchor=tk.CENTER)
        self.process_tree.column("memory", width=100, anchor=tk.CENTER)
        self.process_tree.column("user", width=120, anchor=tk.CENTER)

        self.process_tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.process_tree.configure(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=1, column=0, sticky=(tk.E, tk.W), pady=10)
        for i in range(3):
            button_frame.columnconfigure(i, weight=1)

        ttk.Button(button_frame, text="Refresh", command=self._refresh_processes).grid(
            row=0, column=0, padx=5
        )
        ttk.Button(button_frame, text="Kill Process", command=self._kill_selected_process).grid(
            row=0, column=1, padx=5
        )
        ttk.Button(button_frame, text="View Details", command=self._show_process_details).grid(
            row=0, column=2, padx=5
        )

    def _refresh_processes(self) -> None:
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)

        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
            info = proc.info
            self.process_tree.insert(
                "",
                tk.END,
                values=(
                    info.get("pid"),
                    info.get("name"),
                    f"{info.get('cpu_percent', 0.0):.1f}",
                    f"{info.get('memory_percent', 0.0):.1f}",
                    info.get("username", ""),
                ),
            )

        self.after(REFRESH_INTERVAL, self._refresh_processes)

    def _selected_pid(self) -> Optional[int]:
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a process first.")
            return None
        pid = self.process_tree.item(selected[0], "values")[0]
        return int(pid)

    def _kill_selected_process(self) -> None:
        pid = self._selected_pid()
        if pid is None:
            return

        answer = messagebox.askyesno("Confirm", f"Are you sure you want to terminate PID {pid}?")
        if not answer:
            return

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            messagebox.showinfo("Success", f"Process {pid} terminated.")
            self._refresh_processes()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            messagebox.showerror("Error", f"Failed to terminate process {pid}: {exc}")

    def _show_process_details(self) -> None:
        pid = self._selected_pid()
        if pid is None:
            return

        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                create_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(proc.create_time()))
                cpu_times = proc.cpu_times()
                memory_info = proc.memory_info()
                open_files = proc.open_files()
                connections = proc.connections()

            details = [
                f"PID: {proc.pid}",
                f"Name: {proc.name()}",
                f"Status: {proc.status()}",
                f"User: {proc.username()}",
                f"Started: {create_time}",
                f"CPU Times: user={cpu_times.user:.2f}s system={cpu_times.system:.2f}s",
                f"Memory: RSS={memory_info.rss / (1024**2):.2f} MiB, VMS={memory_info.vms / (1024**2):.2f} MiB",
                f"Threads: {proc.num_threads()}",
                f"Open Files: {len(open_files)}",
                f"Connections: {len(connections)}",
            ]
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            messagebox.showerror("Error", f"Failed to read process details: {exc}")
            return

        detail_window = tk.Toplevel(self)
        detail_window.title(f"Process Details - {pid}")
        detail_window.geometry("500x400")

        text = tk.Text(detail_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, "\n".join(details))
        text.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Service tab
    def _init_service_tab(self) -> None:
        frame = self.service_tab
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        columns = ("name", "state", "description")
        self.service_tree = ttk.Treeview(frame, columns=columns, show="headings")
        self.service_tree.heading("name", text="Service")
        self.service_tree.heading("state", text="State")
        self.service_tree.heading("description", text="Description")

        self.service_tree.column("name", width=240)
        self.service_tree.column("state", width=140)
        self.service_tree.column("description", width=400)
        self.service_tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.service_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.service_tree.configure(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=1, column=0, sticky=(tk.E, tk.W), pady=10)
        for i in range(4):
            button_frame.columnconfigure(i, weight=1)

        ttk.Button(button_frame, text="Refresh", command=self._refresh_services).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Start", command=lambda: self._service_action("start")).grid(
            row=0, column=1, padx=5
        )
        ttk.Button(button_frame, text="Stop", command=lambda: self._service_action("stop")).grid(
            row=0, column=2, padx=5
        )
        ttk.Button(button_frame, text="Restart", command=lambda: self._service_action("restart")).grid(
            row=0, column=3, padx=5
        )

        self.service_status_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.service_status_var).grid(
            row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5
        )

    def _refresh_services(self) -> None:
        for item in self.service_tree.get_children():
            self.service_tree.delete(item)

        services = self._list_systemd_services()
        if services is None:
            self.service_status_var.set("systemctl not available. Services tab disabled.")
            self.service_tree.configure(selectmode="none")
            return

        for svc in services:
            self.service_tree.insert("", tk.END, values=(svc.name, svc.friendly_state, svc.description))

        self.service_status_var.set(f"Loaded {len(services)} services.")
        self.after(REFRESH_INTERVAL * 2, self._refresh_services)

    def _systemctl_available(self) -> bool:
        return shutil.which("systemctl") is not None

    def _list_systemd_services(self) -> Optional[List[ServiceStatus]]:
        import shutil

        if not self._systemctl_available():
            return None

        try:
            output = subprocess.check_output(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--all",
                    "--plain",
                    "--no-legend",
                    "--no-pager",
                ],
                stderr=subprocess.STDOUT,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            self.service_status_var.set(f"Failed to list services: {exc.output.strip()}")
            return []

        services: List[ServiceStatus] = []
        for line in output.strip().splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            name, load, active, sub, description = parts
            services.append(ServiceStatus(name=name, load=load, active=active, sub=sub, description=description))

        return services

    def _selected_service(self) -> Optional[str]:
        selection = self.service_tree.selection()
        if not selection:
            messagebox.showinfo("Selection Required", "Please select a service first.")
            return None
        return self.service_tree.item(selection[0], "values")[0]

    def _service_action(self, action: str) -> None:
        service = self._selected_service()
        if service is None:
            return

        if not self._systemctl_available():
            messagebox.showerror("Error", "systemctl is not available on this system.")
            return

        try:
            subprocess.check_output(["systemctl", action, service], stderr=subprocess.STDOUT, text=True)
            messagebox.showinfo("Success", f"Service {action}ed successfully.")
            self._refresh_services()
        except subprocess.CalledProcessError as exc:
            messagebox.showerror("Error", f"Failed to {action} {service}: {exc.output.strip()}")

    # ------------------------------------------------------------------
    # Logs tab
    def _init_logs_tab(self) -> None:
        frame = self.logs_tab
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        ttk.Label(frame, text="Log Viewer", font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, sticky=tk.W, padx=10, pady=10
        )

        toolbar = ttk.Frame(frame)
        toolbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        toolbar.columnconfigure(0, weight=1)
        toolbar.columnconfigure(1, weight=0)

        self.log_path_var = tk.StringVar()
        entry = ttk.Entry(toolbar, textvariable=self.log_path_var)
        entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=5)

        ttk.Button(toolbar, text="Browse", command=self._browse_log_file).grid(row=0, column=1, padx=5)
        ttk.Button(toolbar, text="Start Tail", command=self._start_tail).grid(row=0, column=2, padx=5)
        ttk.Button(toolbar, text="Stop Tail", command=self._stop_tail).grid(row=0, column=3, padx=5)

        self.log_text = tk.Text(frame, wrap=tk.NONE)
        self.log_text.grid(row=2, column=0, sticky=(tk.N, tk.S, tk.E, tk.W), padx=10, pady=5)

        y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_text.yview)
        y_scroll.grid(row=2, column=1, sticky=(tk.N, tk.S))
        self.log_text.configure(yscrollcommand=y_scroll.set)

        x_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.log_text.xview)
        x_scroll.grid(row=3, column=0, sticky=(tk.W, tk.E))
        self.log_text.configure(xscrollcommand=x_scroll.set)

        self._log_tail_thread: Optional[threading.Thread] = None
        self._log_tail_stop = threading.Event()
        self._log_queue: queue.Queue[str] = queue.Queue()
        self.after(LOG_POLL_INTERVAL, self._poll_log_queue)

    def _browse_log_file(self) -> None:
        file_path = filedialog.askopenfilename(title="Select log file", initialdir=str(Path("/var/log")))
        if file_path:
            self.log_path_var.set(file_path)

    def _start_tail(self) -> None:
        path = self.log_path_var.get()
        if not path:
            messagebox.showinfo("Select File", "Please select a log file first.")
            return

        file_path = Path(path)
        if not file_path.exists():
            messagebox.showerror("Error", f"File {file_path} does not exist.")
            return

        if self._log_tail_thread and self._log_tail_thread.is_alive():
            messagebox.showinfo("Tail Running", "Log tail already running.")
            return

        self._log_tail_stop.clear()
        self._log_tail_thread = threading.Thread(target=self._tail_file, args=(file_path,), daemon=True)
        self._log_tail_thread.start()
        self.log_text.insert(tk.END, f"\n--- Started tailing {file_path} ---\n")

    def _stop_tail(self) -> None:
        if self._log_tail_thread and self._log_tail_thread.is_alive():
            self._log_tail_stop.set()
            self._log_tail_thread.join(timeout=1)
            self.log_text.insert(tk.END, "\n--- Stopped tailing ---\n")

    def _tail_file(self, file_path: Path) -> None:
        try:
            with file_path.open("r") as fh:
                fh.seek(0, os.SEEK_END)
                while not self._log_tail_stop.is_set():
                    line = fh.readline()
                    if line:
                        self._log_queue.put(line)
                    else:
                        time.sleep(0.5)
        except Exception as exc:  # broad to surface errors to UI
            self._log_queue.put(f"Error tailing file: {exc}\n")

    def _poll_log_queue(self) -> None:
        while True:
            try:
                line = self._log_queue.get_nowait()
            except queue.Empty:
                break
            else:
                self.log_text.insert(tk.END, line)
                self.log_text.see(tk.END)
        self.after(LOG_POLL_INTERVAL, self._poll_log_queue)


def main() -> None:
    app = SysAdminGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
