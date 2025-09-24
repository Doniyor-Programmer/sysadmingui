# SysAdmin GUI

A cross-platform Tkinter-based toolkit providing essential system administration utilities:

- **Dashboard** – monitor CPU, memory, disk, load averages, and uptime with live updates.
- **Processes** – inspect running processes, view detailed statistics, and terminate processes.
- **Services** – interact with systemd services (start/stop/restart) when `systemctl` is available.
- **Logs** – tail arbitrary log files with live updates.

## Requirements

- Python 3.9+
- [psutil](https://github.com/giampaolo/psutil)
- Linux with systemd for service management features

Install dependencies with:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m sysadmingui.app
```

The application uses Tkinter and can be bundled with packaging tools like `pyinstaller` if a standalone binary is desired.
