# NetMon
<code style="color: red">hello World!</code>
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-defensive-blue)
![Domain](https://img.shields.io/badge/Domain-Network%20Security-green)
![Status](https://img.shields.io/badge/status-active-success.svg)

NetMon is a graphical, cross-platform tool built with Python and Tkinter designed to provide real-time visibility into all network connections (IPv4, IPv6, TCP, UDP) established by processes on your local machine.

This project is open-source and created by [zrng].

![NetMon](https://github.com/zrnge/NetMon/blob/main/NetMon.png)

# 🚀 Features

**Real-time Table View:** Displays connections including Source IP/Port, Destination IP/Port, Protocol, Process ID (PID), Process Name, Connection Status, and Connection Duration.

**PID Tracking:** Automatically tracks when a connection enters the ESTABLISHED state to calculate accurate duration.

**Theming:** Supports Light and Dark modes with system default detection.

**Filtering:** Use the dropdown to filter by connection Status (e.g., ESTABLISHED, LISTEN, TIME_WAIT).

**Query Search:** Use a powerful search box to filter by multiple criteria (e.g., pid:1234,process_name:chrome,dst_ip:8.8.8.8).

**Baseline Comparison:** Save a network baseline and highlight any new, previously unseen connections for security analysis.

**Logging:** Save dynamic logs of new established connections (network_log.txt) or export a snapshot of the current table data.

**Copy Functionality:** Right-click any row or column to copy data directly to the clipboard.

# ⚙️ Installation

## Prerequisites

You need Python 3.x installed on your system.

## Install Dependencies

NetMon only requires the psutil library (Tkinter is usually included with standard Python installations).
```
pip install -r requirements.txt
```

# ▶️ Running NetMon

IMPORTANT: Due to operating system security restrictions, NetMon must be run with elevated privileges (Administrator/root) to access connection data and associate PIDs with process names for all system-wide connections.

#Operating System

## Linux/macOS
```
sudo python3 netmon_v1.1.py
```
##  Windows
```
1. Open Command Prompt or PowerShell as Administrator. 

2. Navigate to the project directory. 

3. Run: python netmon_v1.1.py
```
# 📝 Usage Guide

## Search Query Filter

Use the text input field to filter the table based on specific criteria. Separate key-value pairs with commas. The search is case-insensitive and supports partial matches.

> Format: key:value,key:value

Key Description Example

pid Process ID 
```
pid:8765
```
process_name Executable name
```
process_name:firefox
```
src_ip Local IP address
```
src_ip:192.168.1.1
```
dst_ip Remote IP address
```
dst_ip:1.1.1.1
```
src_port Local port number
```
src_port:54321
```
dst_port Remote port number
```
dst_port:443
```
protocol Protocol type
```
protocol:udp/ipv6
```
## Baseline Comparison

Use the File menu to manage baselines:

> File > Save a Baseline: Saves the current set of established connections to network_baseline.json.

> File > Compare to a Baseline: Enables comparison mode. Any connection currently active that was NOT in the saved baseline will be highlighted in the table, indicating potentially new or suspicious activity.
