# Network Anomaly Detection and 3D Visualization System

A multi-user web app that captures live network traffic (or loads a `.pcap` file), builds a graph of which devices talk to which, detects attacks using graph algorithms and statistics, and shows the results in an interactive 3D dashboard with plain-English explanations and one-click IP blocking.

## Features

- **Live capture and PCAP upload:** sniff traffic with Scapy or analyse a recorded `.pcap` file.
- **Time-window analysis:** traffic is split into 100-packet windows. Each window is a directed graph (devices as nodes, packet counts as edge weights), so users can inspect one time frame at a time instead of one confusing graph.
- **Attack detection:** DDoS, port scan (source and target), brute force (attacker and target), data exfiltration, botnet controller, network scanner, and a fallback "unknown anomaly". Each detection gets a confidence value and a 1-10 severity, based on betweenness, PageRank, degree centrality, clustering, and z-score spikes.
- **3D network graph:** Plotly 3D view with colour-coded threat types, node size scaled by severity, and heavy-traffic edges highlighted.
- **Attack replay:** packet-by-packet replay with play/pause, step, speed control, a slider, and a chart showing the detection threshold being crossed.
- **Plain-language alerts:** each alert has an explanation, a "why was this flagged" breakdown, and numbered action steps.
- **IP blocking:** block and unblock IPs through `netsh` (Windows) or `iptables` (Linux), with manual commands shown if the automatic rule fails.
- **Device discovery:** Nmap scan with OS-specific install instructions if Nmap is missing.
- **Users and history:** signup/login with hashed passwords, per-user history in SQLite (detections, windows, devices, block rules, alert log), and a History tab to browse it.

## Tech stack

Python, Dash, Flask, Flask-Login, SQLite, Scapy, NetworkX, NumPy, SciPy, Plotly

## Project structure

| File | Purpose |
|------|---------|
| `app.py` | Dash app: capture, detection, 3D graph, replay, blocking, UI |
| `netpulse_db.py` | SQLite schema, migration, and per-user reads/writes |
| `auth.py` | Signup, login, logout, and route protection |

## Setup

```bash
git clone https://github.com/harikrishna247/<repo-name>.git
cd <repo-name>
pip install dash plotly networkx numpy scipy scapy flask-login werkzeug
```

Optional but recommended:

- Install [Nmap](https://nmap.org/download.html) for device discovery.
- On Windows, install [Npcap](https://npcap.com/) so Scapy can capture packets.
- Set a secret key for sessions: `NETPULSE_SECRET_KEY=your-secret-value`

## Run

```bash
python app.py
```

Open http://127.0.0.1:8050, create an account, and click **Start monitoring**.

Live capture and IP blocking need admin rights (Windows: run the terminal as Administrator; Linux: use `sudo`). Without them, you can still upload a `.pcap` file and use the manual block instructions.

## How to use

1. Sign up with a username, email, and password, then log in.
2. Click **Start monitoring** or upload a `.pcap` file.
3. Read the alerts on the **Overview** tab and look at the 3D graph.
4. Select a time window to open it in **Investigate** and play the attack replay.
5. Block a suspicious IP, then review block rules in **Rules & Logs**.
6. Browse saved data in the **History** tab.

## Notes

- This tool only reads traffic. It applies firewall rules only when you click Block.
- Use it only on networks you own or have permission to monitor.
