import plotly.graph_objects as go
import threading
from scapy.all import IP, TCP, sniff
import networkx as nx
import numpy as np
from scipy.stats import zscore
from datetime import datetime
import base64
import tempfile
import os
import socket
import dash
from dash import Dash, dcc, html, Input, Output, State, ALL, callback_context
app = Dash(__name__, suppress_callback_exceptions=True)


# ============================================================
# SHARED STATE — shared between threads and dashboard
# ============================================================
state = {
    "running": False,
    "detected": [],
    "windows": [],
    "window_count": 0,
    "total_ips": 0,
    "packet_buffer": [],
    "window_history": [],
    "graph": None,
    "window_graphs": [],      # stores graph per window for replay
    "window_details": [],     # stores full details per window
    "selected_window": None,  # which window user clicked
    "replay_mode": False,     # is replay playing
    "policies": [],            # simulated firewall policies
    "local_ips": set(),       # IP addresses belonging to this machine
    "pcap_source": None,      # uploaded PCAP currently being analyzed
    "user_device_ip": None,   # optional manual device identification
}

WINDOW_SIZE = 100
SPIKE_THRESHOLD = 1.5

known_attacks = {
    "192.168.1.100": "DDoS Victim",
    "192.168.1.50":  "Port Scan Target",
    "172.16.0.1":    "Port Scanner",
    "192.168.1.20":  "Data Exfiltration Source",
    "91.108.4.1":    "Botnet Controller",
    "172.16.0.5":    "Brute Force Attacker",
    "192.168.1.10":  "Brute Force Target",
    "10.20.0.1":     "Network Scanner",
}

recommendations = {
    "DDoS Victim":              "Activate rate limiting immediately",
    "Port Scanner":             "Block IP at firewall",
    "Port Scan Target":         "Review open ports",
    "Data Exfiltration Source": "Isolate device immediately",
    "Botnet Controller":        "Block external IP",
    "Brute Force Attacker":     "Block IP and enable lockout",
    "Brute Force Target":       "Enable MFA immediately",
    "Network Scanner":          "Block IP and alert team",
    "Unknown Anomaly":          "Investigate manually",
    "DDoS":                     "Activate rate limiting immediately",
    "Exfiltration":             "Isolate device immediately",
    "Network Scanner RT":       "Block IP and alert team",
}

attack_colors = {
    "DDoS Victim": "red",
    "Port Scanner": "orange",
    "Port Scan Target": "orange",
    "Data Exfiltration Source": "purple",
    "Botnet Controller": "darkred",
    "Brute Force Attacker": "yellow",
    "Brute Force Target": "yellow",
    "Network Scanner": "cyan",
    "Unknown Anomaly": "pink",
    "DDoS": "red",
    "Exfiltration": "purple",
}

# ============================================================
# CORE FUNCTIONS
# ============================================================

import time

def unpack_packet(record):
    if isinstance(record, dict):
        return (float(record.get("timestamp", time.time())), record.get("src"), record.get("dst"), int(record.get("port", 0)))
    if len(record) >= 4:
        return float(record[0]), record[1], record[2], int(record[3])
    return time.time(), record[0], record[1], int(record[2])

def packet_for_storage(record):
    timestamp, src, dst, port = unpack_packet(record)
    return {"timestamp": timestamp, "src": src, "dst": dst, "port": port}

def format_packet_time(timestamp):
    try:
        return datetime.fromtimestamp(float(timestamp)).strftime("%H:%M:%S.%f")[:-3]
    except Exception:
        return "Unknown"

def build_graph(packets):
    G = nx.DiGraph()
    port_connections = {}
    for record in packets:
        _, src, dst, port = unpack_packet(record)
        key = (src, dst)
        if key not in port_connections:
            port_connections[key] = set()
        port_connections[key].add(port)
        if src not in G:
            G.add_node(src, ports_tried=[], ports_received=[])
        if dst not in G:
            G.add_node(dst, ports_tried=[], ports_received=[])
        if port not in G.nodes[src]["ports_tried"]:
            G.nodes[src]["ports_tried"].append(port)
        if port not in G.nodes[dst]["ports_received"]:
            G.nodes[dst]["ports_received"].append(port)
        if G.has_edge(src, dst):
            G[src][dst]["weight"] += 1
        else:
            G.add_edge(src, dst, weight=1, ports=[port])
        if G.has_edge(src, dst):
            ports = G[src][dst].setdefault("ports", [])
            if port not in ports:
                ports.append(port)
    return G, port_connections

def run_algorithms(G, port_connections):
    if G.number_of_nodes() == 0:
        return {}, {}, [], {}

    betweenness = nx.betweenness_centrality(G, weight="weight")
    pagerank = nx.pagerank(G, weight="weight")
    G_undirected = G.to_undirected()
    communities = nx.community.greedy_modularity_communities(G_undirected)
    degree_centrality = nx.degree_centrality(G)
    clustering = nx.clustering(G_undirected)

    community_map = {}
    for i, community in enumerate(communities):
        for node in community:
            community_map[node] = i

    node_features = {}
    for ip in G.nodes():
        ports_tried = set()
        ports_received = set()
        for (src, dst), ports in port_connections.items():
            if src == ip:
                ports_tried.update(ports)
            if dst == ip:
                ports_received.update(ports)

        node_features[ip] = {
            "incoming": G.in_degree(ip, weight="weight"),
            "outgoing": G.out_degree(ip, weight="weight"),
            "unique_attackers": len(list(G.predecessors(ip))),
            "unique_destinations": len(list(G.successors(ip))),
            "betweenness": betweenness.get(ip, 0),
            "pagerank": pagerank.get(ip, 0),
            "degree_centrality": degree_centrality.get(ip, 0),
            "clustering": clustering.get(ip, 0),
            "community": community_map.get(ip, -1),
            "ports_tried": len(ports_tried),
            "ports_received": len(ports_received),
        }

    ips = list(node_features.keys())

    def safe_zscore(arr):
        if arr.std() == 0:
            return np.zeros(len(arr))
        return zscore(arr)

    metrics = ["incoming", "outgoing", "unique_attackers",
               "unique_destinations", "pagerank", "betweenness",
               "ports_tried", "ports_received"]

    z_scores = {}
    for metric in metrics:
        vals = np.array([node_features[ip][metric] for ip in ips])
        z = safe_zscore(vals)
        for i, ip in enumerate(ips):
            z_scores[f"{ip}_{metric}"] = z[i]

    return node_features, z_scores, communities, community_map

def detect_attacks(G, node_features, z_scores, community_map):
    detected = []
    for ip in G.nodes():
        f = node_features[ip]
        if is_router(ip):
            continue
        attack_type = None
        confidence = 0
        algorithms_flagged = []

        def z(metric):
            return z_scores.get(f"{ip}_{metric}", 0)

        # DDoS
        ddos_score = 0
        if f["unique_attackers"] > 30:
            ddos_score += 40
            algorithms_flagged.append("Unique Attackers")
        if z("incoming") > 2:
            ddos_score += 25
            algorithms_flagged.append("Z-Score Incoming")
        if f["betweenness"] > 0.05:
            ddos_score += 20
            algorithms_flagged.append("Betweenness Centrality")
        if f["pagerank"] > 0.05:
            ddos_score += 15
            algorithms_flagged.append("PageRank")
        if ddos_score >= 60:
            attack_type = "DDoS Victim"
            confidence = min(99, ddos_score)

        if not attack_type:
            if f["ports_tried"] > 50 and f["unique_destinations"] <= 2:
                ps_score = 0
                if f["ports_tried"] > 50:
                    ps_score += 50
                    algorithms_flagged.append("High Port Variety")
                if z("ports_tried") > 2:
                    ps_score += 25
                    algorithms_flagged.append("Z-Score Ports Tried")
                if f["clustering"] < 0.1:
                    ps_score += 15
                    algorithms_flagged.append("Clustering Coefficient")
                if f["degree_centrality"] > 0.01:
                    ps_score += 10
                    algorithms_flagged.append("Degree Centrality")
                if ps_score >= 50:
                    attack_type = "Port Scanner"
                    confidence = min(99, ps_score)

        if not attack_type:
            if f["ports_received"] > 50 and f["unique_attackers"] <= 3:
                attack_type = "Port Scan Target"
                confidence = 90
                algorithms_flagged.append("High Ports Received")
                algorithms_flagged.append("Z-Score Ports Received")

        if not attack_type:
            if (f["outgoing"] > 100 and f["unique_destinations"] <= 2
                    and f["ports_tried"] == 1):
                bf_score = 0
                if f["outgoing"] > 100:
                    bf_score += 40
                    algorithms_flagged.append("High Repeated Connections")
                if z("outgoing") > 2:
                    bf_score += 30
                    algorithms_flagged.append("Z-Score Outgoing")
                if f["ports_tried"] == 1:
                    bf_score += 20
                    algorithms_flagged.append("Single Port Repeated")
                if f["clustering"] < 0.1:
                    bf_score += 10
                    algorithms_flagged.append("Clustering Coefficient")
                if bf_score >= 60:
                    attack_type = "Brute Force Attacker"
                    confidence = min(99, bf_score)

        if not attack_type:
            if (f["incoming"] > 100 and f["unique_attackers"] <= 3
                    and f["ports_received"] == 1):
                attack_type = "Brute Force Target"
                confidence = 88
                algorithms_flagged.append("Repeated Single Port")
                algorithms_flagged.append("Z-Score Incoming")

        if not attack_type:
            if (f["outgoing"] > 50 and f["unique_attackers"] <= 2
                    and ip.startswith("192.168")
                    and f["unique_destinations"] > 5):
                exfil_score = 0
                if z("outgoing") > 2:
                    exfil_score += 35
                    algorithms_flagged.append("Z-Score Outgoing")
                if f["unique_destinations"] > 5:
                    exfil_score += 30
                    algorithms_flagged.append("Unique Destinations")
                if f["clustering"] < 0.3:
                    exfil_score += 20
                    algorithms_flagged.append("Clustering Coefficient")
                if f["degree_centrality"] > 0.01:
                    exfil_score += 15
                    algorithms_flagged.append("Degree Centrality")
                if exfil_score >= 50:
                    attack_type = "Data Exfiltration Source"
                    confidence = min(99, exfil_score)

        if not attack_type:
            if (f["unique_attackers"] > 5 and f["incoming"] > 50
                    and not ip.startswith("192.168")
                    and not ip.startswith("10.")):
                bot_score = 0
                if f["unique_attackers"] > 5:
                    bot_score += 35
                    algorithms_flagged.append("Multiple Internal Sources")
                if z("incoming") > 2:
                    bot_score += 30
                    algorithms_flagged.append("Z-Score Incoming")
                if community_map.get(ip) is not None:
                    bot_score += 20
                    algorithms_flagged.append("Community Detection")
                if f["pagerank"] > 0.01:
                    bot_score += 15
                    algorithms_flagged.append("PageRank")
                if bot_score >= 50:
                    attack_type = "Botnet Controller"
                    confidence = min(99, bot_score)

        if not attack_type:
            if f["unique_destinations"] > 50 and f["unique_attackers"] == 0:
                ns_score = 0
                if f["unique_destinations"] > 50:
                    ns_score += 40
                    algorithms_flagged.append("High Destination Variety")
                if z("unique_destinations") > 2:
                    ns_score += 30
                    algorithms_flagged.append("Z-Score Unique Destinations")
                if f["degree_centrality"] > 0.1:
                    ns_score += 20
                    algorithms_flagged.append("Degree Centrality")
                if f["clustering"] < 0.1:
                    ns_score += 10
                    algorithms_flagged.append("Clustering Coefficient")
                if ns_score >= 50:
                    attack_type = "Network Scanner"
                    confidence = min(99, ns_score)

        if not attack_type:
            anomaly_flags = []
            if abs(z("incoming")) > 3:
                anomaly_flags.append("Z-Score Incoming")
            if abs(z("outgoing")) > 3:
                anomaly_flags.append("Z-Score Outgoing")
            if abs(z("unique_attackers")) > 3:
                anomaly_flags.append("Z-Score Unique Attackers")
            if abs(z("unique_destinations")) > 3:
                anomaly_flags.append("Z-Score Unique Destinations")
            if len(anomaly_flags) >= 2:
                attack_type = "Unknown Anomaly"
                confidence = 60
                algorithms_flagged.extend(anomaly_flags)

        if attack_type:
            severity = min(10, max(1, round(
                (f["betweenness"] * 3) +
                (f["pagerank"] * 50) +
                (f["degree_centrality"] * 3) +
                (confidence / 20)
            )))
            detected.append({
                "ip": ip,
                "attack_type": attack_type,
                "confidence": confidence,
                "severity": severity,
                "algorithms_flagged": algorithms_flagged,
                "incoming": f["incoming"],
                "outgoing": f["outgoing"],
                "unique_attackers": f["unique_attackers"],
                "unique_destinations": f["unique_destinations"],
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })

    detected.sort(key=lambda x: x["severity"], reverse=True)
    return detected
# Filter out routers and gateways
def is_router(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    # Last octet is 1 or 254 = likely router/gateway
    if parts[3] in ["1", "254", "255"]:
        return True
    # Broadcast addresses
    if parts[3] == "0":
        return True
    return False
def get_local_ips():
    """Best-effort discovery of IPs assigned to this computer."""
    ips = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip:
                ips.add(ip)
    except Exception:
        pass
    try:
        from scapy.all import get_if_list, get_if_addr
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0":
                    ips.add(ip)
            except Exception:
                continue
    except Exception:
        pass
    return ips


def infer_device_type(ip, metrics=None, ports=None):
    """Return a beginner-friendly, best-effort device description."""
    metrics = metrics or {}
    ports = set(ports or [])
    if ip == state.get("user_device_ip") or ip in state.get("local_ips", set()):
        return "Your device"
    if is_router(ip):
        return "Router / Gateway"
    if 9100 in ports or 631 in ports or 515 in ports:
        return "Likely Printer"
    if 53 in ports:
        return "DNS Server"
    if 445 in ports or 3389 in ports:
        return "Likely Windows PC"
    if 22 in ports:
        return "Likely Linux / Unix Device"
    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        return "Web Server / Device"
    if 3306 in ports or 5432 in ports or 1433 in ports or 27017 in ports:
        return "Database Server"
    if not ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3")):
        return "External Device"
    return "Unknown Device"


def is_blockable_attack(attack_type):
    return attack_type in {
        "Port Scanner", "Botnet Controller", "Brute Force Attacker",
        "Network Scanner", "Unknown Anomaly"
    }


def device_info(ip, metrics=None, ports=None):
    dtype = infer_device_type(ip, metrics, ports)
    if dtype == "Your device":
        return "Your device", "This computer"
    if dtype == "Router / Gateway":
        return dtype, "Network gateway"
    if dtype == "Likely Printer":
        return dtype, "Printing device"
    if dtype == "Likely Windows PC":
        return dtype, "Windows computer or service host"
    if dtype == "Likely Linux / Unix Device":
        return dtype, "Linux/Unix computer or service host"
    if dtype == "Web Server / Device":
        return dtype, "Device exposing a web service"
    if dtype == "DNS Server":
        return dtype, "DNS service"
    if dtype == "Database Server":
        return dtype, "Database service"
    if dtype == "External Device":
        return dtype, "Address outside the local network"
    return dtype, "Device type could not be determined from traffic alone"


def get_ports_by_ip(packets):
    result = {}
    for record in packets:
        _, src, dst, port = unpack_packet(record)
        if not src or not dst:
            continue
        result.setdefault(src, set()).add(port)
        result.setdefault(dst, set()).add(port)
    return result


def is_ip_blocked(ip):
    return any(p.get("ip") == ip and p.get("action") == "BLOCK" for p in state.get("policies", []))


def build_plotly_figure(G, detected):
    if G is None or G.number_of_nodes() == 0:
        return go.Figure(layout=go.Layout(
            paper_bgcolor="#0a0a0a",
            plot_bgcolor="#0a0a0a",
            scene=dict(bgcolor="#0a0a0a"),
            title=dict(text="Waiting for network data", font=dict(color="white", size=14))
        ))

    nodes = list(G.nodes())
    pos_2d = nx.spring_layout(G, dim=3, seed=42, k=2)
    pos = {ip: (pos_2d[ip][0], pos_2d[ip][1], pos_2d[ip][2]) for ip in nodes}
    detected_ips = {d["ip"]: d for d in detected}

    light_ex, heavy_ex = [], []
    for src, dst in G.edges():
        weight = G[src][dst].get("weight", 1)
        x0, y0, z0 = pos[src]
        x1, y1, z1 = pos[dst]
        (heavy_ex if weight > 50 else light_ex).append((x0, y0, z0, x1, y1, z1))

    traces = []
    lx, ly, lz = [], [], []
    for x0, y0, z0, x1, y1, z1 in light_ex:
        lx += [x0, x1, None]; ly += [y0, y1, None]; lz += [z0, z1, None]
    if lx:
        traces.append(go.Scatter3d(x=lx, y=ly, z=lz, mode="lines",
            line=dict(color="rgba(100,100,100,0.4)", width=1), hoverinfo="none", name="Normal connection"))

    hx, hy, hz = [], [], []
    for x0, y0, z0, x1, y1, z1 in heavy_ex:
        hx += [x0, x1, None]; hy += [y0, y1, None]; hz += [z0, z1, None]
    if hx:
        traces.append(go.Scatter3d(x=hx, y=hy, z=hz, mode="lines",
            line=dict(color="rgba(255,70,70,0.65)", width=3), hoverinfo="none", name="Heavy traffic"))

    normal = {"x": [], "y": [], "z": [], "text": [], "hover": []}
    groups = {}
    for ip in nodes:
        x, y, z = pos[ip]
        ports = set(G.nodes[ip].get("ports_received", []))
        dtype, desc = device_info(ip, {}, ports)
        if ip in detected_ips:
            d = detected_ips[ip]
            group = d["attack_type"]
            groups.setdefault(group, {"x": [], "y": [], "z": [], "text": [], "hover": [], "size": []})
            groups[group]["x"].append(x); groups[group]["y"].append(y); groups[group]["z"].append(z)
            groups[group]["text"].append(f"{ip}<br>{dtype}")
            groups[group]["size"].append(12 + d["severity"] * 2)
            groups[group]["hover"].append(
                f"<b>{dtype}</b><br>IP: {ip}<br>Role: {desc}<br>"
                f"Threat: {d['attack_type']}<br>Severity: {d['severity']}/10<br>Confidence: {d['confidence']}%"
                + ("<br>Policy: BLOCKED" if is_ip_blocked(ip) else "")
            )
        else:
            normal["x"].append(x); normal["y"].append(y); normal["z"].append(z)
            blocked_note = "<br>Policy: BLOCKED" if is_ip_blocked(ip) else ""
            normal["text"].append(f"{ip}<br>{dtype}")
            normal["hover"].append(f"<b>{dtype}</b><br>IP: {ip}<br>Role: {desc}{blocked_note}")

    if normal["x"]:
        traces.append(go.Scatter3d(x=normal["x"], y=normal["y"], z=normal["z"],
            mode="markers+text", marker=dict(size=7, color="#3DDC97", opacity=0.85,
            line=dict(color="#D5F5E3", width=1)), text=normal["text"], textposition="top center",
            textfont=dict(color="white", size=9), hovertext=normal["hover"], hoverinfo="text", name="Normal device"))

    attack_color_map = {
        "DDoS Victim": "#E74C3C", "Port Scanner": "#F39C12", "Port Scan Target": "#E67E22",
        "Data Exfiltration Source": "#8E44AD", "Botnet Controller": "#922B21",
        "Brute Force Attacker": "#D4AC0D", "Brute Force Target": "#F39C12",
        "Network Scanner": "#17A2B8", "Unknown Anomaly": "#E84393"
    }
    for atype, data in groups.items():
        c = attack_color_map.get(atype, "#E74C3C")
        traces.append(go.Scatter3d(x=data["x"], y=data["y"], z=data["z"], mode="markers+text",
            marker=dict(size=data["size"], color=c, opacity=1, line=dict(color="white", width=1)),
            text=data["text"], textposition="top center", textfont=dict(color="white", size=9),
            hovertext=data["hover"], hoverinfo="text", name=atype))

    return go.Figure(data=traces, layout=go.Layout(
        paper_bgcolor="#0a0a0a", plot_bgcolor="#0a0a0a", font=dict(color="white"),
        scene=dict(bgcolor="#0a0a0a", xaxis=dict(visible=False), yaxis=dict(visible=False), zaxis=dict(visible=False),
                   camera=dict(eye=dict(x=1.5, y=1.5, z=1.0))),
        title=dict(text="Network Overview", font=dict(color="white", size=16), x=0.5),
        legend=dict(bgcolor="rgba(0,0,0,0.45)", bordercolor="#34495E", borderwidth=1,
                    font=dict(color="white", size=10), x=0.01, y=0.99),
        margin=dict(l=0, r=0, t=45, b=0)
    ))

# ============================================================
# REAL TIME CAPTURE THREAD
# ============================================================
def realtime_capture():
    def packet_callback(packet):
        if not state["running"]:
            return
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            port = packet[TCP].dport if packet.haslayer(TCP) else 0
            state["packet_buffer"].append({
                "timestamp": float(getattr(packet, "time", time.time())),
                "src": src, "dst": dst, "port": port
            })
        if len(state["packet_buffer"]) >= WINDOW_SIZE:
            process_window(state["packet_buffer"].copy())
            state["packet_buffer"].clear()
    sniff(prn=packet_callback, store=0, stop_filter=lambda p: not state["running"])


def process_window(packets):
    G, port_connections = build_graph(packets)
    state["graph"] = G
    state["total_ips"] = G.number_of_nodes()
    state["window_count"] += 1
    if G.number_of_nodes() == 0:
        return

    node_features, z_scores, communities, community_map = run_algorithms(G, port_connections)
    detected = detect_attacks(G, node_features, z_scores, community_map)
    for d in detected:
        existing = [x["ip"] for x in state["detected"]]
        if d["ip"] not in existing:
            state["detected"].append(d)

    curr_metrics = {}
    for ip in G.nodes():
        curr_metrics[ip] = {"incoming": G.in_degree(ip, weight="weight"),
                            "unique_attackers": len(list(G.predecessors(ip)))}
    window_info = {"window": state["window_count"], "status": "normal", "alerts": []}
    if state["window_history"]:
        prev_metrics = state["window_history"][-1]
        for ip, metrics in curr_metrics.items():
            if ip in prev_metrics:
                att_ratio = metrics["unique_attackers"] / max(prev_metrics[ip]["unique_attackers"], 1)
                in_ratio = metrics["incoming"] / max(prev_metrics[ip]["incoming"], 1)
                if att_ratio >= SPIKE_THRESHOLD and metrics["unique_attackers"] > 20:
                    window_info["status"] = "alert"; window_info["alerts"].append(f"DDoS forming on {ip}")
                elif in_ratio >= SPIKE_THRESHOLD and metrics["incoming"] > 20:
                    window_info["status"] = "warning"; window_info["alerts"].append(f"Traffic spike on {ip}")
    state["window_history"].append(curr_metrics)
    if len(state["window_history"]) > 10: state["window_history"].pop(0)
    state["windows"].append(window_info)
    if len(state["windows"]) > 20: state["windows"].pop(0)

    packet_records = [packet_for_storage(p) for p in packets]
    window_detail = {
        "window": state["window_count"], "graph_nodes": list(G.nodes()),
        "graph_edges": list(G.edges(data=True)), "detected": detected.copy(),
        "packets": packet_records, "start_time": packet_records[0]["timestamp"] if packet_records else None,
        "end_time": packet_records[-1]["timestamp"] if packet_records else None, "ip_metrics": {}, "ip_ports": {}
    }
    ports_by_ip = get_ports_by_ip(packets)
    for ip in G.nodes():
        window_detail["ip_metrics"][ip] = {
            "incoming": G.in_degree(ip, weight="weight"), "outgoing": G.out_degree(ip, weight="weight"),
            "unique_attackers": len(list(G.predecessors(ip))), "unique_destinations": len(list(G.successors(ip)))
        }
        window_detail["ip_ports"][ip] = sorted(ports_by_ip.get(ip, set()))
    state["window_details"].append(window_detail); state["window_graphs"].append(G.copy())
    if len(state["window_details"]) > 20: state["window_details"].pop(0)
    if len(state["window_graphs"]) > 20: state["window_graphs"].pop(0)

app.layout = html.Div(style={"backgroundColor": "#0B0F14", "minHeight": "100vh", "fontFamily": "Arial, sans-serif", "color": "#EAF2F8"}, children=[
    html.Div(style={"backgroundColor": "#111923", "padding": "18px 22px", "borderBottom": "1px solid #263544"}, children=[
        html.Div(style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "flexWrap": "wrap", "gap": "10px"}, children=[
            html.Div(children=[
                html.H1("NetPulse", style={"margin": 0, "fontSize": "26px", "fontWeight": "600", "color": "white"}),
                html.P("Network monitoring made understandable", style={"margin": "4px 0 0", "fontSize": "13px", "color": "#9FB3C8"})
            ]),
            html.Div(id="overall-status", children="Status: Waiting for network data", style={"fontSize": "13px", "color": "#9FB3C8"})
        ])
    ]),

    html.Div(style={"padding": "16px 18px", "maxWidth": "1500px", "margin": "0 auto"}, children=[
        html.Div(style={"display": "grid", "gridTemplateColumns": "repeat(auto-fit,minmax(150px,1fr))", "gap": "10px", "marginBottom": "14px"}, children=[
            html.Div(style={"backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "13px"}, children=[html.Div("Devices", style={"fontSize": "11px", "color": "#8FA3B8"}), html.Div(id="stat-ips", children="0", style={"fontSize": "24px", "fontWeight": "600", "marginTop": "3px"})]),
            html.Div(style={"backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "13px"}, children=[html.Div("Threats", style={"fontSize": "11px", "color": "#8FA3B8"}), html.Div(id="stat-threats", children="0", style={"fontSize": "24px", "fontWeight": "600", "color": "#F1948A", "marginTop": "3px"})]),
            html.Div(style={"backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "13px"}, children=[html.Div("Time windows", style={"fontSize": "11px", "color": "#8FA3B8"}), html.Div(id="stat-windows", children="0", style={"fontSize": "24px", "fontWeight": "600", "marginTop": "3px"})]),
            html.Div(style={"backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "13px"}, children=[html.Div("Policies", style={"fontSize": "11px", "color": "#8FA3B8"}), html.Div(id="stat-policies", children="0", style={"fontSize": "24px", "fontWeight": "600", "marginTop": "3px"})]),
        ]),

        html.Div(style={"display": "grid", "gridTemplateColumns": "minmax(260px,340px) minmax(0,1fr)", "gap": "14px"}, children=[
            html.Div(style={"backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "13px"}, children=[
                html.H3("Alerts", style={"margin": "0 0 10px", "fontSize": "15px", "fontWeight": "600"}),
                html.Div(id="alert-list", style={"height": "455px", "overflowY": "auto"})
            ]),
            html.Div(style={"backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "overflow": "hidden"}, children=[
                html.Div(style={"padding": "11px 14px", "borderBottom": "1px solid #263544", "display": "flex", "justifyContent": "space-between", "alignItems": "center", "flexWrap": "wrap", "gap": "8px"}, children=[
                    html.Div(children=[html.H3("Network overview", style={"margin": 0, "fontSize": "15px"}), html.P("Select a device or time window to understand what happened.", style={"margin": "3px 0 0", "fontSize": "11px", "color": "#8FA3B8"})]),
                    html.Div("Green = normal   Red = threat   Yellow = warning", style={"fontSize": "10px", "color": "#8FA3B8"})
                ]),
                dcc.Graph(id="network-graph", style={"height": "500px"}, config={"displayModeBar": False})
            ])
        ]),

        html.Div(style={"marginTop": "14px", "backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "13px"}, children=[
            html.H3("Network timeline", style={"margin": "0 0 4px", "fontSize": "15px"}),
            html.P("Each box represents a group of packets. Select one to inspect devices and threats in that period.", style={"margin": "0 0 10px", "fontSize": "11px", "color": "#8FA3B8"}),
            html.Div(id="temporal-panel", style={"display": "flex", "gap": "7px", "flexWrap": "wrap"})
        ]),

        html.Div(id="window-detail-panel", style={"display": "none", "marginTop": "14px", "backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "14px"}, children=[
            html.Div(style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "flexWrap": "wrap", "gap": "10px"}, children=[
                html.Div(children=[html.H3(id="window-detail-title", style={"margin": 0, "fontSize": "16px"}), html.Div(id="window-time-range", style={"fontSize": "11px", "color": "#8FA3B8", "marginTop": "3px"})]),
                html.Button("Block selected IP", id="btn-block-ip", n_clicks=0, style={"backgroundColor": "#922B21", "color": "white", "border": "0", "padding": "8px 12px", "borderRadius": "5px", "cursor": "pointer", "display": "none"})
            ]),
            html.Div(style={"display": "grid", "gridTemplateColumns": "minmax(0,1fr) minmax(0,1fr)", "gap": "12px", "marginTop": "12px"}, children=[
                html.Div(style={"backgroundColor": "#0D141C", "border": "1px solid #263544", "borderRadius": "6px", "padding": "10px"}, children=[html.H4("Devices in this period", style={"margin": "0 0 8px", "fontSize": "13px"}), html.Div(id="window-ip-table")]),
                html.Div(style={"backgroundColor": "#0D141C", "border": "1px solid #263544", "borderRadius": "6px", "padding": "10px"}, children=[html.H4("Suspicious activity", style={"margin": "0 0 8px", "fontSize": "13px"}), html.Div(id="window-suspicious")])
            ]),
            html.Div(style={"marginTop": "12px", "backgroundColor": "#0D141C", "border": "1px solid #263544", "borderRadius": "6px", "padding": "10px"}, children=[html.H4("Selected device", style={"margin": "0 0 8px", "fontSize": "13px"}), html.Div(id="selected-device-info", style={"fontSize": "12px", "color": "#D5DEE7"})])
        ]),

        html.Div(style={"marginTop": "14px", "backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "13px"}, children=[
            html.Div(style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "flexWrap": "wrap", "gap": "10px"}, children=[
                html.Div(children=[html.H3("Security policies", style={"margin": 0, "fontSize": "15px"}), html.P("Simulation only. A policy marks traffic from this IP as blocked inside NetPulse. It does not change your operating system firewall.", style={"margin": "3px 0 0", "fontSize": "11px", "color": "#8FA3B8"})]),
                html.Button("Clear all policies", id="btn-clear-policies", n_clicks=0, style={"backgroundColor": "#34495E", "color": "white", "border": 0, "padding": "7px 11px", "borderRadius": "5px", "cursor": "pointer"})
            ]),
            html.Div(id="policy-list", style={"marginTop": "10px"})
        ]),

        html.Div(style={"marginTop": "14px", "backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "10px", "display": "flex", "gap": "9px", "flexWrap": "wrap", "alignItems": "center"}, children=[
            html.Button("Start live capture", id="btn-start", style={"backgroundColor": "#1E8449", "color": "white", "border": 0, "padding": "9px 14px", "borderRadius": "5px", "cursor": "pointer"}),
            html.Button("Stop", id="btn-stop", style={"backgroundColor": "#922B21", "color": "white", "border": 0, "padding": "9px 14px", "borderRadius": "5px", "cursor": "pointer"}),
            dcc.Upload(id="upload-pcap", children=html.Button("Upload PCAP", style={"backgroundColor": "#1B4F72", "color": "white", "border": 0, "padding": "9px 14px", "borderRadius": "5px", "cursor": "pointer"})),
            html.Div(id="status-text", children="Status: Ready", style={"fontSize": "12px", "color": "#9FB3C8"})
        ]),
        dcc.Interval(id="interval", interval=3000, n_intervals=0, disabled=True),
        dcc.Store(id="store-selected-window", data=None),
        dcc.Store(id="store-selected-ip", data=None),
        dcc.Store(id="store-detected", data=[]),
        dcc.Store(id="store-windows", data=[]),
        dcc.Store(id="store-running", data=False),
    ])
])

# ============================================================
# CALLBACKS
# ============================================================
@app.callback(
    Output("interval", "disabled"), Output("status-text", "children"), Output("btn-start", "style"),
    Input("btn-start", "n_clicks"), Input("btn-stop", "n_clicks"), prevent_initial_call=True
)
def control_capture(start, stop):
    triggered = callback_context.triggered_id
    start_style = {"backgroundColor": "#1E8449", "color": "white", "border": 0, "padding": "9px 14px", "borderRadius": "5px", "cursor": "pointer"}
    running_style = {"backgroundColor": "#566573", "color": "white", "border": 0, "padding": "9px 14px", "borderRadius": "5px", "cursor": "not-allowed"}
    if triggered == "btn-start":
        state["running"] = True; state["detected"] = []; state["windows"] = []; state["window_count"] = 0
        state["packet_buffer"] = []; state["window_history"] = []; state["graph"] = None; state["window_details"] = []; state["window_graphs"] = []
        state["policies"] = []; state["selected_window"] = None
        state["local_ips"] = get_local_ips()
        threading.Thread(target=realtime_capture, daemon=True).start()
        return False, "Status: Live capture running", running_style
    state["running"] = False
    return True, "Status: Stopped", start_style


@app.callback(
    Output("network-graph", "figure"), Output("alert-list", "children"), Output("temporal-panel", "children"),
    Output("stat-ips", "children"), Output("stat-threats", "children"), Output("stat-windows", "children"),
    Output("stat-policies", "children"), Output("overall-status", "children"),
    Input("interval", "n_intervals"), Input("upload-pcap", "contents"), State("upload-pcap", "filename"), prevent_initial_call=False
)
def update_dashboard(n, pcap_contents, pcap_filename):
    triggered = callback_context.triggered[0]["prop_id"] if callback_context.triggered else ""
    if "upload-pcap" in triggered and pcap_contents:
        from scapy.all import PcapReader
        content_type, content_string = pcap_contents.split(",")
        decoded = base64.b64decode(content_string)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(decoded); tmp_path = tmp.name
        packets = []
        try:
            with PcapReader(tmp_path) as pcap:
                for packet in pcap:
                    if packet.haslayer(IP):
                        packets.append({"timestamp": float(getattr(packet, "time", 0)), "src": packet[IP].src,
                                        "dst": packet[IP].dst, "port": packet[TCP].dport if packet.haslayer(TCP) else 0})
        finally:
            os.unlink(tmp_path)
        state["local_ips"] = get_local_ips(); state["pcap_source"] = pcap_filename or "Uploaded PCAP"
        state["detected"] = []; state["windows"] = []; state["window_details"] = []; state["window_graphs"] = []; state["window_history"] = []; state["window_count"] = 0; state["policies"] = []
        for start in range(0, len(packets), WINDOW_SIZE):
            chunk = packets[start:start + WINDOW_SIZE]
            if chunk: process_window(chunk)
        state["status_message"] = f"Loaded {state['pcap_source']}"

    fig = build_plotly_figure(state["graph"], state["detected"])
    alert_cards = []
    for d in state["detected"][:12]:
        dtype, _ = device_info(d["ip"])
        alert_cards.append(html.Div(style={"backgroundColor": "#0D141C", "border": "1px solid #7B241C", "borderRadius": "6px", "padding": "9px", "marginBottom": "7px"}, children=[
            html.Div(d["attack_type"], style={"fontWeight": "600", "fontSize": "12px", "color": "#F1948A"}),
            html.Div(f"{dtype} | {d['ip']}", style={"fontSize": "11px", "color": "white", "marginTop": "3px"}),
            html.Div(f"Severity {d['severity']}/10 | Confidence {d['confidence']}%", style={"fontSize": "10px", "color": "#9FB3C8", "marginTop": "3px"}),
            html.Div(f"Recommended action: {recommendations.get(d['attack_type'], 'Investigate')}", style={"fontSize": "10px", "color": "#D5DEE7", "marginTop": "4px"})
        ]))
    if not alert_cards: alert_cards = [html.Div("No threats detected", style={"color": "#718096", "textAlign": "center", "padding": "25px 5px", "fontSize": "12px"})]

    window_boxes = []
    for w in state["windows"][-15:]:
        bg = "#7B241C" if w["status"] == "alert" else "#7D6608" if w["status"] == "warning" else "#1E8449"
        label = f"Window {w['window']}"
        window_boxes.append(html.Button(label, id={"type": "window-btn", "index": w["window"]}, title="; ".join(w["alerts"]) or "Normal", n_clicks=0,
            style={"backgroundColor": bg, "color": "white", "border": 0, "padding": "7px 10px", "borderRadius": "5px", "fontSize": "11px", "cursor": "pointer"}))
    if not window_boxes: window_boxes = [html.Div("No windows yet", style={"color": "#718096", "fontSize": "11px"})]
    if state["detected"]:
        threat_text = f"Status: {len(state['detected'])} threat(s) detected"
    else:
        threat_text = "Status: Network appears normal"
    if state["policies"]:
        threat_text += f" | {len(state['policies'])} simulated block policy active"
    return fig, alert_cards, window_boxes, str(state["total_ips"]), str(len(state["detected"])), str(state["window_count"]), str(len(state["policies"])), threat_text


@app.callback(
    Output("window-detail-panel", "style"), Output("window-detail-title", "children"), Output("window-time-range", "children"),
    Output("window-ip-table", "children"), Output("window-suspicious", "children"), Output("selected-device-info", "children"),
    Output("btn-block-ip", "style"), Output("btn-block-ip", "children"), Output("store-selected-window", "data"), Output("store-selected-ip", "data"),
    Output("network-graph", "figure", allow_duplicate=True), Input({"type": "window-btn", "index": ALL}, "n_clicks"), prevent_initial_call=True
)
def show_window_detail(n_clicks):
    if not n_clicks or not state["window_details"]: raise dash.exceptions.PreventUpdate
    triggered = callback_context.triggered_id
    if not isinstance(triggered, dict): raise dash.exceptions.PreventUpdate
    selected = next((w for w in state["window_details"] if w["window"] == triggered["index"]), None)
    if selected is None: raise dash.exceptions.PreventUpdate
    rows = []
    for ip, metrics in selected["ip_metrics"].items():
        ports = selected.get("ip_ports", {}).get(ip, [])
        dtype, desc = device_info(ip, metrics, ports)
        threat = next((d for d in selected["detected"] if d["ip"] == ip), None)
        label = f"{dtype} | {ip}"
        if threat: label += f" | {threat['attack_type']}"
        rows.append(html.Button(label, id={"type": "device-btn", "ip": ip, "window": selected["window"]}, n_clicks=0,
            style={"display": "block", "width": "100%", "textAlign": "left", "backgroundColor": "#151E28" if not threat else "#2A1515", "color": "#F4F6F7" if not threat else "#F1948A", "border": "1px solid #263544", "padding": "8px", "borderRadius": "4px", "marginBottom": "5px", "cursor": "pointer", "fontSize": "11px"}))
    suspicious = []
    for d in selected["detected"]:
        dtype, _ = device_info(d["ip"])
        suspicious.append(html.Div(style={"padding": "7px", "marginBottom": "5px", "backgroundColor": "#2A1515", "borderLeft": "3px solid #E74C3C"}, children=[
            html.Div(d["attack_type"], style={"fontWeight": "600", "fontSize": "11px", "color": "#F1948A"}),
            html.Div(f"{dtype} | {d['ip']}", style={"fontSize": "10px", "color": "#D5DEE7", "marginTop": "2px"})]))
    if not suspicious: suspicious = [html.Div("No suspicious activity in this period", style={"fontSize": "11px", "color": "#718096"})]
    start = format_packet_time(selected.get("start_time")) if selected.get("start_time") else "Unknown"
    end = format_packet_time(selected.get("end_time")) if selected.get("end_time") else "Unknown"
    first_ip = selected["detected"][0]["ip"] if selected["detected"] else next(iter(selected["ip_metrics"]), None)
    info = "Select a device above to see its role and traffic."
    if first_ip:
        metrics = selected["ip_metrics"].get(first_ip, {}); ports = selected.get("ip_ports", {}).get(first_ip, [])
        dtype, desc = device_info(first_ip, metrics, ports)
        info = html.Div([html.Div(dtype, style={"fontSize": "14px", "fontWeight": "600"}), html.Div(first_ip, style={"marginTop": "2px"}), html.Div(desc, style={"color": "#9FB3C8", "marginTop": "3px"}), html.Div(f"Incoming: {metrics.get('incoming',0)} | Outgoing: {metrics.get('outgoing',0)} | Connections: {metrics.get('unique_destinations',0)}", style={"marginTop": "5px", "fontSize": "11px"}),
            html.Button("Mark as my device", id="btn-mark-my-device", n_clicks=0, style={"marginTop": "8px", "backgroundColor": "#1B4F72", "color": "white", "border": 0, "padding": "6px 9px", "borderRadius": "4px", "cursor": "pointer", "fontSize": "11px"})])
    selected_threat = next((d for d in selected["detected"] if d["ip"] == first_ip), None)
    can_block = bool(selected_threat and is_blockable_attack(selected_threat["attack_type"]))
    block_style = {"backgroundColor": "#922B21", "color": "white", "border": 0, "padding": "8px 12px", "borderRadius": "5px", "cursor": "pointer"} if can_block else {"display": "none"}
    block_label = "Create block policy" if can_block else "Block selected IP"
    G_window = nx.DiGraph(); G_window.add_nodes_from(selected["graph_nodes"])
    for src, dst, data in selected["graph_edges"]: G_window.add_edge(src, dst, **data)
    return {"display": "block", "marginTop": "14px", "backgroundColor": "#111923", "border": "1px solid #263544", "borderRadius": "8px", "padding": "14px"}, f"Window {selected['window']} details", f"Packet time: {start} to {end}", rows, suspicious, info, block_style, block_label, selected["window"], first_ip, build_plotly_figure(G_window, selected["detected"])


@app.callback(
    Output("selected-device-info", "children", allow_duplicate=True), Output("store-selected-ip", "data", allow_duplicate=True),
    Input({"type": "device-btn", "ip": ALL, "window": ALL}, "n_clicks"), State("store-selected-window", "data"), prevent_initial_call=True
)
def select_device(n_clicks, selected_window):
    triggered = callback_context.triggered_id
    if not isinstance(triggered, dict) or selected_window is None: raise dash.exceptions.PreventUpdate
    window = next((w for w in state["window_details"] if w["window"] == selected_window), None)
    if not window: raise dash.exceptions.PreventUpdate
    ip = triggered["ip"]; metrics = window["ip_metrics"].get(ip, {}); ports = window.get("ip_ports", {}).get(ip, [])
    dtype, desc = device_info(ip, metrics, ports); threat = next((d for d in window["detected"] if d["ip"] == ip), None)
    return html.Div([html.Div(dtype, style={"fontSize": "14px", "fontWeight": "600", "color": "#F1948A" if threat else "#D5DEE7"}), html.Div(ip, style={"marginTop": "2px"}), html.Div(desc, style={"color": "#9FB3C8", "marginTop": "3px"}), html.Div(f"Incoming: {metrics.get('incoming',0)} | Outgoing: {metrics.get('outgoing',0)} | Unique destinations: {metrics.get('unique_destinations',0)}", style={"marginTop": "5px", "fontSize": "11px"}), html.Div(f"Detected: {threat['attack_type']}" if threat else "Status: No threat detected", style={"marginTop": "5px", "fontSize": "11px", "color": "#F1948A" if threat else "#82E0AA"}),
        html.Button("Mark as my device", id="btn-mark-my-device", n_clicks=0, style={"marginTop": "8px", "backgroundColor": "#1B4F72", "color": "white", "border": 0, "padding": "6px 9px", "borderRadius": "4px", "cursor": "pointer", "fontSize": "11px"})]), ip


@app.callback(
    Output("overall-status", "children", allow_duplicate=True),
    Output("selected-device-info", "children", allow_duplicate=True),
    Input("btn-mark-my-device", "n_clicks"),
    State("store-selected-ip", "data"),
    prevent_initial_call=True
)
def mark_my_device(n_clicks, selected_ip):
    if not n_clicks or not selected_ip:
        raise dash.exceptions.PreventUpdate
    state["user_device_ip"] = selected_ip
    state["local_ips"].add(selected_ip)
    return f"Status: {selected_ip} marked as your device", html.Div([
        html.Div("Your device", style={"fontSize": "14px", "fontWeight": "600", "color": "#82E0AA"}),
        html.Div(selected_ip, style={"marginTop": "2px"}),
        html.Div("This node is now identified as your computer in NetPulse.", style={"color": "#9FB3C8", "marginTop": "3px", "fontSize": "11px"})
    ])


@app.callback(
    Output("policy-list", "children"),
    Output("stat-policies", "children"),
    Input("btn-block-ip", "n_clicks"),
    Input("btn-clear-policies", "n_clicks"),
    Input("interval", "n_intervals"),
    State("store-selected-ip", "data"),
    State("store-selected-window", "data"),
    prevent_initial_call=False
)
def update_policies(block_clicks, clear_clicks, n, selected_ip, selected_window):
    triggered = callback_context.triggered_id
    if triggered == "btn-clear-policies": state["policies"] = []
    elif triggered == "btn-block-ip" and selected_ip:
        if not any(p["ip"] == selected_ip for p in state["policies"]):
            attack = None
            if selected_window is not None:
                window = next((w for w in state["window_details"] if w["window"] == selected_window), None)
                if window: attack = next((d for d in window["detected"] if d["ip"] == selected_ip), None)
            state["policies"].append({"ip": selected_ip, "action": "BLOCK", "reason": attack["attack_type"] if attack else "Manual block", "created": datetime.now().strftime("%H:%M:%S")})
    cards = []
    for p in state["policies"]:
        cards.append(html.Div(style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "gap": "10px", "backgroundColor": "#151E28", "border": "1px solid #263544", "borderRadius": "5px", "padding": "8px", "marginBottom": "6px"}, children=[
            html.Div([html.Div(f"BLOCK | {p['ip']}", style={"fontSize": "12px", "fontWeight": "600", "color": "#F1948A"}), html.Div(f"Reason: {p['reason']} | Created: {p['created']}", style={"fontSize": "10px", "color": "#9FB3C8", "marginTop": "2px"})])
        ]))
    if not cards: cards = [html.Div("No active policies", style={"color": "#718096", "fontSize": "11px", "padding": "8px 0"})]
    return cards, str(len(state["policies"]))


if __name__ == "__main__":
    print("Starting NetPulse Dashboard...")
    print("Open browser at: http://127.0.0.1:8050")
    app.run(debug=False)
