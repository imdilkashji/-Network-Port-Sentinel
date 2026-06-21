import json
import socket
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

TARGET_HOST = "127.0.0.1"
PORT_START = 1
PORT_END = 1024
MAX_WORKERS = 100

# Paste your webhook URL below.
DISCORD_WEBHOOK_URL = "PASTE_YOUR_WEBHOOK_URL_HERE"

def send_discord_alert(summary_data, open_ports):
    """Send the scan results to the configured Discord webhook."""
    if DISCORD_WEBHOOK_URL == "PASTE_YOUR_WEBHOOK_URL_HERE":
        print("[-] Skip Discord Notification: Webhook URL not configured.")
        return

    print("[*] Compiling telemetry metrics for Discord transmission...")

    # Turn discovered sockets into a compact markdown block.
    port_list_str = ""
    for p in open_ports:
        port_list_str += (
            f"• **Port {p['port']}** | Latency: {p['latency_ms']}ms\n"
            f"  └ *Identity:* `{p['service']}`\n"
        )

    if not port_list_str:
        port_list_str = "No active open ports discovered in this vector range."

    payload = {
        "username": "Network Sentinel Bot",
        "avatar_url": "https://i.imgur.com/w8R6K6E.png",
        "embeds": [
            {
                "title": "🛡️ Network Audit Security Report",
                "color": 3447003,  # Blue color hex code in decimal
                "fields": [
                    {"name": "Target Host", "value": f"`{summary_data['host']}`", "inline": True},
                    {
                        "name": "Scan Duration",
                        "value": f"`{summary_data['duration']:.2f}s`",
                        "inline": True,
                    },
                    {
                        "name": "Total Ports Audited",
                        "value": f"`{summary_data['total_scanned']}`",
                        "inline": False,
                    },
                    {"name": "Isolated Active Sockets", "value": port_list_str, "inline": False},
                ],
                "footer": {"text": "Automated Telemetry Pipeline | Stage 3 Active"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        ],
    }

    try:
        # Encode JSON for the webhook POST.
        data_bytes = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=data_bytes,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )

        with urllib.request.urlopen(req) as response:
            if response.status == 204 or response.status == 200:
                print("[+] Security metrics transmitted successfully to Discord channel.")
    except Exception as e:
        print(f"[-] API Transmission Failure: {e}")


def grab_service_banner(sock):
    """Try to grab a quick service banner from an already-open socket."""
    try:
        sock.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = sock.recv(1024)
        if banner:
            return (
                banner.decode("utf-8", errors="ignore")
                .replace("\r", "")
                .replace("\n", " ")
                .strip()
            )
    except Exception:
        pass

    return "UNKNOWN SERVICE (No Banner Returned)"


def audit_single_port(host, port):
    """Check if a single TCP port is open, and fingerprint the service if it is."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.6)
            start_time = time.time()
            result = sock.connect_ex((host, port))
            latency = (time.time() - start_time) * 1000

            if result == 0:
                service_fingerprint = grab_service_banner(sock)
                return {
                    "port": port,
                    "status": "OPEN",
                    "latency_ms": round(latency, 2),
                    "service": service_fingerprint,
                }
    except Exception:
        pass

    return {"port": port, "status": "CLOSED", "latency_ms": 0, "service": "NONE"}


def run_network_audit():
    print(f"[*] Initializing Day 3 Connected Sentinel against: {TARGET_HOST}")

    open_ports = []
    start_audit_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(audit_single_port, TARGET_HOST, port)
            for port in range(PORT_START, PORT_END + 1)
        ]
        for future in futures:
            metrics = future.result()
            if metrics["status"] == "OPEN":
                open_ports.append(metrics)
                print(
                    f"    [!] DISCOVERY: Port {metrics['port']} is {metrics['status']} | Latency: {metrics['latency_ms']}ms"
                )

    total_duration = time.time() - start_audit_time

    summary_data = {
        "host": TARGET_HOST,
        "duration": total_duration,
        "total_scanned": PORT_END - PORT_START + 1,
    }

    # Send the scan results to the webhook.
    send_discord_alert(summary_data, open_ports)
    print("[+] Processing loop finalized.")


if __name__ == "__main__":
    run_network_audit()
            "fields": [
                {"name": "Target Host", "value": f"`{summary_data['host']}`", "inline": True},
                {"name": "Scan Duration", "value": f"`{summary_data['duration']:.2f}s`", "inline": True},
                {"name": "Total Ports Audited", "value": f"`{summary_data['total_scanned']}`", "inline": False},
                {"name": "Isolated Active Sockets", "value": port_list_str, "inline": False}
            ],
            "footer": {"text": "Automated Telemetry Pipeline | Stage 3 Active"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }]
    }

    try:
        # Convert the Python dictionary into a JSON string and encode to raw bytes
        data_bytes = json.dumps(payload).encode('utf-8')
        
        # Build the HTTP Request with a proper Content-Type header
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL, 
            data=data_bytes, 
            headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
        )
        
        # Fire the HTTPS POST request to Discord's API
        with urllib.request.urlopen(req) as response:
            if response.status == 204 or response.status == 200:
                print("[+] Security metrics transmitted successfully to Discord channel.")
    except Exception as e:
        print(f"[-] API Transmission Failure: {e}")

def grab_service_banner(sock):
    """Attempts to read the initial service identification banner from an open socket."""
    try:
        sock.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = sock.recv(1024)
        if banner:
            return banner.decode('utf-8', errors='ignore').replace('\r', '').replace('\n', ' ').strip()
    except Exception:
        pass
    return "UNKNOWN SERVICE (No Banner Returned)"

def audit_single_port(host, port):
    """Performs a TCP connect handshake and fingerprints the underlying service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.6)
            start_time = time.time()
            result = sock.connect_ex((host, port))
            latency = (time.time() - start_time) * 1000
            
            if result == 0:
                service_fingerprint = grab_service_banner(sock)
                return {
                    "port": port, 
                    "status": "OPEN", 
                    "latency_ms": round(latency, 2),
                    "service": service_fingerprint
                }
    except Exception:
        pass
    return {"port": port, "status": "CLOSED", "latency_ms": 0, "service": "NONE"}

def run_network_audit():
    print(f"[*] Initializing Day 3 Connected Sentinel against: {TARGET_HOST}")
    
    open_ports = []
    start_audit_time = time.time()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(audit_single_port, TARGET_HOST, port) for port in range(PORT_START, PORT_END + 1)]
        for future in futures:
            metrics = future.result()
            if metrics["status"] == "OPEN":
                open_ports.append(metrics)
                print(f"    [!] DISCOVERY: Port {metrics['port']} is {metrics['status']} | Latency: {metrics['latency_ms']}ms")

    total_duration = time.time() - start_audit_time
    
    summary_data = {
        "host": TARGET_HOST,
        "duration": total_duration,
        "total_scanned": PORT_END - PORT_START + 1
    }
    
    # Trigger the automated webhook pipeline
    send_discord_alert(summary_data, open_ports)
    print(f"[+] Processing loop finalized.")

if __name__ == "__main__":
    run_network_audit()
