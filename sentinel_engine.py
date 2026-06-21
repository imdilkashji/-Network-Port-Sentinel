import socket
import time
from concurrent.futures import ThreadPoolExecutor

TARGET_HOST = "127.0.0.1"
PORT_START = 1
PORT_END = 1024
MAX_WORKERS = 100

def grab_service_banner(sock):
    """Attempts to read the initial service identification banner from an open socket."""
    try:
        # Send a basic application-layer probe in case the service waits for user input
        sock.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
        # Read the first 1024 bytes of the response stream
        banner = sock.recv(1024)
        if banner:
            # Clean up the output string by removing formatting artifacts
            return banner.decode('utf-8', errors='ignore').replace('\r', '').replace('\n', ' ').strip()
    except Exception:
        pass
    return "UNKNOWN SERVICE (No Banner Returned)"

def audit_single_port(host, port):
    """Performs a TCP connect handshake and fingerprints the underlying service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.6) # Slightly higher timeout to give slow banners time to reply
            start_time = time.time()
            result = sock.connect_ex((host, port))
            latency = (time.time() - start_time) * 1000
            
            if result == 0:
                # Port is open, immediately trigger our service identification sub-routine
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
    print(f"[*] Initializing Day 2 Concurrency Sentinel against: {TARGET_HOST}")
    print(f"[*] Fingerprinting services across ports {PORT_START}-{PORT_END} using {MAX_WORKERS} workers...")
    
    open_ports = []
    start_audit_time = time.time()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(audit_single_port, TARGET_HOST, port) for port in range(PORT_START, PORT_END + 1)]
        
        for future in futures:
            metrics = future.result()
            if metrics["status"] == "OPEN":
                open_ports.append(metrics)
                print(f"    [!] DISCOVERY: Port {metrics['port']} is {metrics['status']} | Latency: {metrics['latency_ms']}ms")
                print(f"        └─ Service Identity: {metrics['service']}")

    total_duration = time.time() - start_audit_time
    
    # Update the production audit report on disk
    with open("network_audit_report.txt", "w" , encoding="utf-8") as report:
        report.write("=== ADVANCED NETWORK SENTINEL SYSTEM AUDIT REPORT ===\n")
        report.write(f"Target Infrastructure Host : {TARGET_HOST}\n")
        report.write(f"Total Port Vectors Audited  : {PORT_END - PORT_START + 1}\n")
        report.write(f"Total Execution Duration   : {total_duration:.2f} seconds\n\n")
        report.write("--- DISCOVERED ACTIVE SOCKETS & FINGERPRINTS ---\n")
        if not open_ports:
            report.write("No open ports found within this range.\n")
        for p in open_ports:
            report.write(f"Port {p['port']} | Latency: {p['latency_ms']}ms\n")
            report.write(f"  └─ Service Signature: {p['service']}\n\n")
            
    print(f"[+] Audit complete. Advanced system mapping written to 'network_audit_report.txt'.")

if __name__ == "__main__":
    run_network_audit()