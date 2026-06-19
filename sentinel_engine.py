import socket
import time
from concurrent.futures import ThreadPoolExecutor

# Target host to scan (using localhost/loopback for completely safe testing)
TARGET_HOST = "127.0.0.1"
# Port range to audit
PORT_START = 1
PORT_END = 1024
# Maximum concurrent worker threads
MAX_WORKERS = 100

def audit_single_port(host, port):
    """Attempts a low-level TCP handshake with a target port."""
    try:
        # Create a raw stream socket using IPv4
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Set a tight timeout so slow ports don't block our threads
            sock.settimeout(0.5)
            start_time = time.time()
            result = sock.connect_ex((host, port))
            latency = (time.time() - start_time) * 1000
            
            if result == 0:
                return {"port": port, "status": "OPEN", "latency_ms": round(latency, 2)}
    except Exception:
        pass
    return {"port": port, "status": "CLOSED", "latency_ms": 0}

def run_network_audit():
    print(f"[*] Initializing Multi-Threaded Sentinel against target: {TARGET_HOST}")
    print(f"[*] Allocating {MAX_WORKERS} worker threads across ports {PORT_START}-{PORT_END}...")
    
    open_ports = []
    start_audit_time = time.time()
    
    # Spin up an asynchronous worker pool to process requests concurrently
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Map our port range to the worker pool
        futures = [executor.submit(audit_single_port, TARGET_HOST, port) for port in range(PORT_START, PORT_END + 1)]
        
        for future in futures:
            metrics = future.result()
            if metrics["status"] == "OPEN":
                open_ports.append(metrics)
                print(f"    [!] ALERT: Open Port Discovered -> Port {metrics['port']} | Latency: {metrics['latency_ms']}ms")

    total_duration = time.time() - start_audit_time
    
    # Generate the professional production report
    with open("network_audit_report.txt", "w") as report:
        report.write("=== MULTI-THREADED NETWORK SENTINEL AUDIT REPORT ===\n")
        report.write(f"Target Infrastructure Host : {TARGET_HOST}\n")
        report.write(f"Total Port Vectors Scanned  : {PORT_END - PORT_START + 1}\n")
        report.write(f"Total Execution Duration   : {total_duration:.2f} seconds\n")
        report.write(f"Active Workers Allocated   : {MAX_WORKERS}\n\n")
        report.write("--- DISCOVERED ACTIVE SOCKETS ---\n")
        if not open_ports:
            report.write("No open ports found within this range.\n")
        for p in open_ports:
            report.write(f"Port {p['port']} | Status: {p['status']} | Latency: {p['latency_ms']}ms\n")
            
    print(f"[+] Audit execution complete in {total_duration:.2f} seconds.")
    print(f"[*] Results exported to 'network_audit_report.txt'.")

if __name__ == "__main__":
    run_network_audit()



    