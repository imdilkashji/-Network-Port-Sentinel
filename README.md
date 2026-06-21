# 🛡️ Network-Port-Sentinel: High-Concurrency Telemetry Engine

Network-Port-Sentinel is a high-performance network security and diagnostic utility written in pure Python. It uses multi-threaded worker pools to audit network ports concurrently, determine open socket states, extract service identities, and transmit real-time styled telemetry alerts to remote webhooks over HTTPS.

---

## 🧠 Core Engineering Logic & System Mechanics

To understand why this system is designed this way, we must break down its architectural logic into three specific engineering components:

### 1. Asynchronous Task Concurrency (The Thread Pool)
In a traditional linear program, scanning $1,024$ network ports sequentially would require waiting for each connection attempt to finish or hit its timeout limit before moving to the next. If each connection takes $0.6$ seconds, a sequential run would waste over **10 minutes**.

This sentinel utilizes Python's `ThreadPoolExecutor` to spin up a worker pool of up to **100 parallel execution threads**. Instead of wasting processing cycles while waiting on network network latency, our script distributes the tasks across parallel workers. This drops total audit duration to **under 7 seconds** for over a thousand vectors.

### 2. Low-Level Network Handshakes (`socket`)
The system interfaces directly with the operating system's network layer using a raw TCP stream setup (`socket.AF_INET`, `socket.SOCK_STREAM`).
* **`connect_ex(host, port)`:** Instead of using standard `connect()` which throws system errors when a port is closed, we utilize `connect_ex()`. This returns a raw kernel status code. If it returns `0`, the socket successfully completed the classic **TCP 3-Way Handshake** (SYN -> SYN-ACK -> ACK), proving the port is actively listening.

### 3. Service Fingerprinting (Banner Grabbing)
Once a port is verified as open, the system runs an advanced sub-routine to capture a service fingerprint. It transmits an application-layer probe packet (`HEAD / HTTP/1.1\r\n\r\n`) into the open socket and reads the incoming byte buffer stream (`sock.recv(1024)`). If the underlying application returns a raw system version header, the engine catches, sanitizes, and decodes it.

### 4. REST API Integration (Webhooks)
To achieve real-time alerting without requiring external dependency installations (like `requests`), the script uses native Python networking (`urllib.request`). It builds a complex multi-layered data map, compiles it into an industry-standard **JSON payload** (`json.dumps()`), and streams it over HTTPS using a raw POST method straight to a remote web server.

---

## 🚀 Step-by-Step Local Machine Setup

Follow these exact steps from scratch to install, configure, and execute this network engine on your local computer.

### Prerequisites
* Ensure you have **Python 3.x** installed on your system. You can verify this by running `python --version` inside your terminal window.

### Step 1: Set Up Your Project Directory
Create a folder named `Network-Port-Sentinel` on your computer. Inside that folder, ensure you have these two essential files:
1. `sentinel_engine.py` (The main Python execution script).
2. `README.md` (This documentation guide).

### Step 2: Generate Your Secure Discord Webhook URL
A webhook allows our code to push automatic alert streams straight to your private chat channel.
1. Open your Discord application and navigate to a server where you possess administrative control.
2. Right-click an active text channel (e.g., `#general`) and select **Edit Channel**.
3. Click on the **Integrations** tab from the left sidebar panel.
4. Click on the **Webhooks** menu option, then click **New Webhook**.
5. Copy the automatically generated endpoint link by clicking the **Copy Webhook URL** button.

### Step 3: Inject the Webhook URL into Your Code
1. Open `sentinel_engine.py` using your preferred text editor (like Notepad or VS Code).
2. Find the line in your script that looks like this:
   ```python
   DISCORD_WEBHOOK_URL = "PASTE_YOUR_WEBHOOK_URL_HERE"
3. Replace the placeholder text with your actual copied Discord URL string. Ensure your full URL remains safely enclosed inside the double quotes.
4.Save the file.
