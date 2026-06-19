# Network-Port-Sentinel: High-Concurrency Network Diagnostic Engine

A multi-threaded systems optimization utility designed to audit local network ports, map open network sockets, and measure latency using concurrent thread pools.

## Core Mechanics
- **Asynchronous Work Pools:** Utilizes Python's `concurrent.futures` to manage multiple parallel socket operations.
- **Low-Level Socket Handshakes:** Establishes TCP connect requests directly to network targets.
- **Performance Logging:** Captures connection anomalies and measures performance metrics.