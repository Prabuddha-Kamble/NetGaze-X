# Network Monitoring and Vulnerability Analysis Using Prometheus, Scapy, and Nmap

## Overview
This Python script monitors network activity, detects open ports, performs OS fingerprinting, and analyzes packet traffic using various libraries such as `Prometheus_client`, `Scapy`, and `Nmap`. It exposes system and network metrics via Prometheus for visualization and alerting.

## Libraries Used

- **`prometheus_client`**: Provides an interface for exposing network and system metrics in Prometheus format.
- **`scapy`**: Captures network packets and extracts relevant information.
- **`psutil`**: Retrieves system and network information, such as active network interfaces, CPU, and memory usage.
- **`socket`**: Obtains system network details like IP addresses and MAC addresses.
- **`nmap`**: Performs port scanning and OS fingerprinting to identify active services and security vulnerabilities.
- **`concurrent.futures`**: Implements multithreading for efficient scanning and processing.
- **`time`**: Used for delays in monitoring functions.

## Features

1. **Real Device IP Detection**: Identifies active IP addresses and MAC addresses in the system.
2. **Port Scanning & Service Detection**: Scans open ports and determines running services.
3. **OS Fingerprinting**: Identifies the operating system of networked devices.
4. **Packet Sniffing & Protocol Analysis**: Captures network packets to analyze communication patterns.
5. **System Monitoring**: Tracks CPU, memory, and disk usage in real time.
6. **Network Usage Monitoring**: Measures network transmission and reception speeds.
7. **Vulnerability Risk Assessment**: Evaluates the security risk of detected open ports and services.

## Functions Explanation

### `get_real_device_ips()`
- Retrieves real device IPs and MAC addresses.
- Filters out loopback and virtual interfaces.
- Updates the `ip_count_gauge` Prometheus metric.

### `scan_ports_and_services(ip, mac, start_port, end_port)`
- Uses `nmap` to scan open ports and running services.
- Updates the `open_ports_gauge` metric.
- Assesses vulnerability risks and updates the `vulnerability_risk_gauge` metric.

### `fingerprint_os(ip, interface)`
- Uses `nmap` to perform OS fingerprinting.
- Identifies the OS family (Windows, Linux, MacOS) and updates the `detected_os_gauge` metric.

### `capture_packets_and_analyze(ip, open_ports)`
- Captures network packets using `scapy`.
- Analyzes protocol types and updates `packets_captured_details` metric.
- Associates protocols with detected open ports using `protocol_analysis_gauge`.

### `get_network_usage()`
- Monitors network transmission and reception speeds.
- Updates `network_receive_speed_gauge` and `network_transmit_speed_gauge` metrics.

### `monitor_system_stats()`
- Continuously tracks CPU, memory, and disk usage.
- Updates corresponding Prometheus metrics every 5 seconds.

### `calculate_risk_score(port, service)`
- Assigns risk levels based on known vulnerabilities.
- Returns a dictionary with calculated risk values.

## Execution Flow
1. The script starts a Prometheus metrics server on port `8000`.
2. System monitoring runs in a separate thread.
3. Real device IPs are identified.
4. Network usage is measured.
5. Port scanning, OS fingerprinting, and vulnerability risk assessment are performed.
6. Packet capture and protocol analysis are executed.
7. The script runs in a loop to continuously monitor network activity.

## Prometheus Integration
1. Start the script to expose metrics at `http://localhost:8000/metrics`.
2. Configure Prometheus to scrape data from this endpoint.
3. Use Grafana for visualization and alerting based on collected metrics.


