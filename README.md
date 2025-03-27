#  Network Monitoring and Vulnerability Analysis Using Prometheus, Scapy, and Nmap

## Overview

This Python script monitors network activity, detects open ports, performs OS fingerprinting, and analyzes packet traffic using various libraries such as `prometheus_client`, `Scapy`, and `Nmap`. It exposes system and network metrics via Prometheus for visualization and alerting through Grafana.

## Libraries Used

- `prometheus_client`: Provides an interface for exposing network and system metrics in Prometheus format.
- `scapy`: Captures network packets and extracts relevant information.
- `psutil`: Retrieves system and network information, such as active network interfaces, CPU, and memory usage.
- `socket`: Obtains system network details like IP addresses and MAC addresses.
- `nmap`: Performs port scanning and OS fingerprinting to identify active services and security vulnerabilities.
- `concurrent.futures`: Implements multithreading for efficient scanning and processing.
- `time`: Used for delays in monitoring functions.

## Features

1. **Real Device IP Detection**: Identifies active IP addresses and MAC addresses in the system.
2. **Port Scanning & Service Detection**: Scans open ports and determines running services.
3. **OS Fingerprinting**: Identifies the operating system of networked devices.
4. **Packet Sniffing & Protocol Analysis**: Captures network packets to analyze communication patterns.
5. **System Monitoring**: Tracks CPU, memory, and disk usage in real time.
6. **Network Usage Monitoring**: Measures network transmission and reception speeds.
7. **Vulnerability Risk Assessment**: Evaluates the security risk of detected open ports and services.
8. **Grafana Integration**: Uses collected Prometheus metrics for visualization and alerting in Grafana.

## Functions Explanation

### `get_real_device_ips()`

- Retrieves real device IPs and MAC addresses.
- Filters out loopback and virtual interfaces.
- Updates the `ip_count_gauge` Prometheus metric.

### `scan_ports_and_services(ip, mac, start_port, end_port)`

- Uses Nmap to scan open ports and running services.
- Updates the `open_ports_gauge` metric.
- Assesses vulnerability risks and updates the `vulnerability_risk_gauge` metric.

### `fingerprint_os(ip, interface)`

- Uses Nmap to perform OS fingerprinting.
- Identifies the OS family (Windows, Linux, MacOS) and updates the `detected_os_gauge` metric.

### `capture_packets_and_analyze(ip, open_ports)`

- Captures network packets using Scapy.
- Analyzes protocol types and updates the `packets_captured_details` metric.
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

1. The script starts a Prometheus metrics server on port 8000.
2. System monitoring runs in a separate thread.
3. Real device IPs are identified.
4. Network usage is measured.
5. Port scanning, OS fingerprinting, and vulnerability risk assessment are performed.
6. Packet capture and protocol analysis are executed.
7. The script runs in a loop to continuously monitor network activity.

## Prometheus and Grafana Integration

### **Setting Up Prometheus**

1. Download and install Prometheus from [https://prometheus.io/download/](https://prometheus.io/download/).
2. Extract the files and navigate to the Prometheus directory.
3. Ensure that the `prometheus.yml` configuration file in the Prometheus directory includes the following content:
   ```yaml
   scrape_configs:
     - job_name: 'network_monitor'
       static_configs:
         - targets: ['localhost:8000']
   ```
   *(Scrape interval is not explicitly defined.)*
4. Start Prometheus by navigating to the Prometheus directory and running:
   ```sh
   prometheus --config.file=prometheus.yml
   ```
5. Open `http://localhost:9090/` in your browser to access the Prometheus UI.
6. In the **Targets** section of the Prometheus UI, ensure that both `localhost:9090` and `localhost:8000` are listed as **UP**.

## Setting Up Grafana

1. **Download and Install Grafana**  
   - Visit [Grafana's official website](https://grafana.com/grafana/download) and download the appropriate version for your OS.  
   - Install and run Grafana (it runs continuously in the background).  

2. **Access Grafana in Your Browser**  
   - Open `http://localhost:3000/` in your web browser.  
   - Log in using the default credentials (`admin/admin`).  

3. **Add Prometheus as a Data Source**  
   - Go to **Configuration > Data Sources**.  
   - Click **Add data source** and select **Prometheus**.  
   - Set the **URL** to `http://localhost:9090/` and click **Save & Test**.  

---

## **Importing a Pre-Configured Grafana Dashboard**

If you want to import an existing Grafana dashboard from another system, follow these steps:

### **🔹 Export the Grafana Dashboard (From the Source PC)**
1. Open Grafana and navigate to the **dashboard you want to export**.  
2. Click on **"Dashboard Settings" (Gear Icon ⚙️) in the top-right corner**.  
3. Select **"JSON Model"** (Under "Settings").  
4. Click **"Download JSON"** to save the dashboard configuration.  
5. Share the JSON file (via email, GitHub, Google Drive, etc.).  

### **🔹 Import the Grafana Dashboard (On the Target PC)**
1. Ensure Grafana and Prometheus are installed and running.  
2. Open Grafana and go to **"Dashboards"** (Left Sidebar) → Click **"Import"**.  
3. Click **"Upload JSON File"** and select the file shared with you.  
4. Select the appropriate **Prometheus data source** before finalizing the import.  
5. Click **"Import"**, and the dashboard will be available with all its settings and visualizations.    


## Installation

### Prerequisites

- Python 3.13.1
- Prometheus
- Grafana
- Nmap (Must be installed manually with the `npcap` option enabled and added to environment variables)

### Steps

1. Clone the repository:

   ```sh
   git clone https://github.com/your-repo-name.git
   cd your-repo-name
   ```

2. Install required dependencies:

   ```sh
   pip install -r requirements.txt
   ```

3. Install Nmap manually:

   - Download Nmap from [https://nmap.org/download.html](https://nmap.org/download.html)
   - During installation, select the **NPcap** option.
   - Add Nmap to system environment variables.

4. Start Prometheus by navigating to its directory and running:

   ```sh
   prometheus --config.file=prometheus.yml
   ```

5. Start the Python script:

   ```sh
   python network_monitor.py
   ```

6. Open Grafana and configure Prometheus as a data source.

## Usage

- After running the script, visit `http://localhost:8000/metrics` to see the exposed Prometheus metrics.
- Configure Prometheus to scrape this endpoint.
- Use Grafana for visualization and monitoring.


