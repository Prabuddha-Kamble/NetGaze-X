
### Prometheus Integration
Prometheus is used to collect and expose network and system metrics. The script starts an HTTP server on port `8000`, where Prometheus can scrape the metrics.

### Installing and Configuring Prometheus
1. Download and install Prometheus from [https://prometheus.io/download/](https://prometheus.io/download/).
2. Modify the `prometheus.yml` file to include:
   ```yaml
   scrape_configs:
     - job_name: 'network_monitor'
       static_configs:
         - targets: ['localhost:8000']
   ```
3. Start Prometheus and open `http://localhost:9090` in a browser to view metrics.

## Running the Script
1. Install dependencies:
   ```bash
   pip install prometheus_client scapy psutil python-nmap
   ```
2. Run the script:
   ```bash
   python network_monitor.py
   ```
3. View Prometheus metrics at `http://localhost:8000/metrics`.

## Notes
- Ensure Prometheus is running before querying metrics.
- Adjust scanning ranges and intervals as needed to optimize performance.

This README provides all necessary details for setting up and running the network monitoring tool while integrating Prometheus. 

