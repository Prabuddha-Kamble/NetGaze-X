# NetGazeX Installation Guide for Kali Linux

## Prerequisites
Ensure you are running Kali Linux and have access to the terminal with sudo privileges.

## Step 1: Install Python
```bash
sudo apt update && sudo apt install python3 python3-pip -y
```

## Step 2: Install Prometheus
Prometheus must be installed manually before installing the `prometheus-client` dependency.

### Option 1: Download the Latest Version Automatically
```bash
wget $(curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest | grep "browser_download_url.*linux-amd64.tar.gz" | cut -d '"' -f 4)
```

### Option 2: Download a Specific Version (Recommended)
Check the latest Prometheus versions here: [Prometheus Releases](https://github.com/prometheus/prometheus/releases)

Then download a specific version, e.g., v2.51.2:
```bash
wget https://github.com/prometheus/prometheus/releases/download/v2.51.2/prometheus-2.51.2.linux-amd64.tar.gz
```

### Extract and Install Prometheus
After downloading, extract and move it to `/usr/local/bin`:
```bash
tar -xvf prometheus-2.51.2.linux-amd64.tar.gz
cd prometheus-2.51.2.linux-amd64
sudo mv prometheus promtool /usr/local/bin/
```
Then check if it's installed:
```bash
prometheus --version
```

## Step 3: Configure Prometheus
Modify the Prometheus YAML configuration file to scrape data from NetGazeX on port 8000.

1. Open the Prometheus configuration file:
   ```bash
   sudo nano /etc/prometheus/prometheus.yml
   ```
2. Add the following job under `scrape_configs`:
   ```yaml
   scrape_configs:
     - job_name: 'netgazex'
       static_configs:
         - targets: ['localhost:8000']
   ```
3. Save and exit (`CTRL+X`, then `Y`, then `ENTER`).

## Step 4: Install Python Dependencies (Handling System Break Issues)
While installing dependencies, you may encounter errors due to missing dependencies or system conflicts. To resolve these:

1. Install all dependencies using the `--break-system-packages` flag, as Kali Linux may block installations due to system integrity checks:
   ```bash
   pip install scapy prometheus-client psutil socket nmap concurrent.futures time --break-system-packages
   ```
2. **Warning:** Using `--break-system-packages` allows pip to override system-installed packages, which may lead to unexpected behavior or conflicts with system tools.
3. If any dependency still fails, try installing them one by one:
   ```bash
   pip install scapy --break-system-packages
   pip install psutil --break-system-packages
   pip install socket --break-system-packages
   pip install nmap --break-system-packages
   pip install concurrent.futures --break-system-packages
   pip install time --break-system-packages
   ```

## Step 5: Install and Start Grafana

### 1️⃣ Add the Grafana Repository
```bash
sudo apt update
sudo apt install -y software-properties-common
```
Then, add the Grafana APT repository:
```bash
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
```

### 2️⃣ Add the Correct Grafana GPG Key
```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://packages.grafana.com/gpg.key | sudo tee /etc/apt/keyrings/grafana.asc > /dev/null
```

### 3️⃣ Add the Grafana APT Repository
```bash
echo "deb [signed-by=/etc/apt/keyrings/grafana.asc] https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
```

### 4️⃣ Update the Package List Again
```bash
sudo apt update
```

### 5️⃣ Install Grafana
```bash
sudo apt install -y grafana
```

### 6️⃣ Start and Enable Grafana
```bash
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```
Check if Grafana is running:
```bash
sudo systemctl status grafana-server
```

### 7️⃣ Access Grafana UI
Grafana runs on port 3000. Open your browser and go to:
```bash
http://localhost:3000
```
Default login credentials:
- **Username:** admin
- **Password:** admin (you’ll be asked to change it)

## Step 6: Start Services and Run NetGazeX
To run the project smoothly:
1. Start Prometheus:
   ```bash
   prometheus --config.file=/etc/prometheus/prometheus.yml &
   ```
2. Run NetGazeX with root privileges (needed for packet capture):
   ```bash
   sudo python3 netgazex.py
   ```

Now, NetGazeX should be running successfully, and metrics should be visible in Prometheus and Grafana.

## Notes
- Ensure Prometheus is running before starting NetGazeX.
- Use `sudo` while running NetGazeX to allow packet capture.
- Configure Grafana to visualize data from Prometheus.
- **Be cautious when using `--break-system-packages`, as it may cause conflicts with Kali Linux's package manager.**

---


