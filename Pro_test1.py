from prometheus_client import Gauge, Counter, start_http_server
from scapy.all import sniff, IP, TCP, UDP
import psutil
import socket
import nmap
from concurrent.futures import ThreadPoolExecutor
import time

# Metrics to expose
ip_count_gauge = Gauge('real_device_ip_count', 'Number of real device IPs', ['ip', 'mac', 'interface'])
open_ports_gauge = Gauge('open_ports', 'Number of open ports', ['ip', 'mac', 'port', 'service'])
os_detection_counter = Counter('os_detection_attempts', 'Number of OS detection attempts', ['ip'])
detected_os_gauge = Gauge('detected_os', 'Detected OS by IP', ['ip', 'os', 'interface'])
packets_captured_details = Counter(
    'packets_captured_details',
    'Details of packets captured',
    ['source_ip', 'destination_ip', 'protocol_name', 'protocol_number', 'interface']
)

# Define the protocol analysis gauge to track open port analysis
protocol_analysis_gauge = Gauge(
    'protocol_analysis',
    'Protocol analysis for open ports',
    ['ip', 'port', 'protocol_name']
)

# Prometheus Gauges for tracking system stats
cpu_usage_gauge = Gauge("cpu_usage_percent", "CPU usage percentage")
memory_usage_gauge = Gauge("memory_usage_percent", "Memory usage percentage")
disk_usage_gauge = Gauge("disk_usage_percent", "Disk usage percentage")

# Prometheus Gauges for tracking network stats
network_receive_speed_gauge = Gauge("network_receive_speed_mbps", "Network receive speed in Mbps", ["interface"])
network_transmit_speed_gauge = Gauge("network_transmit_speed_mbps", "Network transmit speed in Mbps", ["interface"])

vulnerability_risk_gauge = Gauge('vulnerability_risk_level','Risk level of detected vulnerabilities',['ip', 'port', 'service', 'risk_level'])


# Protocol mapping for known protocol numbers
protocol_name_map = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6',
    89: 'OSPF',
    132: 'SCTP',
    253: 'DCCP',
    255: 'Reserved'
}

# Function to get real device IPs and MAC addresses
def get_real_device_ips():
    ip_addresses = {}
    interfaces = psutil.net_if_addrs()

    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:  # Only consider IPv4 addresses
                ip = addr.address
                if ip != "127.0.0.1" and not ip.startswith("169.254.") and 'vEthernet' not in interface and 'Loopback' not in interface:
                    mac = None
                    for addr in addrs:
                        if addr.family == psutil.AF_LINK:  # Get the MAC address
                            mac = addr.address
                    ip_addresses[ip] = {"interface": interface, "mac": mac}

                    # Update Prometheus metrics with individual IP details
                    ip_count_gauge.labels(ip=ip, mac=mac, interface=interface).set(1)

    return ip_addresses

# Function to scan ports and services
def scan_ports_and_services(ip, mac, start_port, end_port):
    scanner = nmap.PortScanner()
    scanner.scan(ip, f'{start_port}-{end_port}', arguments='-sV --min-rate 5000')
    open_ports = []
    for protocol in scanner[ip].all_protocols():
        for port in scanner[ip][protocol].keys():
            state = scanner[ip][protocol][port]['state']
            service = scanner[ip][protocol][port].get('name', 'Unknown')
            if state == 'open':
                open_ports.append({"port": port, "service": service})

                # Calculate risk score and update Prometheus
                risk_info = calculate_risk_score(port, service)
                vulnerability_risk_gauge.labels(
                    ip=ip, port=port, service=service, risk_level=risk_info['risk_level']
                ).set(risk_info['calculated_risk'])

                open_ports_gauge.labels(ip=ip, mac=mac, port=port, service=service).set(1)
    return open_ports


# Function to perform OS fingerprinting using nmap
def fingerprint_os(ip, interface):
    scanner = nmap.PortScanner()
    os_detection_counter.labels(ip=ip).inc()  # Increment OS detection attempts for the IP
    try:
        scanner.scan(ip, arguments="-O")
        detected_os = None
        if 'osclass' in scanner[ip]:
            os_classes = scanner[ip]['osclass']
            for os_class in os_classes:
                os_family = os_class['osfamily']
                if os_family in ["Windows", "Linux", "MacOS"]:
                    detected_os = os_family
                    break
        if not detected_os and 'osmatch' in scanner[ip]:
            os_matches = scanner[ip]['osmatch']
            for os_match in os_matches:
                name = os_match['name']
                if "Windows" in name:
                    detected_os = "Windows"
                elif "Linux" in name:
                    detected_os = "Linux"
                elif "Mac OS" in name or "MacOS" in name:
                    detected_os = "MacOS"
                if detected_os:
                    break
        if detected_os:
            # Update OS info in Prometheus
            detected_os_gauge.labels(ip=ip, os=detected_os, interface=interface).set(1)
        else:
            print(f"OS not detected or unknown for IP {ip}.")
    except Exception as e:
        print(f"Error occurred while performing OS fingerprinting for IP {ip}: {e}")

# Function to capture packets and analyze protocols for open ports
def capture_packets_and_analyze(ip, open_ports):
    def process_packet(packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto_number = packet[IP].proto
                proto_name = protocol_name_map.get(proto_number, f"Unknown({proto_number})")
                
                # Increment captured packet count for Prometheus
                packets_captured_details.labels(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol_name=proto_name,
                    protocol_number=str(proto_number),
                    interface='any'  # You may change it based on the interface
                ).inc()
                
                # Protocol analysis for open ports
                for open_port in open_ports:
                    if proto_name in ['TCP', 'UDP']:
                        # Add the protocol analysis metric
                        protocol_analysis_gauge.labels(ip=ip, port=open_port['port'], protocol_name=proto_name).inc()
                
                print(f"Captured Packet: Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto_name}({proto_number})")
        except Exception as e:
            print(f"Error processing packet: {e}")

    print(f"Starting packet capture on IP: {ip}")
    try:
        sniff(filter="ip", prn=process_packet, timeout=10)  # Capture packets for 10 seconds
    except PermissionError:
        print("Permission denied. Please run the script as root or with administrative privileges.")
    except Exception as e:
        print(f"Error occurred during packet capture for IP {ip}: {e}")

# Function to get network usage and expose metrics
def get_network_usage():
    previous_stats = psutil.net_io_counters(pernic=True)
    time.sleep(1)  # Wait for 1 second to calculate speed
    current_stats = psutil.net_io_counters(pernic=True)

    active_interfaces = set()

    for interface, current_data in current_stats.items():
        if interface in previous_stats:
            prev_data = previous_stats[interface]
            
            # Calculate speeds (in Mbps)
            received_speed_mbps = ((current_data.bytes_recv - prev_data.bytes_recv) * 8) / 1_000_000
            transmit_speed_mbps = ((current_data.bytes_sent - prev_data.bytes_sent) * 8) / 1_000_000

            if received_speed_mbps > 0 or transmit_speed_mbps > 0:
                # Update Prometheus metrics for active interfaces
                network_receive_speed_gauge.labels(interface).set(received_speed_mbps)
                network_transmit_speed_gauge.labels(interface).set(transmit_speed_mbps)
                active_interfaces.add(interface)

    # Ensure only active interfaces remain in the Prometheus metrics
    for interface_label in list(network_receive_speed_gauge._metrics.keys()):
        interface_name = interface_label[0]  # Extract interface name from the labels
        if interface_name not in active_interfaces:
            network_receive_speed_gauge.remove(interface_name)
            network_transmit_speed_gauge.remove(interface_name)

# Function to monitor system stats (CPU, memory, disk usage)
def monitor_system_stats():
    while True:
        # Get CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        cpu_usage_gauge.set(cpu_usage)

        # Get memory usage
        memory_info = psutil.virtual_memory()
        memory_usage_gauge.set(memory_info.percent)

        # Get disk usage
        disk_info = psutil.disk_usage('/')
        disk_usage_gauge.set(disk_info.percent)

        # Wait before updating metrics again
        time.sleep(5)

def calculate_risk_score(port, service):
    # Known vulnerabilities with associated risks
    known_vulnerabilities = {
        445: {"name": "EternalBlue (SMB RCE)", "cve": "CVE-2017-0144", "risk": 10},
        3389: {"name": "BlueKeep (RDP RCE)", "cve": "CVE-2019-0708", "risk": 9},
        80: {"name": "Apache Struts RCE", "cve": "CVE-2017-5638", "risk": 8},
        3306: {"name": "MySQL Auth Bypass", "cve": "CVE-2012-2122", "risk": 7},
        22: {"name": "OpenSSH Enumeration", "cve": "CVE-2018-15473", "risk": 6},
        443: {"name": "Heartbleed (TLS Leak)", "cve": "CVE-2014-0160", "risk": 9},
        8080: {"name": "Jenkins RCE", "cve": "CVE-2017-1000353", "risk": 7},
        1099: {"name": "Java RMI RCE", "cve": "CVE-2017-3241", "risk": 8},
        1433: {"name": "SQL Injection MSSQL", "cve": "CVE-2019-1068", "risk": 7},
        8009: {"name": "Tomcat Ghostcat RCE", "cve": "CVE-2020-1938", "risk": 8},
        8443: {"name": "Log4Shell (Java RCE)", "cve": "CVE-2021-44228", "risk": 10},
        25: {"name": "SMTP Email Spoofing", "cve": "N/A", "risk": 5},
        5900: {"name": "VNC Server Vulnerability", "cve": "N/A", "risk": 6},
        53: {"name": "DNS Amplification Attack", "cve": "N/A", "risk": 7},
        161: {"name": "SNMP Weak Config", "cve": "N/A", "risk": 5},
        23: {"name": "Telnet Unencrypted", "cve": "N/A", "risk": 4},
        21: {"name": "FTP Anonymous Access", "cve": "N/A", "risk": 4},
        137: {"name": "NetBIOS Info Leak", "cve": "N/A", "risk": 5},
        514: {"name": "R Services Exploit", "cve": "N/A", "risk": 6},
    }

    # Default values for unknown ports
    base_risk = known_vulnerabilities.get(port, {}).get("risk", 3)  # Use default risk = 3 for unknown ports
    
    # Service-based risk adjustments
    service_risk_factors = {
        "http": 2, "ftp": 2, "telnet": 3, "smtp": 2,
        "mysql": 2, "rdp": 3, "ssh": 2, "smb": 3
    }
    service_risk = service_risk_factors.get(service.lower(), 1)  # Assign risk, default to 1 if unknown

    # Final Risk Score Calculation
    risk_score = base_risk + service_risk

    # Ensuring the risk score is within 1-10 range
    risk_score = min(risk_score, 10)

    # Assigning risk levels based on score
    if risk_score >= 7:
        risk_level = "High"
    elif risk_score >= 4:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "port": port,
        "service": service,
        "calculated_risk": risk_score,
        "risk_level": risk_level
    }

# Main function
if __name__ == "__main__":
    # Start Prometheus metrics server
    start_http_server(8000)

    # Start system stats monitoring in a separate thread
    from threading import Thread
    Thread(target=monitor_system_stats, daemon=True).start()

    # Define Prometheus metric for NT vulnerability risk
    nt_vulnerability_gauge = Gauge(
        'nt_vulnerability_risk_score',
        'Risk score of open ports based on NT vulnerability scanning',
        ['ip', 'port', 'service', 'risk_level']
    )

    while True:
        real_device_ips = get_real_device_ips()
        get_network_usage()  # Monitor network usage

        if real_device_ips:
            for ip, info in real_device_ips.items():
                interface = info['interface']
                mac = info['mac']
                print(f"\nInterface: {interface}, IP Address: {ip}, MAC Address: {mac}")

                # Perform port scanning
                total_ports = 65535
                port_ranges = [(start, min(start + 999, total_ports)) for start in range(1, total_ports + 1, 1000)]
                open_ports = []

                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [
                        executor.submit(scan_ports_and_services, ip, mac, start, end)
                        for start, end in port_ranges
                    ]
                    for future in futures:
                        result = future.result()
                        if result:
                            open_ports.extend(result)

                # Calculate NT vulnerability risk scores
                if open_ports:
                    print("\nDetected Open Ports and Risk Levels:")
                    for port_info in open_ports:
                        port = port_info["port"]
                        service = port_info["service"]

                        # Calculate risk score
                        risk_info = calculate_risk_score(port, service)
                        risk_score = risk_info["calculated_risk"]
                        risk_level = risk_info["risk_level"]

                        # Print risk details
                        print(f"Port: {port}, Service: {service}, Risk Score: {risk_score}, Risk Level: {risk_level}")

                        # Update Prometheus gauge with vulnerability data
                        nt_vulnerability_gauge.labels(
                            ip=ip, port=port, service=service, risk_level=risk_level
                        ).set(risk_score)

                # Perform OS fingerprinting for the IP
                fingerprint_os(ip, interface)

                # Perform packet capturing and protocol analysis for all open ports
                capture_packets_and_analyze(ip, open_ports)

        else:
            print("No real network interfaces found.")

        print("\nWaiting for the next scan interval...\n")

