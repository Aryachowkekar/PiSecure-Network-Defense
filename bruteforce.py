from scapy.all import sniff, TCP, IP, Raw
import logging
from collections import defaultdict
from datetime import datetime, timedelta
import sys
import nmap
import json

# Configure logging
LOG_FILE_TXT = "intrusion_log.txt"
LOG_FILE_JSON = "intrusion_log.json"

logging.basicConfig(
    filename=LOG_FILE_TXT,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Parameters
THRESHOLD = 10  # Max failed attempts per minute
attempts = defaultdict(list)  # Tracks failed attempts
active_connections = set()  # Tracks established connections
auth_success_keywords = {
    21: "230 Login successful",  # FTP success message
    22: "SSH_AUTH_SUCCESS",      # SSH success indicator (if available in payload)
}

monitored_ports = []  # Define globally to avoid undefined reference

def log_alert(alert_type, src_ip, details):
    """Log alerts to JSON file for dashboard display."""
    alert_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "source_ip": src_ip,
        "details": details,
    }
    
    # Live output to dashboard
    print(f"[{alert_type}] {src_ip}: {details}")
    logging.info(json.dumps(alert_data))  # Log to intrusion_log.txt

    # Append to JSON log file for dashboard integration
    try:
        with open(LOG_FILE_JSON, "a") as log_file:
            json.dump(alert_data, log_file)
            log_file.write("\n")
    except Exception as e:
        print(f"Error writing to JSON log file: {e}")

def scan_network():
    """Scan the network to detect connected devices and open ports."""
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.0.0/24', arguments='-p 1-1024')  # Scan first 1024 ports
    devices = []

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            device = {
                'ip': host,
                'ports': []
            }
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    device['ports'].append(port)
            devices.append(device)

    return devices

def detect_intrusions(packet):
    """Callback function to process sniffed packets."""
    global monitored_ports

    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags

        payload = None
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                payload = None  # Ignore decoding errors

        now = datetime.now()

        # Monitor only detected open ports
        if dst_port in monitored_ports:
            if flags & 2:  # SYN flag set (connection attempt)
                attempts[src_ip].append(now)
                # Filter attempts in the last minute
                attempts[src_ip] = [
                    time for time in attempts[src_ip] if now - time < timedelta(minutes=1)
                ]
                if len(attempts[src_ip]) > THRESHOLD:
                    alert_msg = f"Bruteforce attack detected on port {dst_port}"
                    log_alert("Bruteforce Attack", src_ip, alert_msg)

            elif flags & 16:  # ACK flag set (part of handshake)
                if (src_ip, dst_port) not in active_connections:
                    handshake_msg = f"TCP handshake completed by {src_ip} on port {dst_port}"
                    log_alert("Handshake", src_ip, handshake_msg)
                    active_connections.add((src_ip, dst_port))

            # Check for application-level login success in payload
            if payload and dst_port in auth_success_keywords:
                if auth_success_keywords[dst_port] in payload:
                    success_msg = f"Successful authentication by {src_ip} on port {dst_port}"
                    log_alert("Auth Success", src_ip, success_msg)

if __name__ == "__main__":
    # Scan the network for connected devices and open ports
    devices = scan_network()
    for device in devices:
        print(f"Device: {device['ip']}, Open Ports: {device['ports']}")
        monitored_ports.extend(device['ports'])

    # Remove duplicate ports
    monitored_ports = list(set(monitored_ports))

    print(f"🔍 Monitoring for intrusions on ports: {monitored_ports}")
    logging.info(f"🔍 Intrusion detection started on ports: {monitored_ports}")

    # Start sniffing packets
    try:
        sniff(filter="tcp", prn=detect_intrusions, store=0)
    except KeyboardInterrupt:
        print("🛑 Exiting IDS...")
        logging.info("🛑 IDS stopped by user.")