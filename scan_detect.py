from scapy.all import sniff, TCP, IP, ICMP
import logging
import json
from collections import defaultdict
from datetime import datetime, timedelta
import os

# Configure logging to integrate with Monitor IDS
LOG_FILE_TXT = "intrusion_log.txt"
LOG_FILE_JSON = "intrusion_log.json"

logging.basicConfig(
    filename=LOG_FILE_TXT,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Parameters
PORT_SCAN_THRESHOLD = 20  # Increased threshold to reduce false positives
SCAN_WINDOW = 10  # Increased time window to group SYN packets
TRUSTED_IPS_FILE = "trusted_ips.json"  # File to store trusted IPs

# Load trusted IPs from file
def load_trusted_ips():
    """Load trusted IPs from a JSON file."""
    if os.path.exists(TRUSTED_IPS_FILE):
        try:
            with open(TRUSTED_IPS_FILE, "r") as file:
                return set(json.load(file))
        except Exception as e:
            print(f"Error loading trusted IPs: {e}")
            return set()
    else:
        # Create an empty file if it doesn't exist
        with open(TRUSTED_IPS_FILE, "w") as file:
            json.dump([], file)
        return set()

# Save trusted IPs to file
def save_trusted_ips(trusted_ips):
    """Save trusted IPs to a JSON file."""
    try:
        with open(TRUSTED_IPS_FILE, "w") as file:
            json.dump(list(trusted_ips), file)
    except Exception as e:
        print(f"Error saving trusted IPs: {e}")

# Initialize trusted IPs
trusted_ips = load_trusted_ips()

scan_attempts = defaultdict(list)  # Tracks TCP scan attempts
icmp_attempts = defaultdict(list)  # Tracks ICMP (ping) attempts

def log_alert(alert_type, src_ip, dst_ip, details):
    """Log alerts to JSON file for dashboard display."""
    alert_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "details": details,
    }
    
    # Live output to dashboard
    print(f"[{alert_type}] {src_ip} -> {dst_ip}: {details}")
    logging.info(json.dumps(alert_data))  # Log to intrusion_log.txt

    # Append to JSON log file for dashboard integration
    try:
        with open(LOG_FILE_JSON, "a") as log_file:
            json.dump(alert_data, log_file)
            log_file.write("\n")
    except Exception as e:
        print(f"Error writing to JSON log file: {e}")

def detect_port_scan(packet):
    """Detect different types of port scanning and ping sweeps."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        now = datetime.now()

        # Skip trusted IPs
        if src_ip in trusted_ips or dst_ip in trusted_ips:
            return

        # Handle TCP-based scans
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            dst_port = tcp_layer.dport
            flags = tcp_layer.flags

            scan_attempts[src_ip].append((dst_port, now))

            # Filter timestamps within SCAN_WINDOW
            scan_attempts[src_ip] = [
                (port, time)
                for port, time in scan_attempts[src_ip]
                if now - time <= timedelta(seconds=SCAN_WINDOW)
            ]

            probed_ports = {port for port, _ in scan_attempts[src_ip]}

            # SYN Scan Detection
            if flags & 2:  # TCP SYN flag
                if len(probed_ports) >= PORT_SCAN_THRESHOLD:
                    log_alert(
                        "SYN Scan",
                        src_ip,
                        dst_ip,
                        f"Probed Ports: {sorted(probed_ports)}",
                    )

            # FIN Scan Detection
            if flags & 1 and not (flags & 2 or flags & 4 or flags & 16):
                log_alert(
                    "FIN Scan",
                    src_ip,
                    dst_ip,
                    f"Port: {dst_port}",
                )

            # NULL Scan Detection (No flags set)
            if flags == 0:
                log_alert(
                    "NULL Scan",
                    src_ip,
                    dst_ip,
                    f"Port: {dst_port}",
                )

            # XMAS Scan Detection (FIN + PSH + URG flags set)
            if flags == 41:
                log_alert(
                    "XMAS Scan",
                    src_ip,
                    dst_ip,
                    f"Port: {dst_port}",
                )

        # Handle ICMP-based scans (Ping Sweeps)
        elif packet.haslayer(ICMP):
            icmp_attempts[src_ip].append(now)

            # Filter recent ICMP attempts
            icmp_attempts[src_ip] = [
                time
                for time in icmp_attempts[src_ip]
                if now - time <= timedelta(seconds=SCAN_WINDOW)
            ]

            if len(icmp_attempts[src_ip]) >= PORT_SCAN_THRESHOLD:
                log_alert(
                    "Ping Sweep",
                    src_ip,
                    dst_ip,
                    f"ICMP packets detected within {SCAN_WINDOW}s",
                )

def start_scan_detection():
    """Start the scan detection module. This function is callable from the GUI."""
    print("Monitoring for Intrusions (Scan Detection)...")
    logging.info("Scan detection module started.")

    try:
        sniff(filter="ip", prn=detect_port_scan, store=0)
    except KeyboardInterrupt:
        print("Exiting scan detection...")
        logging.info("Scan detection module stopped by user.")

# Example usage for integration
if __name__ == "__main__":
    start_scan_detection()