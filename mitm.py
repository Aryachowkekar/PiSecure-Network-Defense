from scapy.all import ARP, sniff, IP, TCP
import logging
import json
from datetime import datetime, timedelta
from collections import defaultdict

# Configure logging to integrate with Monitor IDS
LOG_FILE_TXT = "intrusion_log.txt"
LOG_FILE_JSON = "intrusion_log.json"

logging.basicConfig(
    filename=LOG_FILE_TXT,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Parameters
ARP_ANOMALY_THRESHOLD = 3  # Number of ARP anomalies before triggering an alert
TIME_WINDOW_SECONDS = 10  # Time window for grouping ARP anomalies

# ARP table to track legitimate IP-MAC pairs
arp_table = defaultdict(set)  # {IP: {MAC addresses}}
arp_anomaly_count = defaultdict(int)  # Track ARP anomalies per IP
arp_anomaly_timestamps = defaultdict(list)  # Track timestamps of ARP anomalies
alerted_ips = set()  # IPs already alerted for anomalies

print("🔍 Monitoring for Man-in-the-Middle (MitM) Attacks...")

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

def detect_arp_anomalies(packet):
    """Detect ARP anomalies indicating possible MitM attacks."""
    if packet.haslayer(ARP):
        arp_src_ip = packet[ARP].psrc  # Source IP
        arp_src_mac = packet[ARP].hwsrc  # Source MAC
        now = datetime.now()

        # Check if the IP is already in the ARP table
        if arp_src_ip in arp_table:
            if arp_src_mac not in arp_table[arp_src_ip]:
                # Track the timestamp of this anomaly
                arp_anomaly_timestamps[arp_src_ip].append(now)

                # Filter timestamps within the time window
                arp_anomaly_timestamps[arp_src_ip] = [
                    timestamp
                    for timestamp in arp_anomaly_timestamps[arp_src_ip]
                    if now - timestamp <= timedelta(seconds=TIME_WINDOW_SECONDS)
                ]

                # Check if the number of anomalies exceeds the threshold
                if len(arp_anomaly_timestamps[arp_src_ip]) >= ARP_ANOMALY_THRESHOLD:
                    alert_msg = (
                        f"ARP Spoofing detected! "
                        f"IP {arp_src_ip} is now associated with MAC {arp_src_mac}. "
                        f"Previous MAC(s): {', '.join(arp_table[arp_src_ip])}"
                    )
                    log_alert("ARP Spoofing", arp_src_ip, alert_msg)
                    alerted_ips.add(arp_src_ip)  # Avoid duplicate alerts
        else:
            # Add new IP-MAC mapping
            arp_table[arp_src_ip].add(arp_src_mac)

def detect_duplicate_packets(packet):
    """Detect duplicate TCP packets that could indicate MitM attacks."""
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        # If packet contains duplicate SYN-ACK flags, it may indicate interception
        if flags == 0x12:  # SYN-ACK flag
            alert_msg = f"Possible MitM attack detected! Duplicate SYN-ACK packet."
            log_alert("MitM Attack", packet[IP].src, alert_msg)

def packet_handler(packet):
    """Handle packets to detect MitM-related anomalies."""
    detect_arp_anomalies(packet)
    detect_duplicate_packets(packet)

def monitor_network():
    """Monitor the network for MitM attacks."""
    try:
        sniff(
            filter="arp or tcp",  # Only monitor ARP and TCP traffic
            prn=packet_handler,
            store=0,
        )
    except KeyboardInterrupt:
        print("\n🛑 Stopping MitM Detection...")
        logging.info("MitM Detection stopped by user.")

if __name__ == "__main__":
    try:
        monitor_network()
    except Exception as e:
        log_alert("Error", "System", f"Error in MitM Detection: {str(e)}")