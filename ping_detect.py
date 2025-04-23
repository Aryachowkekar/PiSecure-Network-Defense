from scapy.all import sniff, IP, ICMP
import logging
import socket
import json
from datetime import datetime

# Configure logging for unified IDS monitoring
LOG_FILE_TXT = "intrusion_log.txt"
LOG_FILE_JSON = "intrusion_log.json"

logging.basicConfig(
    filename=LOG_FILE_TXT,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

def configure_ping_detection():
    """Get the local IP address dynamically for detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        logging.error(f"Error fetching local IP: {str(e)}")
        local_ip = "127.0.0.1"  # Default fallback

    return local_ip

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

def detect_ping(packet, local_ip):
    """Detect ICMP-based Ping requests and log them."""
    if packet.haslayer(ICMP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        icmp_type = packet[ICMP].type

        # Detect only Echo Request (Type 8)
        if icmp_type == 8:
            # Log general ping detection
            alert_msg = f"Ping detected to {ip_dst}"
            log_alert("Ping Scan", ip_src, alert_msg)

            # If the destination is the local machine
            if ip_dst == local_ip:
                alert_msg = f"Direct ping to this device"
                log_alert("Direct Ping", ip_src, alert_msg)

def start_ping_detection():
    """Start the ping detection system."""
    local_ip = configure_ping_detection()
    print(f"🔍 Monitoring for Ping Intrusions (Local IP: {local_ip})...")
    logging.info("Ping Detection started.")

    try:
        sniff(filter="icmp", prn=lambda packet: detect_ping(packet, local_ip), store=0)
    except KeyboardInterrupt:
        print("🛑 Stopping Ping Detection...")
        logging.info("Ping Detection stopped by user.")
    except Exception as e:
        logging.error(f"Error in Ping Detection: {str(e)}")

if __name__ == "__main__":
    start_ping_detection()