from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import socket
import json
import sys

# Configure logging for real-time and file-based logging
LOG_FILE_TXT = "intrusion_log.txt"
LOG_FILE_JSON = "intrusion_log.json"

logging.basicConfig(
    filename=LOG_FILE_TXT,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Get system's actual IP address dynamically
def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        s.close()
        return host_ip
    except Exception as e:
        logging.error(f"Error fetching host IP: {str(e)}")
        return "127.0.0.1"

HOST_IP = get_host_ip()

# Global Variables
traffic_data = defaultdict(list)  # Tracks traffic per source IP
aggregate_traffic = []  # Tracks global traffic
learning_mode = False  # Self-learning mode
learned_baseline = {}  # Baseline traffic for self-learning
MONITOR_WINDOW = 1  # Time window in seconds
LEARNING_DURATION = timedelta(hours=24)  # Duration for self-learning
learning_start_time = None  # Start time for self-learning

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
    sys.stdout.flush()  # Ensure real-time log updates

    # Log to intrusion_log.txt
    logging.info(json.dumps(alert_data))

    # Save structured logs in intrusion_log.json
    try:
        with open(LOG_FILE_JSON, "a") as log_file:
            json.dump(alert_data, log_file)
            log_file.write("\n")
    except Exception as e:
        print(f"Error writing to JSON log file: {e}")
        sys.stdout.flush()

def start_self_learning():
    """Start self-learning mode to establish baseline traffic."""
    global learning_mode, learning_start_time, learned_baseline
    learning_mode = True
    learning_start_time = datetime.now()
    learned_baseline = defaultdict(int)
    log_alert("Self-Learning", HOST_IP, "Self-learning mode initiated for 24 hours.")

def detect_dos_ddos(packet, dos_threshold, ddos_threshold):
    """Detect DoS and DDoS attacks based on traffic patterns."""
    global learning_mode, learned_baseline, learning_start_time
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        now = datetime.now()

        # Ignore packets originating from the host itself
        if src_ip == HOST_IP:
            return

        # Self-learning mode: Build baseline traffic
        if learning_mode:
            if now - learning_start_time < LEARNING_DURATION:
                learned_baseline[src_ip] += 1
                return
            else:
                learning_mode = False
                log_alert("Self-Learning", HOST_IP, "Self-learning completed. Entering detection mode.")

        # Track traffic for the current IP
        traffic_data[src_ip].append(now)
        aggregate_traffic.append(now)

        # Filter traffic within the monitoring window
        traffic_data[src_ip] = [t for t in traffic_data[src_ip] if now - t <= timedelta(seconds=MONITOR_WINDOW)]
        aggregate_traffic[:] = [t for t in aggregate_traffic if now - t <= timedelta(seconds=MONITOR_WINDOW)]

        # Count packets for the current IP and global traffic
        packet_count = len(traffic_data[src_ip])
        global_traffic_count = len(aggregate_traffic)

        # Detect DoS attack
        if packet_count > dos_threshold:
            alert_msg = f"DoS attack detected on {dst_ip} with {packet_count} packets/sec from {src_ip}"
            log_alert("DoS Attack", src_ip, alert_msg)

        # Detect DDoS attack
        if global_traffic_count > ddos_threshold:
            alert_msg = f"DDoS attack detected with {global_traffic_count} packets/sec from {len(traffic_data)} sources"
            log_alert("DDoS Attack", src_ip, alert_msg)

def start_detection(dos_threshold, ddos_threshold, self_learn=False):
    """Start the DoS/DDoS detection system."""
    if self_learn:
        start_self_learning()
    log_alert("DoS/DDoS Detection", HOST_IP, f"Monitoring started (Thresholds: DoS={dos_threshold}, DDoS={ddos_threshold})")
    try:
        sniff(filter="ip", prn=lambda packet: detect_dos_ddos(packet, dos_threshold, ddos_threshold), store=0)
    except KeyboardInterrupt:
        log_alert("DoS/DDoS Detection", HOST_IP, "Monitoring stopped by user.")
    except Exception as e:
        log_alert("Error", HOST_IP, f"Error in detection: {str(e)}")

if __name__ == "__main__":
    # Default thresholds (can be overridden by frontend)
    dos_threshold = 100  # Packets per second for DoS
    ddos_threshold = 500  # Packets per second for DDoS

    # Check if self-learning mode is enabled
    self_learn = False
    if len(sys.argv) > 1 and sys.argv[1] == "selflearn":
        self_learn = True

    # Override thresholds if provided via command-line arguments
    if len(sys.argv) > 3:
        dos_threshold = int(sys.argv[2])  # DoS threshold
        ddos_threshold = int(sys.argv[3])  # DDoS threshold

    # Start detection
    start_detection(dos_threshold, ddos_threshold, self_learn)