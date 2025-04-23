import os
import requests
import subprocess
import socket
import re
from datetime import datetime
from flask import Blueprint, request, jsonify

blacklist_bp = Blueprint('blacklist', __name__, url_prefix='/blacklist')

# Configuration
BLACKLIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Black List')
ALLOWED_FILE_TYPES = ['.txt']
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blacklist.log')
DNSMASQ_CONFIG = "/etc/dnsmasq.d/blacklist.conf"
HOSTS_FILE = "/etc/hosts"

# Mapping between checkbox IDs and actual filenames
FILENAME_MAPPING = {
    'polish': 'PolishFiltersTeam.txt',
    'fademind': 'FadeMind.txt',
    'static': 'Static.txt',
    'adaway': 'adaway.txt',
    'adguarddns': 'AdguardDNS.txt',
    'admiral': 'Admiral.txt',
    'adservers': 'adservers.txt',
    'easylist': 'Easylist.txt',
    'pglyoyo': 'pgl.yoyo.txt',
    'easyprivacy': 'Easyprivacy.txt',
    'prigent': 'Prigent-Ads.txt',
    'spy': 'spy.txt',
    'firstparty': 'firstparty-trackers-hosts.txt'
}

# Ensure directories exist
os.makedirs(BLACKLIST_DIR, exist_ok=True)

def log_action(action, details):
    """Log actions to a file"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {action}: {details}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry)

def get_actual_filename(list_id):
    """Get the actual filename from the checkbox ID"""
    return FILENAME_MAPPING.get(list_id, f"{list_id}.txt")

def sanitize_domain(domain):
    """Enhanced domain sanitization that properly handles hosts file format"""
    domain = str(domain).strip()
    
    # Remove 127.0.0.1 or 0.0.0.0 prefix if present
    domain = re.sub(r'^\s*(127\.0\.0\.1|0\.0\.0\.0)\s+', '', domain)
    
    # Remove any remaining whitespace or comments
    domain = domain.split('#')[0].strip()
    
    # Remove http://, https://, www.
    domain = re.sub(r'^https?://(www\.)?', '', domain)
    
    # Remove paths, ports, and queries
    domain = re.sub(r'[/?:].*$', '', domain)
    
    # Remove trailing dots
    domain = domain.rstrip('.')
    
    return domain.lower() if domain else None

def resolve_domain(domain):
    """More robust domain resolution with timeout"""
    try:
        # Set timeout for DNS resolution (5 seconds)
        socket.setdefaulttimeout(5)
        
        # Get both A (IPv4) and AAAA (IPv6) records
        _, _, _, _, (ip, *_) = socket.getaddrinfo(domain, None)[0]
        return [ip]
    except (socket.gaierror, socket.timeout, IndexError) as e:
        log_action("Resolution Failed", f"Could not resolve {domain} - {str(e)}")
        return None
    except Exception as e:
        log_action("Resolution Error", f"Unexpected error resolving {domain} - {str(e)}")
        return None

def update_dnsmasq_config(domains):
    """Update dnsmasq configuration to block domains"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(DNSMASQ_CONFIG), exist_ok=True)
        
        with open(DNSMASQ_CONFIG, 'w') as f:
            f.write("# Automatically generated blacklist\n")
            f.write("# Do not edit manually - changes will be overwritten\n\n")
            for domain in domains:
                if domain.strip():  # Skip empty domains
                    f.write(f"address=/{domain}/0.0.0.0\n")
                    f.write(f"address=/{domain}/::\n")  # IPv6
        
        # Verify dnsmasq is installed before trying to restart
        try:
            subprocess.run(['which', 'dnsmasq'], check=True)
            subprocess.run(['systemctl', 'restart', 'dnsmasq'], check=True)
            return True
        except subprocess.CalledProcessError:
            log_action("DNSMASQ Not Installed", "dnsmasq service not found")
            return False
            
    except Exception as e:
        log_action("DNSMASQ Update Failed", str(e))
        return False

def get_domains_from_file(filename):
    """Read domains from file with proper hosts format handling"""
    filepath = os.path.join(BLACKLIST_DIR, filename)
    domains = []
    
    if not os.path.exists(filepath):
        log_action("File Missing", f"{filepath} not found")
        return domains
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle hosts format (127.0.0.1 domain.com) and variants
                parts = re.split(r'\s+', line)
                if len(parts) >= 2 and parts[0] in ('127.0.0.1', '0.0.0.0'):
                    domain = sanitize_domain(parts[1])
                else:
                    domain = sanitize_domain(parts[0])
                
                if domain:
                    domains.append(domain)
    
    except Exception as e:
        log_action("File Error", f"Error reading {filepath}: {str(e)}")
    
    return list(set(domains))  # Remove duplicates

def update_hosts_file(domains):
    """Update /etc/hosts file to block domains"""
    try:
        # Read existing hosts file
        with open(HOSTS_FILE, 'r') as f:
            lines = f.readlines()
        
        # Remove existing blacklist entries
        new_lines = [line for line in lines if not line.startswith(('0.0.0.0', '::')) or 
                    not any(domain in line for domain in domains)]
        
        # Add new blacklist entries
        with open(HOSTS_FILE, 'w') as f:
            f.writelines(new_lines)
            f.write("\n# Blacklisted domains\n")
            for domain in domains:
                f.write(f"0.0.0.0 {domain}\n")
                f.write(f"0.0.0.0 www.{domain}\n")  # Block www subdomain too
                f.write(f":: {domain}\n")
                f.write(f":: www.{domain}\n")
        return True
    except Exception as e:
        log_action("Hosts File Update Failed", str(e))
        return False

def block_domains(domains):
    """Block domains with multiple fallback methods"""
    blocked_count = 0
    
    for domain in domains:
        # 1. DNS-based blocking (dnsmasq)
        try:
            with open(DNSMASQ_CONFIG, 'a') as f:
                f.write(f"address=/{domain}/0.0.0.0\n")
                f.write(f"address=/{domain}/::\n")
            blocked_count += 1
        except Exception as e:
            log_action("DNS Block Failed", f"{domain}: {str(e)}")
        
        # 2. Hosts file blocking
        try:
            with open(HOSTS_FILE, 'a') as f:
                f.write(f"0.0.0.0 {domain}\n")
                f.write(f"0.0.0.0 www.{domain}\n")
                f.write(f":: {domain}\n")
                f.write(f":: www.{domain}\n")
            blocked_count += 1
        except Exception as e:
            log_action("Hosts Block Failed", f"{domain}: {str(e)}")
        
        # 3. IP-based blocking (if resolution succeeds)
        ips = resolve_domain(domain)
        if ips:
            for ip in ips:
                try:
                    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                    subprocess.run(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
                    blocked_count += 1
                except subprocess.CalledProcessError as e:
                    log_action("IPTables Block Failed", f"{domain} ({ip}): {str(e)}")
    
    return blocked_count > 0

def download_and_save_list(url, filename=None):
    """Download a domain list from a URL and save it to the blacklist directory"""
    if not filename:
        filename = os.path.basename(url.split('?')[0])
    
    if not filename.lower().endswith('.txt'):
        filename += '.txt'
    
    filepath = os.path.join(BLACKLIST_DIR, filename)
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        log_action("List Downloaded", f"{filename} from {url}")
        return True, filename
    except requests.exceptions.RequestException as e:
        log_action("Download Failed", f"{url}: {str(e)}")
        return False, str(e)
    except Exception as e:
        log_action("Download Error", f"{url}: {str(e)}")
        return False, str(e)

@blacklist_bp.route('/apply', methods=['POST'])
def apply_blacklists():
    """Handle checkbox selections with proper filename mapping"""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    selected_lists = data.get('selected', [])
    
    if not selected_lists:
        return jsonify({"status": "error", "message": "No lists selected"}), 400
    
    all_domains = []
    missing_files = []
    
    for list_id in selected_lists:
        actual_filename = get_actual_filename(list_id)
        domains = get_domains_from_file(actual_filename)
        
        if not domains and not os.path.exists(os.path.join(BLACKLIST_DIR, actual_filename)):
            missing_files.append(actual_filename)
        elif domains:
            all_domains.extend(domains)
    
    if not all_domains:
        msg = "No domains found in selected lists"
        if missing_files:
            msg += f" (missing files: {', '.join(missing_files)})"
        return jsonify({"status": "error", "message": msg}), 400
    
    success = block_domains(all_domains)
    
    if success:
        return jsonify({
            "status": "success",
            "message": f"Blocked {len(all_domains)} domains from {len(selected_lists)} lists",
            "blocked_count": len(all_domains),
            "missing_files": missing_files
        })
    else:
        return jsonify({
            "status": "partial",
            "message": "Some domains could not be blocked",
            "blocked_count": len(all_domains),
            "missing_files": missing_files
        })

@blacklist_bp.route('/add', methods=['POST'])
def add_custom_list():
    """Handle adding a custom domain list from a URL"""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400
    
    # Try to extract a reasonable filename from the URL
    filename = os.path.basename(url.split('?')[0])  # Remove query parameters
    if not filename or len(filename) > 50:  # If too long or empty
        filename = "custom_list.txt"
    
    success, result = download_and_save_list(url, filename)
    
    if success:
        # Also block the domains from this new list
        domains = get_domains_from_file(filename)
        if domains:
            block_success = block_domains(domains)
            if block_success:
                return jsonify({
                    "status": "success",
                    "message": f"Added and blocked {len(domains)} domains from {filename}",
                    "filename": filename,
                    "blocked_count": len(domains)
                })
            else:
                return jsonify({
                    "status": "partial",
                    "message": "List added but some domains could not be blocked",
                    "filename": filename,
                    "blocked_count": len(domains)
                })
        else:
            return jsonify({
                "status": "success",
                "message": f"List added but no domains found in {filename}",
                "filename": filename,
                "blocked_count": 0
            })
    else:
        return jsonify({"status": "error", "message": f"Failed to download: {result}"}), 400

@blacklist_bp.route('/lists', methods=['GET'])
def get_available_lists():
    """Return list of available blacklist files with proper mapping"""
    available = {}
    for list_id, filename in FILENAME_MAPPING.items():
        filepath = os.path.join(BLACKLIST_DIR, filename)
        available[list_id] = os.path.exists(filepath)
    
    return jsonify({
        "status": "success",
        "available_lists": available
    })

@blacklist_bp.route('/init-files', methods=['POST'])
def initialize_files():
    """Create empty versions of all expected blacklist files"""
    created_files = []
    failed_files = []
    
    for list_id, filename in FILENAME_MAPPING.items():
        filepath = os.path.join(BLACKLIST_DIR, filename)
        if not os.path.exists(filepath):
            try:
                with open(filepath, 'w') as f:
                    f.write(f"# {filename}\n")
                created_files.append(filename)
            except Exception as e:
                failed_files.append({
                    "filename": filename,
                    "error": str(e)
                })
    
    return jsonify({
        "status": "success",
        "created_files": created_files,
        "failed_files": failed_files
    })
