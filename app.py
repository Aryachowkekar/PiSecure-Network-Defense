from flask import Flask, render_template, jsonify, request, Response, send_file, redirect, url_for, session, make_response
from flask_cors import CORS
import subprocess
import threading
import time
import os
import logging
import socket
import re
import requests
from datetime import datetime
import concurrent.futures
from functools import partial
import bcrypt
import json
from datetime import timedelta
import hashlib
import hmac

# Import functions from firewall.py
from firewall import block_website, unblock_website, list_blocked_websites

# Import get_system_stats from Rassberrypi_temp_data.py
try:
    from Rassberrypi_temp_data import get_system_stats
except ImportError:
    def get_system_stats():
        return {"error": "System stats module not found"}

app = Flask(__name__)
CORS(app)
app.secret_key = 'supersecurekey'  # Change in production
app.permanent_session_lifetime = timedelta(days=7)

# Authentication configuration
USER_DATA_FILE = 'user_data.txt'

def get_stored_password():
    """Get the stored password hash from config file"""
    try:
        with open('config.json') as f:
            config = json.load(f)
        return config.get("hashed_password")
    except (FileNotFoundError, json.JSONDecodeError):
        return None

@app.before_request
def check_login():
    """Check if user is logged in or has remember me cookie"""
    if not session.get('logged_in'):
        remember_cookie = request.cookies.get('remember_me')
        if remember_cookie == 'true':
            session['logged_in'] = True
        elif request.endpoint not in ('login', 'static'):
            return redirect(url_for('login'))

# Store running processes
running_processes = {}

# IDS scripts mapping
DETECTION_SCRIPTS = {
    "bruteforce": "bruteforce.py",
    "dos_ddos": "dos-ddos_updated.py",
    "ping_detect": "ping_detect.py",
    "scan_detect": "scan_detect.py",
    "mitm": "mitm.py"
}

LOG_FILE = "intrusion_log.txt"
BLACKLIST_LOG = "blacklist.log"

# Blacklist configuration
BLACKLIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Black List')
DNSMASQ_CONFIG = "/etc/dnsmasq.d/blacklist.conf"
HOSTS_FILE = "/etc/hosts"

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

os.makedirs(BLACKLIST_DIR, exist_ok=True)

def write_to_log(message, log_file=LOG_FILE):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
    with open(log_file, "a") as f:
        f.write(timestamp + message + "\n")
    print(message)

def log_blacklist_action(action, details):
    write_to_log(f"BLACKLIST: {action} - {details}", BLACKLIST_LOG)

def get_actual_filename(list_id):
    return FILENAME_MAPPING.get(list_id, f"{list_id}.txt")

def start_ids_backend():
    try:
        result = subprocess.run(["pgrep", "-f", "ids-backend.py"], stdout=subprocess.PIPE, text=True)
        if result.stdout.strip():
            print("✅ ids-backend.py is already running.")
            return
        
        print("🚀 Starting ids-backend.py...")
        subprocess.Popen(["python3", "ids-backend.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"❌ Error starting ids-backend.py: {e}")

def run_script(script, args=[]):
    write_to_log(f"🚀 Starting {script} with args: {args}...")
    try:
        process = subprocess.Popen(
            ["sudo", "python3", script] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        running_processes[script] = process

        def log_output(process, script_name):
            for line in iter(process.stdout.readline, ''):
                write_to_log(f"{script_name}: {line.strip()}")
            for error in process.stderr:
                write_to_log(f"{script_name} ERROR: {error.strip()}")

        threading.Thread(target=log_output, args=(process, script), daemon=True).start()
    except Exception as e:
        write_to_log(f"❌ Error starting {script}: {str(e)}")

def sanitize_website(website):
    website = re.sub(r"^https?://", "", website)
    website = re.sub(r"/$", "", website)
    return website

def sanitize_domain(domain):
    domain = str(domain).strip()
    domain = re.sub(r'^\s*(127\.0\.0\.1|0\.0\.0\.0)\s+', '', domain)
    domain = domain.split('#')[0].strip()
    domain = re.sub(r'^https?://(www\.)?', '', domain)
    domain = re.sub(r'[/?:].*$', '', domain)
    domain = domain.rstrip('.')
    return domain.lower() if domain else None

def resolve_domain(domain):
    try:
        socket.setdefaulttimeout(5)
        _, _, _, _, (ip, *_) = socket.getaddrinfo(domain, None)[0]
        return [ip]
    except (socket.gaierror, socket.timeout, IndexError) as e:
        log_blacklist_action("Resolution Failed", f"Could not resolve {domain} - {str(e)}")
        return None
    except Exception as e:
        log_blacklist_action("Resolution Error", f"Unexpected error resolving {domain} - {str(e)}")
        return None

def update_dnsmasq_config(domains):
    try:
        os.makedirs(os.path.dirname(DNSMASQ_CONFIG), exist_ok=True)
        with open(DNSMASQ_CONFIG, 'w') as f:
            f.write("# Automatically generated blacklist\n")
            f.write("# Do not edit manually - changes will be overwritten\n\n")
            for domain in domains:
                if domain.strip():
                    f.write(f"address=/{domain}/0.0.0.0\n")
                    f.write(f"address=/{domain}/::\n")
        
        try:
            subprocess.run(['which', 'dnsmasq'], check=True, timeout=10)
            subprocess.run(['systemctl', 'restart', 'dnsmasq'], check=True, timeout=30)
            return True
        except subprocess.TimeoutExpired:
            log_blacklist_action("DNSMASQ Timeout", "Timeout while restarting dnsmasq")
            return False
        except subprocess.CalledProcessError:
            log_blacklist_action("DNSMASQ Not Installed", "dnsmasq service not found")
            return False
    except Exception as e:
        log_blacklist_action("DNSMASQ Update Failed", str(e))
        return False

def get_domains_from_file(filename):
    filepath = os.path.join(BLACKLIST_DIR, filename)
    domains = []
    if not os.path.exists(filepath):
        log_blacklist_action("File Missing", f"{filepath} not found")
        return domains
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = re.split(r'\s+', line)
                if len(parts) >= 2 and parts[0] in ('127.0.0.1', '0.0.0.0'):
                    domain = sanitize_domain(parts[1])
                else:
                    domain = sanitize_domain(parts[0])
                
                if domain:
                    domains.append(domain)
    except Exception as e:
        log_blacklist_action("File Error", f"Error reading {filepath}: {str(e)}")
    
    return list(set(domains))

def update_hosts_file(domains):
    try:
        with open(HOSTS_FILE, 'r') as f:
            lines = f.readlines()
        
        new_lines = [line for line in lines if not line.startswith(('0.0.0.0', '::')) or 
                    not any(domain in line for domain in domains)]
        
        with open(HOSTS_FILE, 'w') as f:
            f.writelines(new_lines)
            f.write("\n# Blacklisted domains\n")
            for domain in domains:
                f.write(f"0.0.0.0 {domain}\n")
                f.write(f"0.0.0.0 www.{domain}\n")
                f.write(f":: {domain}\n")
                f.write(f":: www.{domain}\n")
        return True
    except Exception as e:
        log_blacklist_action("Hosts File Update Failed", str(e))
        return False

def process_single_domain(domain):
    try:
        domain = domain.strip()
        if not domain:
            return False
            
        # DNS-based blocking
        try:
            with open(DNSMASQ_CONFIG, 'a') as f:
                f.write(f"address=/{domain}/0.0.0.0\n")
                f.write(f"address=/{domain}/::\n")
        except Exception as e:
            log_blacklist_action("DNS Block Failed", f"{domain}: {str(e)}")
            return False
        
        # Hosts file blocking
        try:
            with open(HOSTS_FILE, 'a') as f:
                f.write(f"0.0.0.0 {domain}\n")
                f.write(f"0.0.0.0 www.{domain}\n")
                f.write(f":: {domain}\n")
                f.write(f":: www.{domain}\n")
        except Exception as e:
            log_blacklist_action("Hosts Block Failed", f"{domain}: {str(e)}")
            return False
        
        # IP-based blocking
        try:
            ips = resolve_domain(domain)
            if ips:
                for ip in ips:
                    try:
                        subprocess.run(
                            ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                            timeout=5,
                            check=True
                        )
                        subprocess.run(
                            ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                            timeout=5,
                            check=True
                        )
                    except subprocess.TimeoutExpired:
                        log_blacklist_action("IPTables Timeout", f"Timeout blocking {domain} ({ip})")
                        continue
                    except subprocess.CalledProcessError as e:
                        log_blacklist_action("IPTables Block Failed", f"{domain} ({ip}): {str(e)}")
                        continue
        except Exception as e:
            log_blacklist_action("Resolution Error", f"{domain}: {str(e)}")
            return False
        
        return True
    except Exception as e:
        log_blacklist_action("Processing Error", f"{domain}: {str(e)}")
        return False

def block_domains(domains):
    blocked_count = 0
    total_domains = len(domains)
    BATCH_SIZE = 50
    
    for i in range(0, total_domains, BATCH_SIZE):
        batch = domains[i:i+BATCH_SIZE]
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_domain = {
                    executor.submit(process_single_domain, domain): domain 
                    for domain in batch
                }
                
                for future in concurrent.futures.as_completed(future_to_domain, timeout=30):
                    domain = future_to_domain[future]
                    try:
                        if future.result():
                            blocked_count += 1
                    except Exception as e:
                        log_blacklist_action("Block Failed", f"{domain}: {str(e)}")
        except concurrent.futures.TimeoutError:
            log_blacklist_action("Block Timeout", f"Timeout processing batch {i//BATCH_SIZE}")
            continue
    
    return blocked_count > 0

def download_and_save_list(url, filename=None):
    if not filename:
        filename = os.path.basename(url.split('?')[0])
    
    if not filename.lower().endswith('.txt'):
        filename += '.txt'
    
    filepath = os.path.join(BLACKLIST_DIR, filename)
    
    try:
        response = requests.get(url, timeout=(10, 30))
        response.raise_for_status()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        log_blacklist_action("List Downloaded", f"{filename} from {url}")
        return True, filename
    except requests.exceptions.Timeout:
        log_blacklist_action("Download Timeout", f"Timeout while downloading {url}")
        return False, "Download timed out"
    except requests.exceptions.RequestException as e:
        log_blacklist_action("Download Failed", f"{url}: {str(e)}")
        return False, str(e)
    except Exception as e:
        log_blacklist_action("Download Error", f"{url}: {str(e)}")
        return False, str(e)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    error = None
    if request.method == 'POST':
        stored_hash = get_stored_password()
        if not stored_hash:
            return render_template('login.html', error="Authentication not configured properly.")
        
        password = request.form.get('password')
        remember = request.form.get('remember')

        if password and bcrypt.checkpw(password.encode(), stored_hash.encode()):
            session['logged_in'] = True
            resp = make_response(redirect(url_for('index')))
            if remember:
                resp.set_cookie('remember_me', 'true', max_age=7 * 24 * 60 * 60)
            else:
                resp.set_cookie('remember_me', '', expires=0)
            return resp
        else:
            error = 'Incorrect password. Please try again.'

    return render_template('login.html', error=error)

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/stats')
def stats():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        return jsonify(get_system_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_logs', methods=['GET'])
def get_logs():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    def generate():
        last_position = 0
        while True:
            try:
                with open(LOG_FILE, "r") as f:
                    f.seek(last_position)
                    new_logs = f.readlines()
                    last_position = f.tell()
                    for log in new_logs:
                        if "HTTP" not in log:
                            yield f"data: {log.strip()}\n\n"
                time.sleep(0.5)
            except Exception as e:
                yield f"data: ⚠️ Error reading logs: {str(e)}\n\n"
                time.sleep(5)
    return Response(generate(), content_type='text/event-stream')

@app.route('/start_ids', methods=['POST'])
def start_ids():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    try:
        dos_ddos_option = request.form.get("dos_ddos_option", "Custom")
        dos_threshold_input = request.form.get("dos_threshold", "500/1000")
        log_file = request.files.get("log_file")
        self_learn = dos_ddos_option == "selflearn"

        try:
            dos_threshold, ddos_threshold = map(int, dos_threshold_input.split("/"))
        except ValueError:
            return jsonify({"error": "Invalid threshold format. Use <DoS threshold>/<DDoS threshold> (e.g., 500/1000)."}), 400

        write_to_log(f"🚀 Starting IDS with inputs - DOS Option: {dos_ddos_option}, Threshold: {dos_threshold_input}, Self-Learn: {self_learn}")

        log_file_path = None
        if log_file:
            log_file_path = os.path.join("uploads", log_file.filename)
            os.makedirs("uploads", exist_ok=True)
            log_file.save(log_file_path)

        for script_name, script_path in DETECTION_SCRIPTS.items():
            if script_name == "dos_ddos":
                args = [dos_ddos_option, str(dos_threshold), str(ddos_threshold)]
                if self_learn:
                    args.append("selflearn")
                if log_file_path:
                    args.append(log_file_path)
                run_script(script_path, args)
            else:
                run_script(script_path)

        return jsonify({"message": "IDS started successfully"}), 200
    except Exception as e:
        write_to_log(f"❌ Error starting IDS: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/stop_ids', methods=['POST'])
def stop_ids():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    write_to_log("🛑 Stopping IDS System...")
    for script, process in running_processes.items():
        process.terminate()
        process.wait()
    running_processes.clear()
    write_to_log("✅ IDS System Stopped Successfully")
    return jsonify({"message": "All IDS processes stopped"}), 200

@app.route('/download_logs', methods=['GET'])
def download_logs():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    try:
        return send_file(LOG_FILE, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ad-blocker')
def ad_blocker():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('ad-blocker.html')

@app.route('/blacklist')
def blacklist():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('blacklist.html')

@app.route('/intrusion-detection')
def intrusion_detection():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('intrusion-detection.html')

@app.route('/monitor-ids')
def monitor_ids():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('monitor-ids.html')

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('remember_me', '', expires=0)
    return resp

@app.route('/netguard-directives')
def netguard_directives():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('netguard-directives.html')

@app.route('/setting')
def setting():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('setting.html')

# Updated website blocking routes using functions from firewall.py
@app.route('/block-website', methods=['POST'])
def api_block_website():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    data = request.get_json()
    website = data.get('website')
    if not website:
        return jsonify({"success": False, "error": "Missing website in request."}), 400

    if block_website(website):
        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "error": "Failed to block website."}), 500

@app.route('/unblock-website', methods=['POST'])
def api_unblock_website():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    data = request.get_json()
    website = data.get('website')
    if not website:
        return jsonify({"success": False, "error": "Missing website in request."}), 400

    if unblock_website(website):
        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "error": "Failed to unblock website."}), 500

@app.route('/list-blocked', methods=['GET'])
def api_list_blocked():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    return jsonify({"blocked_websites": list_blocked_websites()}), 200

@app.route('/blacklist/apply', methods=['POST'])
def apply_blacklists():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
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

@app.route('/blacklist/add', methods=['POST'])
def add_custom_list():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400
    
    filename = os.path.basename(url.split('?')[0]) or "custom_list.txt"
    if len(filename) > 50:
        filename = "custom_list.txt"
    if not filename.lower().endswith('.txt'):
        filename += '.txt'
    
    try:
        success, result = download_and_save_list(url, filename)
        if not success:
            return jsonify({"status": "error", "message": f"Failed to download: {result}"}), 400
        
        domains = get_domains_from_file(filename)
        if not domains:
            return jsonify({
                "status": "success",
                "message": f"List added but no domains found in {filename}",
                "filename": filename,
                "blocked_count": 0
            })
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(block_domains, domains)
                try:
                    block_success = future.result(timeout=300)
                except concurrent.futures.TimeoutError:
                    log_blacklist_action("Block Timeout", "Overall blocking operation timed out")
                    return jsonify({
                        "status": "partial",
                        "message": "Blocking operation timed out",
                        "filename": filename,
                        "blocked_count": "unknown"
                    }), 500
                
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
        except Exception as e:
            log_blacklist_action("Add List Error", f"Unexpected error: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Unexpected error processing list: {str(e)}"
            }), 500
    except Exception as e:
        log_blacklist_action("Add List Error", f"Unexpected error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Unexpected error processing list: {str(e)}"
        }), 500

@app.route('/blacklist/lists', methods=['GET'])
def get_available_lists():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    available = {}
    for list_id, filename in FILENAME_MAPPING.items():
        filepath = os.path.join(BLACKLIST_DIR, filename)
        available[list_id] = os.path.exists(filepath)
    
    return jsonify({
        "status": "success",
        "available_lists": available
    })

@app.route('/blacklist/init-files', methods=['POST'])
def initialize_files():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
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

if __name__ == '__main__':
    start_ids_backend()
    app.run(host='0.0.0.0', port=5000, debug=True)
