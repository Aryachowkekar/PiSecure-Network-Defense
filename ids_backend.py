from flask import Flask, request, jsonify, Response
import subprocess
from flask_cors import CORS
import time
import os
import logging
import threading

app = Flask(__name__)
CORS(app)

# Store running processes
running_processes = {}

# IDS scripts mapping (ensure paths are correct)
DETECTION_SCRIPTS = {
    "bruteforce": "bruteforce.py",
    "dos_ddos": "dos-ddos_updated.py",
    "ping_detect": "ping_detect.py",
    "scan_detect": "scan_detect.py",
    "mitm": "mitm.py"
}

LOG_FILE = "intrusion_log.txt"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

def write_to_log(message):
    """Write messages to the log file and print for debugging"""
    logging.info(message)
    print(message)  # Debugging live output

def run_script(script, args=[]):
    """Run IDS scripts in the background and store their logs"""
    if script in running_processes:
        write_to_log(f"⚠️ {script} is already running. Skipping duplicate start.")
        return

    write_to_log(f"🚀 Starting {script} with args: {args}...")

    try:
        process = subprocess.Popen(
            ["sudo", "python3", script] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Unbuffered output for real-time logging
        )
        running_processes[script] = process

        # Log real-time script output
        def log_output(process, script_name):
            for line in iter(process.stdout.readline, ''):
                write_to_log(f"{script_name}: {line.strip()}")
            for error in process.stderr:
                write_to_log(f"{script_name} ERROR: {error.strip()}")

        # Start a thread to log output
        threading.Thread(target=log_output, args=(process, script), daemon=True).start()

    except Exception as e:
        write_to_log(f"❌ Error starting {script}: {str(e)}")

def start_all_ids(dos_ddos_option="Custom", dos_threshold="500/100", log_file=None, self_learn=False):
    """Starts all IDS scripts with user-provided arguments"""
    write_to_log("🚀 Auto-starting IDS scripts with user inputs...")

    for script_name, script_path in DETECTION_SCRIPTS.items():
        if script_name == "dos_ddos":
            args = [dos_ddos_option, dos_threshold]
            if self_learn:
                args.append("selflearn")
            if log_file:
                args.append(log_file)
            run_script(script_path, args)
        else:
            run_script(script_path)

@app.route('/get_logs', methods=['GET'])
def get_logs():
    """Stream logs from the log file with real-time updates"""
    def generate():
        last_position = 0
        while True:
            try:
                time.sleep(0.1)  # Faster updates
                with open(LOG_FILE, "r") as f:
                    f.seek(last_position)
                    new_logs = f.readlines()
                    last_position = f.tell()

                    for log in new_logs:
                        yield f"data: {log.strip()}\n\n"

            except Exception as e:
                yield f"data: ⚠️ Error reading logs: {str(e)}\n\n"
                time.sleep(2)

    return Response(generate(), content_type='text/event-stream')

@app.route('/start_ids', methods=['POST'])
def start_ids():
    """Start ALL IDS processes via API with user inputs"""
    dos_ddos_option = request.form.get("dos_ddos_option", "Custom")
    dos_threshold = request.form.get("dos_threshold", "500/100")
    log_file = request.files.get("log_file")
    self_learn = dos_ddos_option == "selflearn"

    write_to_log(f"🚀 Starting IDS via API with inputs - DOS Option: {dos_ddos_option}, Threshold: {dos_threshold}, Self-Learn: {self_learn}")

    start_all_ids(dos_ddos_option, dos_threshold, log_file, self_learn)
    return jsonify({"message": "IDS started successfully"}), 200

@app.route('/stop_ids', methods=['POST'])
def stop_ids():
    """Stops all IDS processes"""
    write_to_log("🛑 Stopping IDS System...")

    try:
        for script, process in running_processes.items():
            process.terminate()
            process.wait()

        running_processes.clear()
        write_to_log("✅ IDS System Stopped Successfully")

        return jsonify({"message": "All IDS processes stopped"}), 200

    except Exception as e:
        write_to_log(f"⚠️ Error stopping IDS: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)