⚙️ Step-by-Step Installation Guide
🔧 1. Clone the Repository & Access It
Open a terminal and run:

bash
Copy
Edit
git clone https://github.com/Aryachowkekar/PiSecure-Network-Defense.git
cd PiSecure-Network-Defense
🛡️ 2. Grant Execution Permission
To allow all scripts to run smoothly, execute:

bash
Copy
Edit
chmod +x *
📦 3. Install Required Tools and Libraries
Use the following command to install all dependencies like Flask, iptables, PyShark, Pandas, etc.:

bash
Copy
Edit
sudo python3 install.py
This step sets up the Python environment, network tools, and initial configurations.

You will be prompted to generate a password or key—store it securely for accessing the web dashboard.

🌐 4. Launch the Web-Based Firewall Console
Run the dashboard server:

bash
Copy
Edit
python3 app.py
Then, open a browser and visit the Raspberry Pi’s IP (shown in the terminal) like:

cpp
Copy
Edit
http://192.168.0.106:5000
Login using the admin credentials you set, and access the centralized control panel.

🔌 Hardware Connection Hierarchy (Firewall Setup)
This setup ensures all incoming and outgoing traffic is filtered by the Raspberry Pi before reaching user devices.

scss
Copy
Edit
📡 Internet (ISP)
   ↓
📶 Wi-Fi Router
   ↓ (Ethernet Cable to eth0)
🧠 Raspberry Pi (Firewall: eth0)
   ↓ (USB to Ethernet Adapter → eth1)
💻 Laptop or Lab Switch (Filtered Output)
💡 Technical Roles:
eth0 → Input interface (Internet via router)

eth1 → Output interface (Filtered traffic to endpoint device)

You can manage connections over wired (RJ45) or wireless (Wi-Fi) modes, and traffic is filtered using iptables and monitored by the IDS in real time​
.

🔒 Key Features Enabled by This Setup
Firewall Module: Blocks unauthorized IPs, ports, and services (HTTP, SSH, DNS, FTP, etc.).

Ad Blocker (DNS Sinkhole): Prevents ads and malicious domain resolutions by redirecting to a null IP.

IDS Integration: Real-time detection of DoS, brute-force, MITM, ARP spoofing, and reconnaissance attempts​
.

Log-Based Analysis: No database! Logs are saved and can be analyzed with tools like Wireshark.

Web Console: Real-time dashboard for traffic stats, threat alerts, firewall rule updates, and domain blacklisting.

🛠 Recommended Hardware
Raspberry Pi 3B+: Quad-Core CPU, 1GB RAM, built-in Ethernet & Wi-Fi

USB to Ethernet Adapter: Enables a second interface (eth1) for filtered output traffic​

📌 Final Tips
Use the Flask dashboard as your central control.

Ensure iptables is persistent across reboots (consider using iptables-save and iptables-restore).

Keep your install.py script updated with future tools or threat definitions.
