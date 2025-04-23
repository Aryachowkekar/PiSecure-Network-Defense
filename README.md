# 🚀 Getting Started with PiSecure Firewall
Welcome to PiSecure — your complete plug-and-play network security system powered by Raspberry Pi.
This project brings together the core pillars of modern cybersecurity into a single, compact, and cost-effective solution:

✅ DNS Sinkhole-based Ad Blocking to eliminate online ads and trackers before they load

🔥 Customizable Firewall Rules using iptables to filter malicious or unauthorized traffic

🛡️ Intrusion Detection System (IDS) to monitor and alert on network-based attacks in real time

With this guide, you'll learn how to install, configure, and deploy the PiSecure Firewall effortlessly, gaining full control over your network’s security — whether for home, labs, or small business environments.



## ⚙️ Step-by-Step Installation Guide

### 🧰 1. Clone the Repository & Access It

```bash
git clone https://github.com/Aryachowkekar/PiSecure-Network-Defense.git
cd PiSecure-Network-Defense
```
## 🛡️ 2. Grant Execution Permission
```bash
chmod +x *
```
## 📦 3. Install Required Tools and Libraries
```bash
sudo python3 install.py
```
This installs all dependencies like Flask, iptables, PyShark, Pandas, and more.
During installation, you’ll be asked to set a password for admin access — keep this safe!

## 🌐 4. Launch the Web-Based Firewall Console
```bash
sudo python3 app.py
```
Then open your browser and visit:
```
http://<raspberry-pi-ip>:5000
```
![Image ALT] ()
## 🛡️ 5. Intrusion Prevention System
```bash
sudo python3 ips.py
```


### Use your login credentials to access the centralized dashboard.

## 🔌 Hardware Connection Hierarchy (Firewall Setup)
This ensures all incoming and outgoing traffic passes through the Raspberry Pi before reaching your device.
```
📡 Internet (ISP)
   ↓
📶 Raspberry Pi (Eth0 Port)
   ↓ 
🧠 USB-TO-ETHERNET Adapter (Ethernet Cable) to Switch/Router
   ↓ (USB to Ethernet → eth1)
💻 Deidcated PC's Or Wirless Devices (Filtered Output)
```
## 💡 Interface Roles:
eth0 → Input Interface (Internet from router)

eth1 → Output Interface (Filtered traffic to devices)

Both wired (RJ45) and wireless modes are supported.

## 🔒 Key Features of PiSecure
Firewall Module: Blocks unwanted traffic based on IP, port, and protocol (HTTP, FTP, SSH, etc.).

Ad Blocker (DNS Sinkhole): Redirects ad/tracker domains to null IPs.

Intrusion Detection System (IDS): Real-time detection of threats (DoS, brute-force, MITM, ARP spoofing).

Log-based Analysis: All data is stored in logs, viewable via Wireshark (no database needed).

Web Dashboard: Centralized UI for monitoring, rule setup, and threat alerts.

## 🛠 Recommended Hardware
Raspberry Pi 3B+: Quad-Core CPU, 1GB RAM, Ethernet + Wi-Fi support

USB-to-Ethernet Adapter: Enables second network interface (eth1)

## 📌 Final Notes
Make sure iptables rules persist after reboot using:
```
sudo iptables-save > /etc/iptables/rules.v4
```
Keep your scripts up to date by editing install.py for future tools or rules.

Use Wireshark to inspect traffic logs and understand network behavior.

### 🛡️ Built for powerful yet affordable network security!
### 💻 Designed by: Team PiSecure – Atharva College of Engineering
### 📍 Use this for homes, small businesses, or even cyber labs!





