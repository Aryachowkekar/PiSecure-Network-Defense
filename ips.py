#!/usr/bin/env python3
import os
import time
import subprocess
from datetime import datetime, timedelta
import sys
import signal
import pyfiglet
from termcolor import colored
import threading

# ASCII Art Banner
def display_banner():
    os.system('clear')
    result = pyfiglet.figlet_format("Laptop IPS", font="slant")
    print(colored(result, 'red'))
    print(colored("="*60, 'blue'))
    print(colored("||", 'blue'), colored(" " * 20, 'red'), 
          colored("LOCAL INTRUSION PREVENTION", 'yellow', attrs=['bold']), 
          colored(" " * 20, 'red'), colored("||", 'blue'))
    print(colored("="*60, 'blue'))
    print("\n")

# Check admin privileges
def check_admin():
    if os.geteuid() != 0:
        print(colored("[!] This script must be run as root!", 'red'))
        sys.exit(1)

# Thread-based unblock timer
def schedule_unblock(ip, minutes):
    time.sleep(minutes * 60)
    unblock_ip(ip)
    print(colored(f"\n[+] IP {ip} automatically unblocked after {minutes} minutes", 'green'))

# Block IP using iptables
def block_ip(ip, minutes=None):
    if not is_valid_ip(ip):
        print(colored(f"[!] Invalid IP address: {ip}", 'red'))
        return False
    
    if is_ip_blocked(ip):
        print(colored(f"[!] IP {ip} is already blocked", 'yellow'))
        return True
    
    try:
        subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
        subprocess.run(f"iptables -A OUTPUT -d {ip} -j DROP", shell=True, check=True)
        
        if minutes:
            # Try using 'at' command first
            try:
                unblock_time = datetime.now() + timedelta(minutes=minutes)
                cmd = f"echo 'iptables -D INPUT -s {ip} -j DROP; iptables -D OUTPUT -d {ip} -j DROP' | at {unblock_time.strftime('%H:%M')}"
                subprocess.run(cmd, shell=True, check=True)
                print(colored(f"[+] IP {ip} blocked for {minutes} minutes (until {unblock_time.strftime('%Y-%m-%d %H:%M:%S')})", 'green'))
            except subprocess.CalledProcessError:
                # Fallback to threading if 'at' is not available
                print(colored("[*] 'at' command not available, using fallback timer", 'yellow'))
                timer = threading.Thread(target=schedule_unblock, args=(ip, minutes))
                timer.daemon = True
                timer.start()
                print(colored(f"[+] IP {ip} blocked for {minutes} minutes (using fallback timer)", 'green'))
        else:
            print(colored(f"[+] IP {ip} blocked permanently", 'green'))
        
        return True
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Failed to block IP {ip}: {str(e)}", 'red'))
        return False

# Unblock IP
def unblock_ip(ip):
    if not is_valid_ip(ip):
        print(colored(f"[!] Invalid IP address: {ip}", 'red'))
        return False
    
    try:
        subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", shell=True)
        subprocess.run(f"iptables -D OUTPUT -d {ip} -j DROP", shell=True)
        print(colored(f"[+] IP {ip} unblocked successfully", 'green'))
        return True
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Failed to unblock IP {ip}: {str(e)}", 'red'))
        return False

# Check if IP is already blocked
def is_ip_blocked(ip):
    try:
        result = subprocess.run(f"iptables -L -n | grep {ip}", shell=True, capture_output=True, text=True)
        return ip in result.stdout
    except:
        return False

# Validate IP address
def is_valid_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

# List all blocked IPs
def list_blocked_ips():
    try:
        result = subprocess.run("iptables -L INPUT -n | grep DROP | awk '{print $4}' | sort -u", 
                               shell=True, capture_output=True, text=True)
        blocked_ips = result.stdout.splitlines()
        
        if not blocked_ips or (len(blocked_ips) == 1 and blocked_ips[0] == ''):
            print(colored("[*] No IPs are currently blocked", 'yellow'))
            return []
        
        print(colored("\nCurrently Blocked IP Addresses:", 'cyan', attrs=['bold']))
        for ip in blocked_ips:
            print(colored(f" - {ip}", 'yellow'))
        return blocked_ips
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Error listing blocked IPs: {str(e)}", 'red'))
        return []

# Interactive menu
def show_menu():
    while True:
        display_banner()
        print(colored("\nMain Menu:", 'magenta', attrs=['bold']))
        print(colored("1. Block a single IP address", 'green'))
        print(colored("2. Block multiple IP addresses", 'green'))
        print(colored("3. Unblock an IP address", 'blue'))
        print(colored("4. List all blocked IPs", 'cyan'))
        print(colored("5. Flush all blocked IPs (unblock all)", 'red'))
        print(colored("0. Exit", 'yellow'))
        
        choice = input(colored("\nEnter your choice: ", 'white', attrs=['bold']))
        
        if choice == '1':
            ip = input(colored("\nEnter IP address to block: ", 'white'))
            minutes = input(colored("Enter minutes to block (leave empty for permanent): ", 'white'))
            try:
                minutes = int(minutes) if minutes.strip() else None
            except ValueError:
                print(colored("[!] Invalid minutes value. Blocking permanently.", 'yellow'))
                minutes = None
            block_ip(ip, minutes)
            input(colored("\nPress Enter to continue...", 'white'))
        
        elif choice == '2':
            ips = input(colored("\nEnter IP addresses to block (comma separated): ", 'white'))
            minutes = input(colored("Enter minutes to block (leave empty for permanent): ", 'white'))
            try:
                minutes = int(minutes) if minutes.strip() else None
            except ValueError:
                print(colored("[!] Invalid minutes value. Blocking permanently.", 'yellow'))
                minutes = None
            
            for ip in ips.split(','):
                block_ip(ip.strip(), minutes)
            input(colored("\nPress Enter to continue...", 'white'))
        
        elif choice == '3':
            blocked_ips = list_blocked_ips()
            if blocked_ips:
                ip = input(colored("\nEnter IP address to unblock: ", 'white'))
                unblock_ip(ip)
            input(colored("\nPress Enter to continue...", 'white'))
        
        elif choice == '4':
            list_blocked_ips()
            input(colored("\nPress Enter to continue...", 'white'))
        
        elif choice == '5':
            confirm = input(colored("\nAre you sure you want to unblock ALL IPs? (y/n): ", 'red'))
            if confirm.lower() == 'y':
                try:
                    subprocess.run("iptables -F INPUT", shell=True, check=True)
                    subprocess.run("iptables -F OUTPUT", shell=True, check=True)
                    print(colored("[+] All blocked IPs have been unblocked", 'green'))
                except subprocess.CalledProcessError as e:
                    print(colored(f"[!] Error flushing iptables: {str(e)}", 'red'))
            input(colored("\nPress Enter to continue...", 'white'))
        
        elif choice == '0':
            print(colored("\nExiting Laptop IPS. Goodbye!\n", 'magenta', attrs=['bold']))
            break
        
        else:
            print(colored("\n[!] Invalid choice. Please try again.", 'red'))
            time.sleep(1)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
    check_admin()
    
    # Check if iptables is available
    try:
        subprocess.run("iptables --version", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        print(colored("[!] iptables is not available. This script requires iptables to function.", 'red'))
        sys.exit(1)
    
    show_menu()
