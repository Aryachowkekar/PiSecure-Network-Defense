import subprocess
import re
import json
from datetime import datetime
import dns.resolver
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

blocked_websites = {}

def sanitize_website(website):
    """Clean and standardize website input"""
    website = re.sub(r"^https?://", "", website, flags=re.IGNORECASE)
    website = re.sub(r"/.*$", "", website)
    website = re.sub(r"^www\.", "", website, flags=re.IGNORECASE)
    return website.lower().strip()

def resolve_real_ips(domain):
    """Resolve domain to IP addresses with retries"""
    try:
        ips = []
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        
        # Resolve main domain
        try:
            result = resolver.resolve(domain, 'A')
            ips.extend(str(ip) for ip in result)
        except:
            pass
            
        # Resolve www subdomain
        try:
            www_result = resolver.resolve(f"www.{domain}", 'A')
            ips.extend(str(ip) for ip in www_result)
        except:
            pass
            
        return list(set(ips))  # Remove duplicates
        
    except Exception as e:
        logger.error(f"Resolution error for {domain}: {str(e)}")
        return []

def block_website(website):
    """Final working blocking function"""
    try:
        website = sanitize_website(website)
        if not website:
            return {"status": "error", "message": "Invalid domain"}

        logger.info(f"Starting block process for {website}")

        # ===== DNS BLOCKING =====
        blacklist_path = '/etc/dnsmasq.d/blacklist.conf'
        with open(blacklist_path, 'a+') as f:
            f.seek(0)
            content = f.read()
            if f"address=/{website}/0.0.0.0" not in content:
                f.write(f"address=/{website}/0.0.0.0\n")
                f.write(f"address=/www.{website}/0.0.0.0\n")
                f.write(f"address=/*.{website}/0.0.0.0\n")
                logger.info(f"Added DNS blocks for {website}")

        # Restart dnsmasq safely
        try:
            subprocess.run(['systemctl', 'restart', 'dnsmasq'], check=True, timeout=30)
            subprocess.run(['pkill', '-HUP', 'dnsmasq'], stderr=subprocess.DEVNULL, timeout=10)
        except subprocess.TimeoutExpired:
            logger.warning("dnsmasq restart timed out but continuing")

        # ===== NETWORK BLOCKING =====
        ip_list = resolve_real_ips(website)
        logger.info(f"Resolved IPs for {website}: {ip_list}")

        # Add Cloudflare ranges if using Cloudflare
        if any(ip.startswith(('104.', '172.')) for ip in ip_list):
            ip_list.extend(['104.16.0.0/12', '172.64.0.0/13'])
            logger.info("Added Cloudflare IP ranges")

        # Block all IPs in FORWARD chain only (eth1 traffic)
        for ip in ip_list:
            try:
                # Check if rule exists first
                subprocess.run(
                    ['iptables', '-C', 'FORWARD', '-i', 'eth1', '-d', ip, '-j', 'DROP'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                logger.info(f"IP {ip} already blocked in FORWARD chain")
            except subprocess.CalledProcessError:
                subprocess.run(
                    ['iptables', '-A', 'FORWARD', '-i', 'eth1', '-d', ip, '-j', 'DROP'],
                    check=True
                )
                logger.info(f"Blocked {ip} in FORWARD chain")

        blocked_websites[website] = datetime.now().isoformat()
        logger.info(f"Successfully blocked {website}")
        return {"status": "success", "message": f"Blocked {website}"}

    except Exception as e:
        logger.error(f"Blocking error: {str(e)}")
        return {"status": "error", "message": f"Failed to block: {str(e)}"}

def unblock_website(website):
    """Safe unblocking function"""
    try:
        website = sanitize_website(website)
        if website not in blocked_websites:
            return {"status": "error", "message": "Not blocked"}

        logger.info(f"Starting unblock process for {website}")

        # Remove DNS blocking
        blacklist_path = '/etc/dnsmasq.d/blacklist.conf'
        try:
            with open(blacklist_path, 'r') as f:
                lines = f.readlines()
            with open(blacklist_path, 'w') as f:
                for line in lines:
                    if website not in line:
                        f.write(line)
            subprocess.run(['systemctl', 'restart', 'dnsmasq'], check=True, timeout=30)
            logger.info(f"Removed DNS blocks for {website}")
        except FileNotFoundError:
            pass

        # Remove network blocking
        ip_list = resolve_real_ips(website)
        for ip in ip_list:
            try:
                subprocess.run(
                    ['iptables', '-D', 'FORWARD', '-i', 'eth1', '-d', ip, '-j', 'DROP'],
                    stderr=subprocess.DEVNULL
                )
                logger.info(f"Unblocked IP: {ip}")
            except subprocess.CalledProcessError:
                pass

        # Remove from blocked list
        del blocked_websites[website]
        logger.info(f"Successfully unblocked {website}")
        return {"status": "success", "message": f"Unblocked {website}"}

    except Exception as e:
        logger.error(f"Unblocking error: {str(e)}")
        return {"status": "error", "message": f"Failed to unblock: {str(e)}"}

def list_blocked_websites():
    """Return current blocked websites"""
    return {
        "status": "success",
        "blocked_websites": [
            {"website": site, "timestamp": blocked_websites[site]}
            for site in blocked_websites
        ]
    }
