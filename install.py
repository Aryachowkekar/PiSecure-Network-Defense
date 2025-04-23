#!/usr/bin/env python3

import os
import subprocess
import bcrypt
import json
import getpass
import time

# ASCII Art Logo of PiSecure
pisecure_logo = r"""
        ⠀⠀⠀⢀⣴⣶⣶⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣶⣶⣦⡀
        ⠀⠀⣴⣿⣿⡿⠛⠛⠛⠻⢷⣤⠀⠀⠀⠀⠀⠀⣠⣾⠟⠋⠉⠙⢿⣿⣿⣷⣄
        ⠀⣼⣿⠋⠀⠀⠀⢀⣀⠀⠈⢻⣿⣄⠀⠀⣠⣿⣿⣧⣤⣤⣤⣤⣤⣼⠟⠉⣿
        ⢀⣿⡏⠀⠀⠀⠀⠈⠉⠀⠀⠀⠙⢿⣷⣾⣿⡿⠛⠛⠛⠉⠉⠉⠉⠀⠀⢸⣿
        ⢸⣿⡇⠀⠀⣠⣶⣶⣶⣶⣶⣤⠀⠀⠈⠉⠁⠀⠀⢠⣶⣶⣶⣶⣶⣆⠀⠀⣿
        ⠈⣿⣧⠀⠘⣿⣯⠁⠀⢀⣽⣿⠀⠀⠀⠀⠀⠀⠀⠘⣿⣯⠉⢹⣿⠇⠀⣼⣿
        ⠀⠹⣿⣷⣄⠈⠛⠃⢀⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢃⣿⡿⣠⣾⣿⠏
        ⠀⠀⠈⠻⢿⣿⣷⣶⣶⣶⣶⣶⣤⣤⣤⣤⣤⣤⣤⣤⣶⣾⣿⣿⣿⠿⠋
"""

def welcome():
    os.system("clear")
    print("\033[1;92m" + pisecure_logo + "\033[0m")
    print("\033[1;94m" + "="*60 + "\033[0m")
    print("\033[1;92mWelcome to PiSecure - An Integrated Firewall for Network Security\033[0m")
    print("\033[1;90mAuthor: Arya Chowkekar - https://github.com/Aryachowkekar\033[0m")
    print("\033[1;94m" + "="*60 + "\n\033[0m")
    time.sleep(2)

def check_root():
    if os.geteuid() != 0:
        print("\033[1;91m[✘] Please run this script as root!\033[0m")
        exit(1)

def install_packages():
    print("\n\033[1;93m[~] Installing required packages...\033[0m")
    subprocess.run(["apt-get", "update", "-y"])
    subprocess.run(["apt-get", "upgrade", "-y"])
    packages = ["nmap", "iptables", "python3-pip", "python3-flask", "python3-flask-cors"]
    subprocess.run(["apt-get", "install", "-y"] + packages)
    subprocess.run(["pip3", "install", "flask", "flask-cors", "bcrypt"])
    print("\033[1;92m[✔] All packages installed!\033[0m\n")

def set_password():
    print("\033[1;94m🔐 Let's set your login password for PiSecure dashboard\033[0m")
    while True:
        password = getpass.getpass("Set password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password == confirm:
            break
        else:
            print("\033[1;91m[✘] Passwords do not match. Try again.\033[0m")

    # Hash the password
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    config = {"hashed_password": hashed}
    with open("config.json", "w") as f:
        json.dump(config, f)
    
    print("\n\033[1;92m[✔] Password set and stored securely in config.json!\033[0m")

def finish():
    print("\n\033[1;92m🎉 PiSecure installation completed successfully!\033[0m")
    print("➡️  You can now run your Flask dashboard with: \033[1;97mpython3 app.py\033[0m")
    print("🛡️  Happy Securing!\n")

if __name__ == "__main__":
    welcome()
    check_root()
    install_packages()
    set_password()
    finish()
