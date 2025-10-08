#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import importlib
import importlib.util
from importlib.machinery import SourceFileLoader

# Colors for CLI
RED = "\033[1;31m"
GREEN = "\033[1;32m"
LIGHT_GREEN = "\033[1;92m"  # Light glowing green
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
RESET = "\033[0m"

# Clear terminal function
def clear():
    os.system('clear')

# Banner
def banner():
    clear()
    print(f"""{CYAN}
__________              __                 _________        .__           .__   __    
\______   \_____       |__|_____          /   _____/______  |  |    ____  |__|_/  |_  
 |       _/\__  \      |  |\__  \         \_____  \ \____ \ |  |   /  _ \ |  |\   __\ 
 |    |   \ / __ \_    |  | / __ \_       /        \|  |_> >|  |__(  <_> )|  | |  |   
 |____|_  /(____  //\__|  |(____  /______/_______  /|   __/ |____/ \____/ |__| |__|   
        \/      \/ \______|     \//_____/        \/ |__|                                


        """)
    spaces = 85
    print(" " * spaces + f"{LIGHT_GREEN}V1.2.0{RESET}\n")
    print(f"{RED}         Hacking is not my job, it's my Choice{RESET}\n")
    print(f"{YELLOW}Created by Santa Digital || Presented By Team EHSFB{RESET}\n")

# ---------------- Module Menu ----------------
def menu():
    banner()
    print(f"{GREEN}╔════════════════════════════════════════════════════════╗{RESET}")
    print(f"{GREEN}║  1) {WHITE}Reconnaissance                                     {GREEN}║{RESET}")
    print(f"{GREEN}║  2) {WHITE}Attacks & Exploitation                             {GREEN}║{RESET}")
    print(f"{GREEN}║  3) {WHITE}Forensics & Incident Response                      {GREEN}║{RESET}")
    print(f"{GREEN}║  4) {WHITE}Defensive & Monitoring                             {GREEN}║{RESET}")
    print(f"{GREEN}║  5) {WHITE}Honeypot                                           {GREEN}║{RESET}")
    print(f"{GREEN}║  6) {WHITE}Extra Features                                     {GREEN}║{RESET}")
    print(f"{GREEN}║  7) {WHITE}Reporting                                          {GREEN}║{RESET}")
    print(f"{GREEN}║  0) {WHITE}Exit                                               {GREEN}║{RESET}")
    print(f"{GREEN}╚════════════════════════════════════════════════════════╝{RESET}")

    choice = input(f"\n{CYAN}Rajasploit > {RESET}")
    return choice.strip()

# ---------------- Module Wrappers ----------------
def run_recon_module():
    """
    Wrapper to launch the reconnaissance module from /modules/recon.py.
    Ensures results are saved inside /results/recon/ folder.
    """
    recon_path = os.path.join(os.getcwd(), "modules", "recon.py")
    results_dir = os.path.join(os.getcwd(), "results", "recon")

    # Create results folder for recon if missing
    os.makedirs(results_dir, exist_ok=True)

    if os.path.exists(recon_path):
        print(f"\n{MAGENTA}[+] Launching Reconnaissance module...{RESET}")
        # Run the module in a subprocess so it doesn't block the CLI
        subprocess.run([sys.executable, recon_path], check=False)
    else:
        print(f"{RED}[!] Recon module not found at: {recon_path}{RESET}")
    input("Press Enter to return to menu.")


def attacks_exploitation():
    attacks_path = os.path.join(os.getcwd(), "modules", "attacks_exploitation.py")
    if os.path.exists(attacks_path):
        print(f"\n{MAGENTA}[+] Launching Attacks & Exploitation module...{RESET}")
        subprocess.run([sys.executable, attacks_path], check=False)
    else:
        print(f"\n{MAGENTA}[+] Attacks & Exploitation Module is selected...{RESET}")
        print(f"{YELLOW}[!] attacks_exploitation.py not found. Create: {attacks_path}{RESET}")
    input("Press Enter to return to menu.")

def forensics():
    path = os.path.join(os.getcwd(), "modules", "forensics_incident_response.py")
    if os.path.exists(path):
        print(f"\n{MAGENTA}[+] Launching Forensics & Incident Response module...{RESET}")
        subprocess.run([sys.executable, path], check=False)
    else:
        print(f"{RED}[!] Forensics module not found at: {path}{RESET}")
    input("Press Enter to return to menu.")

def defensive_monitoring():
    path = os.path.join(os.getcwd(), "modules", "defensive_monitoring.py")
    if os.path.exists(path):
        print(f"\n{MAGENTA}[+] Launching Defensive & Monitoring module...{RESET}")
        subprocess.run([sys.executable, path], check=False)
    else:
        print(f"{RED}[!] Defensive & Monitoring module not found at: {path}{RESET}")
    input("Press Enter to return to menu.")

def honeypot():
    path = os.path.join(os.getcwd(), "modules", "honeypot.py")
    if os.path.exists(path):
        print(f"\n{MAGENTA}[+] Launching Honeypot module...{RESET}")
        subprocess.run([sys.executable, path], check=False)
    else:
        print(f"{RED}[!] Honeypot module not found at: {path}{RESET}")
    input("Press Enter to return to menu.")

def extras():
    path = os.path.join(os.getcwd(), "modules", "extra_features.py")
    if os.path.exists(path):
        print(f"\n{MAGENTA}[+] Launching Extra Features module...{RESET}")
        subprocess.run([sys.executable, path], check=False)
    else:
        print(f"{RED}[!] Extra Features module not found: {path}{RESET}")
    input("Press Enter to return to menu.")

def reporting():
    path = os.path.join(os.getcwd(), "modules", "reporting.py")
    if os.path.exists(path):
        print(f"\n{MAGENTA}[+] Launching Reporting module...{RESET}")
        subprocess.run([sys.executable, path], check=False)
    else:
        print(f"{RED}[!] Reporting module not found at: {path}{RESET}")
    input("Press Enter to return to menu.")

# ---------------- Main Loop ----------------
def main():
    while True:
        choice = menu()
        if choice == "1":
            run_recon_module()
        elif choice == "2":
            attacks_exploitation()
        elif choice == "3":
            forensics()
        elif choice == "4":
            defensive_monitoring()
        elif choice == "5":
            honeypot()
        elif choice == "6":
            extras()
        elif choice == "7":
            reporting()
        elif choice == "0":
            print(f"\n{RED}[!] Exiting Rajasploit...{RESET}")
            sys.exit()
        else:
            print(f"{RED}[!] Invalid choice!{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
