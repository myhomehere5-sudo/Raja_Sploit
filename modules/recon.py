#!/usr/bin/env python3
"""
recon.py - Recon module for Rajasploit (fixed entrypoint & improved scanners/report)

All file outputs are written under: results/recon/
"""

import os
import subprocess
import time
import sys
import json
import glob
import socket
import threading
import re
from datetime import datetime
from random import randint
from colorama import init, Fore, Style

# Ensure matplotlib will save images in headless environments
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from concurrent.futures import ThreadPoolExecutor, as_completed

# optional requests import
try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

init(autoreset=True)

# Colors
RED = Fore.RED + Style.BRIGHT
GREEN = Fore.GREEN + Style.BRIGHT
YELLOW = Fore.YELLOW + Style.BRIGHT
CYAN = Fore.CYAN + Style.BRIGHT
MAGENTA = Fore.MAGENTA + Style.BRIGHT
RESET = Style.RESET_ALL

# Ensure top-level directories exist
os.makedirs("results", exist_ok=True)
os.makedirs("results/graphs", exist_ok=True)

# Dedicated results folder for the reconnaissance module
RESULTS_DIR = os.path.join(os.getcwd(), "results", "recon")
os.makedirs(RESULTS_DIR, exist_ok=True)

# Session start timestamp: will be set in main() so each entry into the module is a fresh session
SESSION_START = None

# SESSION_LOGS: store per-option structured summaries so report can present them
SESSION_LOGS = {
    'ping': [],
    'port_scan': [],
    'banner': [],
    'whois': [],
    'geoip': [],
    'mobile': [],
    'domain_enum': [],
    'auto_vuln': []
}

# Utility functions
def clear():
    os.system("cls" if sys.platform.startswith('win') else "clear")

def banner():
    clear()
    print(f"{CYAN}===== Reconnaissance Module ====={RESET}")

def menu():
    banner()
    print(f"{GREEN}1){RESET} Ping / Host Discovery")
    print(f"{GREEN}2){RESET} TCP & UDP Port Scan (Top 1000 ports + OS + Service)")
    print(f"{GREEN}3){RESET} Banner Grabbing")
    print(f"{GREEN}4){RESET} Whois Lookup")
    print(f"{GREEN}5){RESET} GeoIP Lookup")
    print(f"{GREEN}6){RESET} Mobile Info Lookup")
    print(f"{GREEN}7){RESET} Domain and TLD Enumeration (recon-ng)")
    print(f"{GREEN}8){RESET} Automatic Vulnerability Scan (6K+ ports)")
    print(f"{GREEN}9){RESET} Generate Professional Report")
    print(f"{GREEN}0){RESET} Exit")
    choice = input(f"\n{CYAN}Recon > {RESET}")
    return choice.strip()

# Cross-platform which
def shutil_which(cmd):
    from shutil import which
    try:
        return which(cmd)
    except Exception:
        paths = os.environ.get('PATH', '').split(os.pathsep)
        extlist = ['']
        if sys.platform.startswith('win'):
            pathext = os.environ.get('PATHEXT', '').split(os.pathsep)
            extlist = pathext
        for p in paths:
            p = p.strip('"')
            exe = os.path.join(p, cmd)
            for ext in extlist:
                candidate = exe + ext
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    return candidate
        return None

# Networking helpers
def tcp_connect(target_ip, port, timeout=1.0):
    """Return True if TCP connect succeeds, False otherwise."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((target_ip, port)) == 0
    except Exception:
        raise

# Helper to safely write small files
def safe_write(path, content):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass
    with open(path, 'w', encoding='utf-8', errors='ignore') as fh:
        fh.write(content)

# ---------------- Option 1 ----------------
def ping_host():
    target = input(f"{YELLOW}Enter target IP/domain: {RESET}").strip()
    if not target:
        print(f"{RED}[!] No target provided.{RESET}")
        input("Press Enter to return to menu.")
        return
    print(f"{MAGENTA}[+] Pinging target...{RESET}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(RESULTS_DIR, f'ping_{target.replace("/", "")}_{timestamp}.txt')
    try:
        cmd = ["ping", "-c", "4", target] if not sys.platform.startswith('win') else ["ping", "-n", "4", target]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        safe_write(out_file, proc.stdout)
        # Print to screen (user requested)
        print(proc.stdout)
        SESSION_LOGS['ping'].append({'target': target, 'file': out_file, 'time': timestamp, 'reachable': proc.returncode == 0})
        print(f"{GREEN}[+] Ping output saved: {out_file}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Ping failed: {e}{RESET}")
        SESSION_LOGS['ping'].append({'target': target, 'error': str(e), 'time': timestamp})
    input("Press Enter to return to menu.")

# ---------------- Option 2 (TCP-only with live progress) ----------------
def port_scan():
    target = input(f"{YELLOW}Enter target IP/domain: {RESET}").strip()
    if not target:
        print(f"{RED}[!] No target provided.{RESET}")
        input("Press Enter to return to menu.")
        return

    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        print(f"{RED}[!] Failed to resolve '{target}': {e}{RESET}")
        input("Press Enter to return to menu.")
        return

    print(f"{MAGENTA}[+] Starting TCP-only scan against {target} ({target_ip}){RESET}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(RESULTS_DIR, f'port_scan_{target.replace("/","")}_{timestamp}.txt')

    start_port = 1
    end_port = 1000
    ports = list(range(start_port, end_port + 1))
    total = len(ports)

    completed = 0
    completed_lock = threading.Lock()
    open_ports = []
    open_lock = threading.Lock()
    network_issues = False
    network_messages = []

    stop_progress = threading.Event()
    def progress_loop():
        while not stop_progress.is_set():
            with completed_lock:
                pct = (completed / total) * 100 if total else 100.0
                sys.stdout.write(f"\r{CYAN}TCP scan progress: {completed}/{total} ports scanned ({pct:.1f}%) {RESET}")
                sys.stdout.flush()
            time.sleep(0.2)
        with completed_lock:
            pct = (completed / total) * 100 if total else 100.0
            sys.stdout.write(f"\r{GREEN}TCP scan completed: {completed}/{total} ports ({pct:.1f}%) ✅{RESET}\n")
            sys.stdout.flush()

    def worker(port):
        nonlocal completed, network_issues
        try:
            if tcp_connect(target_ip, port, timeout=0.7):
                with open_lock:
                    open_ports.append(port)
        except Exception as e:
            network_issues = True
            try:
                network_messages.append(f"Port {port}: network error: {e}")
            except Exception:
                network_messages.append(f"Port {port}: network error")
        finally:
            with completed_lock:
                completed += 1
        return port

    t_progress = threading.Thread(target=progress_loop, daemon=True)
    t_progress.start()

    max_workers = 150 if total >= 150 else total
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(worker, p) for p in ports]
            for _ in as_completed(futures):
                pass
    except Exception as e:
        print(f"\n{RED}[!] Scanning aborted due to exception: {e}{RESET}")
    finally:
        stop_progress.set()
        t_progress.join(timeout=1)

    try:
        with open(out_file, 'w') as fh:
            fh.write(f"Open TCP ports for {target} ({target_ip}) scanned at {timestamp}\n")
            if open_ports:
                for p in sorted(open_ports):
                    fh.write(f"{p}\n")
            else:
                fh.write(f"No open TCP ports found (1-{end_port}) for {target} ({target_ip})\n")
        print(f"{GREEN}[+] TCP scan saved: {out_file}{RESET}")
        # Log summary
        SESSION_LOGS['port_scan'].append({'target': target, 'ip': target_ip, 'file': out_file, 'open_ports': sorted(open_ports), 'time': timestamp})
    except Exception as e:
        print(f"{RED}[!] Failed to save TCP scan results: {e}{RESET}")
        SESSION_LOGS['port_scan'].append({'target': target, 'error': str(e), 'time': timestamp})

    if network_issues:
        print(f"{YELLOW}[!] Some network-level errors occurred during scanning (showing up to 6):{RESET}")
        for msg in network_messages[:6]:
            print(f"  {YELLOW}{msg}{RESET}")
        if len(network_messages) > 6:
            print(f"  {YELLOW}... and {len(network_messages)-6} more ...{RESET}")

    # Targeted nmap follow-up on discovered open TCP ports
    if open_ports:
        ports_arg = ",".join(map(str, sorted(open_ports)))
        nmap_out = os.path.join(RESULTS_DIR, f'port_scan_nmap_{target.replace("/","")}_{timestamp}.txt')
        nmap_bin = shutil_which("nmap")
        if nmap_bin:
            nmap_cmd = [nmap_bin, "-sS", "-sV", "-O", "-p", ports_arg, target, "-oN", nmap_out]
            print(f"{MAGENTA}[+] Running targeted Nmap service/OS probe on discovered TCP ports ({len(open_ports)} ports) ...{RESET}")
            try:
                subprocess.run(nmap_cmd, check=False)
                print(f"{GREEN}[+] Nmap results saved: {nmap_out}{RESET}")
                SESSION_LOGS['port_scan'][-1].update({'nmap_file': nmap_out})
            except Exception as e:
                print(f"{YELLOW}[!] Nmap follow-up failed: {e}{RESET}")
        else:
            print(f"{YELLOW}[!] nmap not found on PATH; skipping targeted nmap follow-up.{RESET}")
    else:
        print(f"{CYAN}[+] No open TCP ports found, skipping Nmap service probe.{RESET}")

    input("Press Enter to return to menu.")

# ---------------- Option 3 ----------------
def banner_grab():
    target = input(f"{YELLOW}Enter target IP/domain: {RESET}").strip()
    if not target:
        print(f"{RED}[!] No target provided.{RESET}")
        input("Press Enter to return to menu.")
        return
    print(f"{MAGENTA}[+] Running Banner Grabbing...{RESET}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(RESULTS_DIR, f'banner_grab_{target.replace("/","")}_{timestamp}.txt')
    nmap_bin = shutil_which("nmap")
    if not nmap_bin:
        print(f"{YELLOW}[!] nmap not found on PATH. Banner grabbing via nmap skipped.{RESET}")
        SESSION_LOGS['banner'].append({'target': target, 'error': 'nmap not found', 'time': timestamp})
        input("Press Enter to return to menu.")
        return
    try:
        subprocess.run([nmap_bin, "-sV", "-Pn", target, "-oN", out_file], check=False)
        print(f"{GREEN}[+] Banner grab saved: {out_file}{RESET}")
        SESSION_LOGS['banner'].append({'target': target, 'file': out_file, 'time': timestamp})
    except Exception as e:
        print(f"{RED}[!] Banner grab failed: {e}{RESET}")
        SESSION_LOGS['banner'].append({'target': target, 'error': str(e), 'time': timestamp})
    input("Press Enter to return to menu.")

# ---------------- Option 4 ----------------
def whois_lookup():
    print(f"{MAGENTA}[+] Whois Lookup{RESET}")
    domains = input(f"{YELLOW}Enter domains/IPs (comma-separated): {RESET}")
    if not domains.strip():
        print(f"{RED}[!] No input provided.{RESET}")
        input("Press Enter to return to menu.")
        return
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]

    def fetch_whois(domain):
        try:
            whois_bin = shutil_which("whois")
            if not whois_bin:
                return {"domain": domain, "error": "whois command not installed"}
            result = subprocess.check_output([whois_bin, domain], stderr=subprocess.STDOUT, text=True)
            safe_name = domain.replace('/', '').replace(':', '')
            fname = os.path.join(RESULTS_DIR, f"whois_{safe_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt")
            with open(fname, "w") as fh:
                fh.write(result)
            return {"domain": domain, "result": result, "file": fname}
        except subprocess.CalledProcessError as e:
            return {"domain": domain, "error": str(e)}
        except FileNotFoundError:
            return {"domain": domain, "error": "whois command not installed"}

    print(f"{CYAN}[+] Running Whois lookups...{RESET}")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_whois, d): d for d in domain_list}
        for future in as_completed(futures):
            res = future.result()
            if "error" in res:
                print(f"{RED}[!] Error fetching Whois for {res['domain']}: {res['error']}{RESET}")
                SESSION_LOGS['whois'].append({'domain': res['domain'], 'error': res['error']})
            else:
                snippet = res['result'][:800].rstrip()
                print(f"{GREEN}[+] Whois for {res['domain']} (saved to {res['file']}):\n{snippet}...\n{RESET}")
                SESSION_LOGS['whois'].append({'domain': res['domain'], 'file': res['file']})

    input("Press Enter to return to menu.")

# ---------------- Option 5 ----------------
def geoip_lookup():
    print(f"{MAGENTA}[+] GeoIP Lookup{RESET}")
    targets = input(f"{YELLOW}Enter IPs/domains (comma-separated): {RESET}")
    if not targets.strip():
        print(f"{RED}[!] No input provided.{RESET}")
        input("Press Enter to return to menu.")
        return
    target_list = [t.strip() for t in targets.split(",") if t.strip()]

    def fetch_geoip_cli(target):
        try:
            geo_bin = shutil_which("geoiplookup")
            if geo_bin:
                result = subprocess.check_output([geo_bin, target], stderr=subprocess.STDOUT, text=True)
                fname = os.path.join(RESULTS_DIR, f'geoip_{target}_{datetime.now().strftime("%Y%m%d%H%M%S")}.txt')
                with open(fname, 'w') as fh:
                    fh.write(result)
                return {"target": target, "result": result, 'file': fname}
            else:
                return {"target": target, "error": "geoiplookup not installed"}
        except subprocess.CalledProcessError as e:
            return {"target": target, "error": str(e)}
        except FileNotFoundError:
            return {"target": target, "error": "geoiplookup not installed"}

    def fetch_geoip_api(target):
        try:
            r = requests.get(f"https://ipinfo.io/{target}/json", timeout=8)
            r.raise_for_status()
            data = r.json()
            fname = os.path.join(RESULTS_DIR, f'geoip_{target}_{datetime.now().strftime("%Y%m%d%H%M%S")}.json')
            with open(fname, 'w') as fh:
                json.dump(data, fh, indent=2)
            out = json.dumps(data, indent=2)
            return {"target": target, "result": out, 'file': fname}
        except Exception as e:
            return {"target": target, "error": str(e)}

    print(f"{CYAN}[+] Running GeoIP lookups...{RESET}")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for t in target_list:
            futures[executor.submit(fetch_geoip_cli, t)] = (t, 'cli')
        for future in as_completed(list(futures.keys())):
            info = futures[future]
            res = future.result()
            if 'error' in res and REQUESTS_AVAILABLE:
                fallback = fetch_geoip_api(info[0])
                if 'error' in fallback:
                    print(f"{RED}[!] Error fetching GeoIP for {info[0]}: {fallback['error']}{RESET}")
                    SESSION_LOGS['geoip'].append({'target': info[0], 'error': fallback['error']})
                else:
                    print(f"{GREEN}[+] GeoIP for {info[0]} (api fallback, saved to {fallback.get('file')}):\n{fallback['result']}{RESET}")
                    SESSION_LOGS['geoip'].append({'target': info[0], 'file': fallback.get('file')})
            elif 'error' in res:
                print(f"{RED}[!] Error fetching GeoIP for {info[0]}: {res['error']}{RESET}")
                SESSION_LOGS['geoip'].append({'target': info[0], 'error': res['error']})
            else:
                print(f"{GREEN}[+] GeoIP for {info[0]}:\n{res['result']}{RESET}")
                SESSION_LOGS['geoip'].append({'target': info[0], 'file': res.get('file')})

    input("Press Enter to return to menu.")

# ---------------- Option 6 ----------------
def mobile_lookup():
    print(f"{MAGENTA}[+] Mobile Info Lookup{RESET}")
    numbers = input(f"{YELLOW}Enter mobile numbers (comma-separated, with country code): {RESET}")
    if not numbers.strip():
        print(f"{RED}[!] No numbers provided.{RESET}")
        input("Press Enter to return to menu.")
        return
    numbers_list = [num.strip() for num in numbers.split(",") if num.strip()]

    API_KEY = os.environ.get('NUMVERIFY_KEY', 'YOUR_REAL_API_KEY')
    API_URL = "http://apilayer.net/api/validate"

    def fetch_mobile_info_api(number):
        try:
            params = {"access_key": API_KEY, "number": number}
            r = requests.get(API_URL, params=params, timeout=10)
            r.raise_for_status()
            data = r.json()
            fname = os.path.join(RESULTS_DIR, f'mobile_{number.replace("+","").replace(" ","")}_{datetime.now().strftime("%Y%m%d%H%M%S")}.json')
            with open(fname, 'w') as fh:
                json.dump(data, fh, indent=2)
            return {"number": number, "data": data, 'file': fname}
        except Exception as e:
            return {"number": number, "error": str(e)}

    def simple_local_check(number):
        n = number.lstrip('+').replace(' ', '').replace('-', '')
        valid = n.isdigit() and 7 <= len(n) <= 15
        return {"number": number, "data": {"valid": valid, "note": "Local format validation only"}}

    results = []
    print(f"{CYAN}[+] Fetching mobile info...{RESET}")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for num in numbers_list:
            if REQUESTS_AVAILABLE and API_KEY != 'YOUR_REAL_API_KEY':
                futures[executor.submit(fetch_mobile_info_api, num)] = num
            else:
                futures[executor.submit(simple_local_check, num)] = num

        for future in as_completed(futures):
            res = future.result()
            number = res.get('number')
            if 'error' in res:
                print(f"{RED}[!] Error fetching {number}: {res['error']}{RESET}")
                results.append({"number": number, "error": res['error']})
                SESSION_LOGS['mobile'].append({'number': number, 'error': res['error']})
            else:
                data = res.get('data') or res.get('data')
                if isinstance(data, dict):
                    valid = data.get('valid')
                    country = data.get('country_name') or data.get('country')
                    carrier = data.get('carrier') or data.get('line_provider')
                    location = data.get('location')
                else:
                    valid = country = carrier = location = None

                print(f"{GREEN}[+] Number: {number}, Valid: {valid}, Country: {country}, Carrier: {carrier}, Location: {location}{RESET}")
                if isinstance(data, dict):
                    fname = res.get('file') if res.get('file') else os.path.join(RESULTS_DIR, f"mobile_{number.replace('+','').replace(' ','').replace('/','_')}.json")
                    try:
                        if not res.get('file'):
                            with open(fname, 'w') as fh:
                                json.dump(data, fh, indent=2)
                        print(f"  {CYAN}Saved detailed result to: {fname}{RESET}")
                        results.append({"number": number, "file": fname, "data": data})
                        SESSION_LOGS['mobile'].append({'number': number, 'file': fname})
                    except Exception:
                        results.append({"number": number, "data": data})
                        SESSION_LOGS['mobile'].append({'number': number, 'data': data})
                else:
                    results.append({"number": number, "data": data})
                    SESSION_LOGS['mobile'].append({'number': number, 'data': data})

    if not REQUESTS_AVAILABLE:
        print(f"\n{YELLOW}[!] Note: the 'requests' library is not available. Install it with: pip3 install requests\n{RESET}")
    elif API_KEY == 'YOUR_REAL_API_KEY':
        print(f"\n{YELLOW}[!] Note: No NUMVERIFY_KEY provided. Set environment variable NUMVERIFY_KEY for carrier details.{RESET}")

    input("Press Enter to return to menu.")

# ---------------- Option 7 (Launch recon-ng) ----------------
def domain_tld_enum():
    print(f"{MAGENTA}[+] Launching Recon-ng framework...{RESET}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        recon_bin = shutil_which("recon-ng")
        if recon_bin:
            SESSION_LOGS['domain_enum'].append({'action': 'launched recon-ng', 'time': timestamp})
            subprocess.run([recon_bin], check=False)
        else:
            # Some installs use recon-ng as a script available in python path
            try:
                subprocess.run(["recon-ng"], check=False)
                SESSION_LOGS['domain_enum'].append({'action': 'launched recon-ng (fallback)', 'time': timestamp})
            except FileNotFoundError:
                print(f"{YELLOW}[!] recon-ng not found on PATH. Install recon-ng or adjust your PATH.{RESET}")
                SESSION_LOGS['domain_enum'].append({'error': 'recon-ng not found', 'time': timestamp})
    except Exception as e:
        print(f"{RED}[!] Failed to launch recon-ng: {e}{RESET}")
        SESSION_LOGS['domain_enum'].append({'error': str(e), 'time': timestamp})
    input("Press Enter to return to menu.")

# ---------------- Option 8 (auto_vuln_scan with robust progress + improved scanner handling) ----------------
def auto_vuln_scan():
    """
    Full auto vulnerability scan (standalone):
      - Port scan (1-6000) with live percentage progress and network issue reporting
      - Nmap vulnerability scan (with progress parsing) -> saved to RESULTS_DIR/
      - Nikto, WPScan, SSLScan with smarter retries/timeouts and basic parsing to include in report
    Note: This function will NOT auto-call generate_report(). Use option 9 to build the final report.
    """
    import itertools
    import re
    import time
    from datetime import datetime as _dt

    # Nested helper: run subprocess with streaming progress UI (spinner or parsed percent)
    def run_command_with_progress(cmd, label, outfile=None, parse_progress=None, max_duration=None, retries=1):
        """
        Run subprocess streaming stdout and show a spinner or parsed percent.
        Returns True if process returned 0, False otherwise.
        Retries the whole run up to retries times on failure.
        """
        attempt = 1
        while attempt <= retries:
            spinner = itertools.cycle(['-', '\\', '|', '/'])
            start = time.time()
            last_line = ""
            percent = None
            f_out = None

            if outfile:
                try:
                    os.makedirs(os.path.dirname(outfile), exist_ok=True)
                    f_out = open(outfile, 'w', encoding='utf-8', errors='ignore')
                except Exception as e:
                    print(f"{YELLOW}[!] Couldn't open output file {outfile}: {e}{RESET}")
                    f_out = None

            print(f"{CYAN}[+] {label} (attempt {attempt}/{retries}) ...{RESET}")
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            except FileNotFoundError:
                print(f"{YELLOW}[!] Command not found: {cmd[0]}. Skipping {label}.{RESET}")
                if f_out:
                    f_out.close()
                return False
            except Exception as e:
                print(f"{RED}[!] Failed to start {label}: {e}{RESET}")
                if f_out:
                    f_out.close()
                return False

            try:
                while True:
                    elapsed = int(time.time() - start)
                    if max_duration and elapsed > max_duration:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        print(f"\n{YELLOW}[!] {label} timed out after {max_duration} seconds and was terminated.{RESET}")
                        break

                    line = proc.stdout.readline()
                    if line == '' and proc.poll() is not None:
                        break
                    if line:
                        last_line = line.rstrip()
                        if f_out:
                            try:
                                f_out.write(line)
                            except Exception:
                                pass
                        if parse_progress:
                            try:
                                p = parse_progress(line)
                                if p is not None:
                                    percent = max(0.0, min(100.0, float(p)))
                            except Exception:
                                pass

                    elapsed = int(time.time() - start)
                    if percent is not None:
                        sys.stdout.write(f"\r{CYAN}{label} — {percent:.1f}% complete — elapsed {elapsed}s {RESET}")
                    else:
                        spinner_char = next(spinner)
                        display_line = (last_line[:60] + '...') if len(last_line) > 63 else last_line
                        sys.stdout.write(f"\r{CYAN}{spinner_char} {label} — elapsed {elapsed}s — {display_line:63s}{RESET}")
                    sys.stdout.flush()
                    time.sleep(0.06)

                try:
                    ret = proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    ret = -1

                elapsed = int(time.time() - start)
                if percent is not None:
                    sys.stdout.write(f"\r{GREEN}{label} — {percent:.1f}% complete — elapsed {elapsed}s ✅{RESET}\n")
                else:
                    sys.stdout.write(f"\r{GREEN}{label} completed — elapsed {elapsed}s ✅{RESET}\n")
                sys.stdout.flush()

                if f_out:
                    try:
                        f_out.close()
                    except Exception:
                        pass

                if ret == 0:
                    return True
                else:
                    print(f"{YELLOW}[!] {label} exited with code {ret}.\n{RESET}")
            except Exception as e:
                try:
                    proc.kill()
                except Exception:
                    pass
                print(f"\n{RED}[!] {label} failed while running: {e}{RESET}")
            finally:
                if f_out:
                    try:
                        f_out.close()
                    except Exception:
                        pass

            attempt += 1
            print(f"{YELLOW}[!] Retrying {label} (next attempt {attempt}/{retries})...{RESET}")
            time.sleep(1)

        return False

    def parse_nmap_progress(line):
        m = re.search(r'(\d{1,3}(?:\.\d+)?)\s*%\s*(?:done)?', line)
        if m:
            try:
                return float(m.group(1))
            except Exception:
                return None
        m2 = re.search(r'Percent done:\s*(\d{1,3}(?:\.\d+)?)', line)
        if m2:
            try:
                return float(m2.group(1))
            except Exception:
                return None
        return None

    def parse_nmap_summary(nmap_path):
        """Basic nmap parsing: get open ports and service/version lines and any 'VULNERABLE' mentions."""
        summary = {'open_ports': [], 'services': [], 'raw_snippet': None}
        try:
            with open(nmap_path, 'r', encoding='utf-8', errors='ignore') as fh:
                data = fh.read()
            summary['raw_snippet'] = data[:3000]
            # Find the PORT table block
            lines = data.splitlines()
            in_port_section = False
            for line in lines:
                if re.match(r'^PORT\s+STATE\s+SERVICE', line):
                    in_port_section = True
                    continue
                if in_port_section:
                    if not line.strip():
                        in_port_section = False
                        continue
                    parts = line.split()
                    # typical: "80/tcp open  http  Apache httpd 2.4"
                    if len(parts) >= 3:
                        port_part = parts[0]
                        state = parts[1]
                        service = parts[2]
                        if 'open' in state.lower():
                            summary['open_ports'].append(port_part)
                            svc_line = ' '.join(parts[2:])
                            summary['services'].append(svc_line)
            # also capture heuristics for vulnerabilities (CVE, VULNERABLE, etc.)
            vulns = re.findall(r'(CVE-\d{4}-\d+)', data, flags=re.IGNORECASE)
            if vulns:
                summary['vulns'] = sorted(set(vulns))
            else:
                summary['vulns'] = []
        except Exception as e:
            summary['error'] = str(e)
        return summary

    def parse_nikto_summary(nikto_path):
        summary = {'issues': [], 'raw_snippet': None}
        try:
            with open(nikto_path, 'r', encoding='utf-8', errors='ignore') as fh:
                data = fh.read()
            summary['raw_snippet'] = data[:3000]
            # Nikto issues often reference "OSVDB-" or "id:" or "OSVDB"
            for match in re.findall(r'(OSVDB-\d+)', data, flags=re.IGNORECASE):
                summary['issues'].append(match)
            # Also extract lines that look like issues (heuristic)
            for line in data.splitlines():
                if ('OSVDB' in line) or ('Nikto' in line and ':' in line) or re.search(r'\b(SERVER:|Server:|X-Powered-By:)\b', line, flags=re.IGNORECASE):
                    summary['issues'].append(line.strip())
            # dedupe
            summary['issues'] = list(dict.fromkeys(summary['issues']))[:40]
        except Exception as e:
            summary['error'] = str(e)
        return summary

    def parse_wpscan_summary(wp_path):
        summary = {'interesting': [], 'raw_snippet': None}
        try:
            with open(wp_path, 'r', encoding='utf-8', errors='ignore') as fh:
                data = fh.read()
            summary['raw_snippet'] = data[:3000]
            # WPScan outputs "Vulnerable", "Version", "Listing found", etc.
            for line in data.splitlines():
                if any(k in line for k in ['Vulnerable', 'vulnerable', 'Outdated', 'Interesting', 'Found', 'WordPress version']):
                    summary['interesting'].append(line.strip())
            # Extract CVE references
            cves = re.findall(r'(CVE-\d{4}-\d+)', data)
            if cves:
                summary['cves'] = sorted(set(cves))
        except Exception as e:
            summary['error'] = str(e)
        return summary

    def parse_sslscan_summary(ssl_path):
        summary = {'protocols': [], 'cert_info': None, 'raw_snippet': None}
        try:
            with open(ssl_path, 'r', encoding='utf-8', errors='ignore') as fh:
                data = fh.read()
            summary['raw_snippet'] = data[:3000]
            # Extract lines like "Accepted  TLS1.2  ECDHE-RSA-AES256-GCM-SHA384 ..."
            for line in data.splitlines():
                if line.strip().startswith('Accepted') or 'Server certificate' in line or 'Subject:' in line or 'Issuer:' in line:
                    summary['protocols'].append(line.strip())
            # try to capture certificate subject/issuer block if present
            subj = re.search(r'Subject:\s*(.+)', data)
            iss = re.search(r'Issuer:\s*(.+)', data)
            if subj:
                summary['cert_info'] = {'subject': subj.group(1).strip(), 'issuer': iss.group(1).strip() if iss else None}
        except Exception as e:
            summary['error'] = str(e)
        return summary

    # --- Begin scan flow (user input) ---
    target = input(f"{YELLOW}Enter target domain/IP: {RESET}").strip()
    if not target:
        print(f"{RED}[!] No target provided.{RESET}")
        input("Press Enter to return to menu.")
        return

    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        resolved_ip = None

    print(f"{MAGENTA}[+] Checking target reachability...{RESET}")
    reachable = os.system(f"ping -c 2 {target} > /dev/null 2>&1") == 0 if not sys.platform.startswith('win') else os.system(f"ping -n 2 {target} >nul 2>&1") == 0
    if not reachable:
        print(f"{RED}[!] Target {target} is unreachable. Aborting scan.{RESET}")
        input("Press Enter to return to menu.")
        return

    run_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    port_file = os.path.join(RESULTS_DIR, f"run{run_id}_open_ports.txt")
    nmap_file = os.path.join(RESULTS_DIR, f"run{run_id}_nmap_vuln.txt")
    nikto_file = os.path.join(RESULTS_DIR, f"run{run_id}_nikto.txt")
    wpscan_file = os.path.join(RESULTS_DIR, f"run{run_id}_wpscan.txt")
    ssl_file = os.path.join(RESULTS_DIR, f"run{run_id}_sslscan.txt")

    # ------------------ Port scan (1-6000) with background progress ------------------
    start_port = 1
    end_port = 6000
    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    completed = 0
    completed_lock = threading.Lock()
    open_ports = []
    open_lock = threading.Lock()
    network_issues = False
    network_messages = []

    stop_progress = threading.Event()

    def progress_thread():
        while not stop_progress.is_set():
            with completed_lock:
                pct = (completed / total) * 100 if total else 100.0
                sys.stdout.write(f"\r{CYAN}Port Scan Progress: {completed}/{total} ports ({pct:.1f}%) {RESET}")
                sys.stdout.flush()
            time.sleep(0.25)
        with completed_lock:
            pct = (completed / total) * 100 if total else 100.0
            sys.stdout.write(f"\r{GREEN}Port Scan completed: {completed}/{total} ports ({pct:.1f}%) ✅{RESET}\n")
            sys.stdout.flush()

    def worker_port(p):
        nonlocal completed, network_issues
        try:
            addr = resolved_ip if resolved_ip else target
            if tcp_connect(addr, p, timeout=0.55):
                with open_lock:
                    open_ports.append(p)
        except Exception as e:
            network_issues = True
            try:
                network_messages.append(f"Port {p}: {str(e)}")
            except Exception:
                network_messages.append(f"Port {p}: network error")
        finally:
            with completed_lock:
                completed += 1
        return p

    print(f"{CYAN}[+] Scanning ports (1-6000). Please wait...{RESET}")
    prog_thread = threading.Thread(target=progress_thread, daemon=True)
    prog_thread.start()

    max_workers = 250 if total >= 250 else total
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(worker_port, p) for p in ports]
            for _ in as_completed(futures):
                pass
    except Exception as e:
        print(f"\n{RED}[!] Port scanning aborted due to exception: {e}{RESET}")
    finally:
        stop_progress.set()
        prog_thread.join(timeout=2)

    # Save port results
    try:
        with open(port_file, 'w') as pf:
            if open_ports:
                pf.write(f"Open ports for {target} (scan run {run_id}):\n")
                for p in sorted(open_ports):
                    pf.write(f"{p}\n")
            else:
                pf.write("No open ports found\n")
        print(f"{GREEN}[+] Open ports saved to {port_file}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Failed to save open ports: {e}{RESET}")

    if network_issues:
        print(f"{YELLOW}[!] Network-level issues detected; showing up to 6 examples:{RESET}")
        for m in network_messages[:6]:
            print(f"  {YELLOW}{m}{RESET}")
        if len(network_messages) > 6:
            print(f"  {YELLOW}... and {len(network_messages)-6} more ...{RESET}")

    # log summary for auto_vuln
    SESSION_LOGS['auto_vuln'].append({'target': target, 'run_id': run_id, 'open_ports_file': port_file, 'open_ports': sorted(open_ports)})

    # ------------------ Nmap vulnerability scan ------------------
    nmap_bin = shutil_which("nmap")
    if nmap_bin:
        nmap_cmd = [nmap_bin, "-sS", "-sV", "-O", "--script", "vuln", "-p-", target, "-oN", nmap_file, "--stats-every", "2s"]
        nmap_max = 60 * 60 * 2  # 2 hours
        ok = run_command_with_progress(nmap_cmd, "Nmap Vulnerability Scan", outfile=nmap_file, parse_progress=parse_nmap_progress, max_duration=nmap_max, retries=1)
        if not ok:
            print(f"{YELLOW}[!] Nmap returned non-zero, timed out, or failed. Check {nmap_file}{RESET}")
            # Save at least a note file to indicate failure
            try:
                safe_write(nmap_file, "nmap scan failed or timed out. Check system nmap or rerun manually.")
            except Exception:
                pass
            SESSION_LOGS['auto_vuln'][-1].update({'nmap_file': nmap_file, 'nmap_ok': False})
        else:
            print(f"{GREEN}[+] Nmap vulnerability scan finished. Output: {nmap_file}{RESET}")
            SESSION_LOGS['auto_vuln'][-1].update({'nmap_file': nmap_file, 'nmap_ok': True})
            # parse nmap for summary
            try:
                nmap_summary = parse_nmap_summary(nmap_file)
                SESSION_LOGS['auto_vuln'][-1].update({'nmap_summary': nmap_summary})
            except Exception as e:
                SESSION_LOGS['auto_vuln'][-1].update({'nmap_parse_error': str(e)})
    else:
        print(f"{YELLOW}[!] nmap not found; skipping Nmap vulnerability scan.{RESET}")

    # ------------------ Nikto web scan ------------------
    nikto_bin = shutil_which('nikto')
    if not nikto_bin:
        print(f"{YELLOW}[!] Nikto not found on PATH. Skipping Nikto scan. Install 'nikto' to enable this scan.{RESET}")
    else:
        # Correct format flag to 'txt' and add -Tuning to reduce false positives if desired
        nikto_cmd = [nikto_bin, '-h', target, '-o', nikto_file, '-Format', 'txt']
        # allow longer timeout & 2 retries to avoid flaky failure
        nikto_max = 60 * 60  # 1 hour
        ok = run_command_with_progress(nikto_cmd, "Nikto Web Scan", outfile=nikto_file, max_duration=nikto_max, retries=2)
        if not ok:
            print(f"{YELLOW}[!] Nikto returned non-zero, timed out, or failed. Check {nikto_file}{RESET}")
            SESSION_LOGS['auto_vuln'][-1].update({'nikto_file': nikto_file, 'nikto_ok': False})
            try:
                # save note if file missing
                if not os.path.exists(nikto_file):
                    safe_write(nikto_file, "Nikto scan failed or timed out.")
            except Exception:
                pass
        else:
            print(f"{GREEN}[+] Nikto finished. Output: {nikto_file}{RESET}")
            SESSION_LOGS['auto_vuln'][-1].update({'nikto_file': nikto_file, 'nikto_ok': True})
            try:
                nikto_summary = parse_nikto_summary(nikto_file)
                SESSION_LOGS['auto_vuln'][-1].update({'nikto_summary': nikto_summary})
            except Exception as e:
                SESSION_LOGS['auto_vuln'][-1].update({'nikto_parse_error': str(e)})

    # ------------------ WPScan ------------------
    wpscan_bin = shutil_which('wpscan')
    if not wpscan_bin:
        print(f"{YELLOW}[!] WPScan not found on PATH. Skipping WPScan. Install 'wpscan' (Ruby gem) to enable this scan.{RESET}")
    else:
        # ensure correct URL format; WPScan tends to hang if site blocks requests - add --disable-tls-checks to help some cases
        url_try = target if re.match(r'^https?://', target) else f"http://{target}"
        wpscan_cmd = [wpscan_bin, '--url', url_try, '--no-update', '--output', wpscan_file, '--disable-tls-checks']
        wpscan_max = 60 * 45  # 45 minutes
        ok = run_command_with_progress(wpscan_cmd, "WPScan (HTTP/HTTPS)", outfile=wpscan_file, max_duration=wpscan_max, retries=1)
        if not ok and not re.match(r'^https?://', target):
            url_https = f"https://{target}"
            print(f"{CYAN}[+] Retrying WPScan with HTTPS...{RESET}")
            wpscan_cmd = [wpscan_bin, '--url', url_https, '--no-update', '--output', wpscan_file, '--disable-tls-checks']
            ok = run_command_with_progress(wpscan_cmd, "WPScan (HTTPS)", outfile=wpscan_file, max_duration=wpscan_max, retries=1)
        if not ok:
            print(f"{YELLOW}[!] WPScan returned non-zero, timed out, or failed. Check {wpscan_file}{RESET}")
            SESSION_LOGS['auto_vuln'][-1].update({'wpscan_file': wpscan_file, 'wpscan_ok': False})
            try:
                if not os.path.exists(wpscan_file):
                    safe_write(wpscan_file, "WPScan failed or timed out.")
            except Exception:
                pass
        else:
            print(f"{GREEN}[+] WPScan finished. Output: {wpscan_file}{RESET}")
            SESSION_LOGS['auto_vuln'][-1].update({'wpscan_file': wpscan_file, 'wpscan_ok': True})
            try:
                wpsummary = parse_wpscan_summary(wpscan_file)
                SESSION_LOGS['auto_vuln'][-1].update({'wpscan_summary': wpsummary})
            except Exception as e:
                SESSION_LOGS['auto_vuln'][-1].update({'wpscan_parse_error': str(e)})

    # ------------------ SSLScan ------------------
    sslscan_bin = shutil_which('sslscan')
    if not sslscan_bin:
        print(f"{YELLOW}[!] sslscan not found on PATH. Skipping SSLScan. Install 'sslscan' to enable this scan.{RESET}")
    else:
        # sslscan prints to stdout; run and save output via run_command_with_progress
        sslscan_cmd = [sslscan_bin, target]
        sslscan_max = 60 * 10  # 10 minutes (increase to be safe)
        ok = run_command_with_progress(sslscan_cmd, "SSLScan", outfile=ssl_file, max_duration=sslscan_max, retries=1)
        if not ok:
            print(f"{YELLOW}[!] SSLScan returned non-zero, timed out, or failed. Check {ssl_file}{RESET}")
            SESSION_LOGS['auto_vuln'][-1].update({'ssl_file': ssl_file, 'ssl_ok': False})
            try:
                if not os.path.exists(ssl_file):
                    safe_write(ssl_file, "SSLScan failed or timed out.")
            except Exception:
                pass
        else:
            print(f"{GREEN}[+] SSLScan finished. Output: {ssl_file}{RESET}")
            SESSION_LOGS['auto_vuln'][-1].update({'ssl_file': ssl_file, 'ssl_ok': True})
            try:
                ssum = parse_sslscan_summary(ssl_file)
                SESSION_LOGS['auto_vuln'][-1].update({'ssl_summary': ssum})
            except Exception as e:
                SESSION_LOGS['auto_vuln'][-1].update({'ssl_parse_error': str(e)})

    print(f"\n{CYAN}[+] All scans finished for run {run_id}. Results saved to {RESULTS_DIR}/{RESET}\n")

    input("Press Enter to return to menu.")

# ---------------- Report generation ----------------
def generate_report():
    from pathlib import Path
    try:
        import pdfkit
        PDFKIT_AVAILABLE = True
    except ImportError:
        PDFKIT_AVAILABLE = False

    title = 'Reconnaissance Report'
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_file = os.path.join(RESULTS_DIR, f"recon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")

    # Build HTML header
    html_parts = [f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1e1e1e; color: #f0f0f0; }}
        .container {{ max-width: 1100px; margin: auto; padding: 20px; }}
        h1 {{ color: #00ffff; }}
        h2 {{ color: #00ff00; border-bottom: 1px solid #555; }}
        pre {{ background: #111; padding: 10px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 15px; }}
        th, td {{ border: 1px solid #555; padding: 8px; text-align: left; }}
        th {{ background: #222; }}
        .summary {{ background: #0f1720; padding: 10px; margin-bottom: 12px; border-radius: 6px; }}
        .ok {{ color: #6ee7b7; }}
        .warn {{ color: #facc15; }}
        .err {{ color: #fb7185; }}
    </style>
    </head>
    <body>
    <div class="container">
    <h1>{title}</h1>
    <p>Generated at: {timestamp}</p>
    """]

    # If SESSION_LOGS has data, include parsed summaries
    # Include a readable summary for auto_vuln entries first (they are the heavy results)
    auto_vuln_entries = SESSION_LOGS.get('auto_vuln', [])
    if auto_vuln_entries:
        html_parts.append("<h2>Automatic Vulnerability Scans (Summary)</h2>")
        for ent in auto_vuln_entries:
            run_id = ent.get('run_id', 'unknown')
            target = ent.get('target', 'unknown')
            html_parts.append(f"<div class='summary'><strong>Run:</strong> {run_id} &nbsp; <strong>Target:</strong> {target}</div>")
            # open ports
            open_ports = ent.get('open_ports', [])
            if open_ports:
                html_parts.append("<h3>Open Ports</h3>")
                html_parts.append("<pre>" + ", ".join(str(p) for p in open_ports[:200]) + (" (truncated)" if len(open_ports) > 200 else "") + "</pre>")
            else:
                html_parts.append("<p>No open ports detected.</p>")

            # Nmap summary
            nmap_ok = ent.get('nmap_ok', None)
            if 'nmap_file' in ent:
                html_parts.append("<h3>Nmap</h3>")
                html_parts.append(f"<p>Raw output file: <code>{ent['nmap_file']}</code></p>")
                if nmap_ok:
                    nm = ent.get('nmap_summary', {})
                    if nm:
                        html_parts.append("<ul>")
                        if nm.get('open_ports'):
                            html_parts.append(f"<li><strong>Open ports:</strong> {', '.join(nm.get('open_ports')[:50])}</li>")
                        if nm.get('vulns'):
                            html_parts.append(f"<li class='warn'><strong>Potential CVEs:</strong> {', '.join(nm.get('vulns')[:20])}</li>")
                        html_parts.append("</ul>")
                        if nm.get('raw_snippet'):
                            html_parts.append("<details><summary>Show Nmap snippet</summary><pre>{}</pre></details>".format(html_escape(nm.get('raw_snippet'))))
                else:
                    html_parts.append("<p class='warn'>Nmap did not finish successfully or timed out. Raw output file may have partial results.</p>")

            # Nikto
            if 'nikto_file' in ent:
                html_parts.append("<h3>Nikto</h3>")
                html_parts.append(f"<p>Raw output file: <code>{ent['nikto_file']}</code></p>")
                if ent.get('nikto_ok'):
                    nik = ent.get('nikto_summary', {})
                    if nik and nik.get('issues'):
                        html_parts.append("<ul>")
                        for i in nik.get('issues')[:40]:
                            html_parts.append(f"<li>{html_escape(i)}</li>")
                        html_parts.append("</ul>")
                        if nik.get('raw_snippet'):
                            html_parts.append("<details><summary>Show Nikto snippet</summary><pre>{}</pre></details>".format(html_escape(nik.get('raw_snippet'))))
                    else:
                        html_parts.append("<p>No clear issues parsed from Nikto output.</p>")
                else:
                    html_parts.append("<p class='warn'>Nikto did not finish successfully or timed out. Raw output file may have partial results.</p>")

            # WPScan
            if 'wpscan_file' in ent:
                html_parts.append("<h3>WPScan</h3>")
                html_parts.append(f"<p>Raw output file: <code>{ent['wpscan_file']}</code></p>")
                if ent.get('wpscan_ok'):
                    wp = ent.get('wpscan_summary', {})
                    if wp:
                        if wp.get('interesting'):
                            html_parts.append("<ul>")
                            for it in wp.get('interesting')[:40]:
                                html_parts.append(f"<li>{html_escape(it)}</li>")
                            html_parts.append("</ul>")
                        if wp.get('cves'):
                            html_parts.append(f"<p class='warn'><strong>Found CVEs:</strong> {', '.join(wp.get('cves')[:20])}</p>")
                        if wp.get('raw_snippet'):
                            html_parts.append("<details><summary>Show WPScan snippet</summary><pre>{}</pre></details>".format(html_escape(wp.get('raw_snippet'))))
                    else:
                        html_parts.append("<p>No clear issues parsed from WPScan output.</p>")
                else:
                    html_parts.append("<p class='warn'>WPScan did not finish successfully or timed out. Raw output file may have partial results.</p>")

            # SSLScan
            if 'ssl_file' in ent:
                html_parts.append("<h3>SSLScan</h3>")
                html_parts.append(f"<p>Raw output file: <code>{ent['ssl_file']}</code></p>")
                if ent.get('ssl_ok'):
                    ss = ent.get('ssl_summary', {})
                    if ss:
                        if ss.get('protocols'):
                            html_parts.append("<ul>")
                            for pr in ss.get('protocols')[:50]:
                                html_parts.append(f"<li>{html_escape(pr)}</li>")
                            html_parts.append("</ul>")
                        if ss.get('cert_info'):
                            html_parts.append("<p><strong>Certificate subject:</strong> {}</p>".format(html_escape(str(ss.get('cert_info')))))
                        if ss.get('raw_snippet'):
                            html_parts.append("<details><summary>Show SSLScan snippet</summary><pre>{}</pre></details>".format(html_escape(ss.get('raw_snippet'))))
                    else:
                        html_parts.append("<p>No clear data parsed from SSLScan output.</p>")
                else:
                    html_parts.append("<p class='warn'>SSLScan did not finish successfully or timed out. Raw output file may have partial results.</p>")

    # If no auto_vuln entries found, provide a note
    if not auto_vuln_entries:
        html_parts.append("<h2>Automatic Vulnerability Scans</h2>")
        html_parts.append("<p>No automatic vulnerability scans were run in this session (SESSION_LOGS empty for auto_vuln).</p>")

    # Generic sections: include other SESSION_LOGS entries and snippets for convenience
    for section, entries in SESSION_LOGS.items():
        if section == 'auto_vuln':
            continue  # already included
        html_parts.append(f"<h2>{section.replace('_', ' ').title()}</h2>")
        if not entries:
            html_parts.append("<p>No data collected.</p>")
            continue
        for entry in entries:
            html_parts.append("<div class='summary'>")
            # show some fields neatly
            keys_shown = []
            for k, v in entry.items():
                if k in ('file', 'ip', 'target', 'domain', 'number', 'time', 'action'):
                    html_parts.append(f"<p><strong>{html_escape(str(k))}:</strong> {html_escape(str(v))}</p>")
                    keys_shown.append(k)
            html_parts.append("</div>")
            # include small raw snippet if file present
            if 'file' in entry and os.path.exists(entry['file']):
                try:
                    with open(entry['file'], 'r', encoding='utf-8', errors='ignore') as fh:
                        txt = fh.read(2000)
                    html_parts.append("<details><summary>Show raw file snippet</summary><pre>{}</pre></details>".format(html_escape(txt)))
                except Exception:
                    pass

    html_parts.append("</div></body></html>")

    html_content = "\n".join(html_parts)

    # Save report
    safe_write(report_file, html_content)
    print(f"{GREEN}[+] HTML report generated: {report_file}{RESET}")

    # Optionally convert to PDF if pdfkit available
    if PDFKIT_AVAILABLE:
        pdf_file = Path(report_file).with_suffix('.pdf')
        try:
            pdfkit.from_file(report_file, str(pdf_file))
            print(f"{GREEN}[+] PDF version generated: {pdf_file}{RESET}")
        except Exception as e:
            print(f"{YELLOW}[!] Failed to generate PDF: {e}{RESET}")
    else:
        print(f"{YELLOW}[!] pdfkit not installed. Install with 'pip install pdfkit' to generate PDF.{RESET}")

    input("Press Enter to return to menu.")

# Helper for HTML escaping
def html_escape(s):
    if s is None:
        return ''
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))

# ---------------- Main Loop ----------------
def main():
    global SESSION_START
    SESSION_START = datetime.now()

    while True:
        choice = menu()
        print(f"[DEBUG] raw choice repr: {repr(choice)}")  # This will show hidden characters

        choice = choice.strip()  # remove any whitespace/newlines
        print(f"[DEBUG] stripped choice repr: {repr(choice)}")  # confirm it's clean

        if choice == "1":
            ping_host()
        elif choice == "2":
            port_scan()
        elif choice == "3":
            banner_grab()
        elif choice == "4":
            whois_lookup()
        elif choice == "5":
            geoip_lookup()
        elif choice == "6":
            mobile_lookup()
        elif choice == "7":
            domain_tld_enum()
        elif choice == "8":
            auto_vuln_scan()
        elif choice == "9":
            generate_report()
        elif choice == "0":
            print(f"{CYAN}Exiting...{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}[!] Invalid choice: {repr(choice)}. Please select 0-9.{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
