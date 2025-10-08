#!/usr/bin/env python3
"""
defensive_monitoring.py (fixed, cleaned)

Robust Defensive & Monitoring module for Rajasploit.

Drop this file into modules/ and run it with:
    python3 modules/defensive_monitoring.py
"""

from pathlib import Path
from datetime import datetime
import subprocess, shutil, os, sys, stat, hashlib, time, getpass

# Colors for terminal
RESET = "\033[0m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"

# Base results directory
BASE_RESULTS = Path("results/defensive_monitoring")
BASE_RESULTS.mkdir(parents=True, exist_ok=True)

# --- run id / folders ---
def next_run_id():
    runs = [p for p in BASE_RESULTS.iterdir() if p.is_dir() and p.name.startswith("run")]
    nums = []
    for r in runs:
        try:
            nums.append(int(r.name.replace("run","")))
        except Exception:
            continue
    return max(nums)+1 if nums else 1

RUN_ID = next_run_id()
RUN_FOLDER = BASE_RESULTS / f"run{RUN_ID}"
RUN_FOLDER.mkdir(parents=True, exist_ok=True)

# Print debug info about where outputs are written
print(f"{GREEN}[INFO]{RESET} RUN_FOLDER = {RUN_FOLDER.resolve()} (user={getpass.getuser()})")

# --- Utility: robust run-and-save that always writes something ---
def run_and_save(cmd_list, out_path, binary=False, show_preview=True, env=None):
    """
    Run a command and save stdout+stderr to out_path.
    - cmd_list: list of command tokens
    - out_path: Path (or string) to file
    - binary: if True, write raw bytes; otherwise decode to text (utf-8 then latin-1)
    Returns (success:bool, returncode:int, bytes_written:int)
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if env is None:
        env = os.environ.copy()

    try:
        proc = subprocess.run(list(map(str, cmd_list)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, check=False)
        data = proc.stdout or b""

        if binary:
            # If command produced no stdout but file already exists (tool wrote it with -w), don't overwrite
            if len(data) == 0 and out_path.exists():
                print(f"{YELLOW}[WARN]{RESET} Command produced no stdout but {out_path} already exists (not overwriting).")
                return True, proc.returncode, out_path.stat().st_size
            out_path.write_bytes(data)
        else:
            try:
                text = data.decode("utf-8")
            except Exception:
                text = data.decode("latin-1", errors="replace")
            out_path.write_text(text, errors="ignore")

        # Print debug info to console
        print(f"{CYAN}[RUN]{RESET} {' '.join(map(str,cmd_list))}")
        print(f"{CYAN}[OUT]{RESET} Wrote {len(data)} bytes -> {out_path.resolve()}")
        if show_preview and len(data) > 0 and not binary:
            preview = data[:800]
            try:
                print(f"{CYAN}[PREVIEW]{RESET}\n{preview.decode('utf-8')}\n...")
            except Exception:
                print(f"{CYAN}[PREVIEW]{RESET}\n{preview.decode('latin-1',errors='replace')}\n...")
        return True, proc.returncode, len(data)
    except Exception as e:
        try:
            out_path.write_text(f"[ERROR] Exception running {' '.join(map(str,cmd_list))}\n{e}\n", errors="ignore")
        except Exception:
            pass
        print(f"{RED}[ERROR]{RESET} Exception while running {' '.join(map(str,cmd_list))}: {e}")
        return False, -1, 0

def check_tool(name):
    return shutil.which(name) is not None

# Helper to chown files back to user if they are root-owned and sudo is available
def try_fix_ownership(path: Path):
    try:
        if not path.exists():
            return
        st = path.stat()
        # If file owned by root try to chown to current user
        if hasattr(os, "getuid") and st.st_uid == 0:
            uid = os.getuid()
            gid = os.getgid()
            try:
                os.chown(str(path), uid, gid)
            except PermissionError:
                if check_tool("sudo"):
                    subprocess.run(["sudo", "chown", f"{uid}:{gid}", str(path)], check=False)
    except Exception:
        pass

# --- UI helpers ---
def banner():
    os.system("clear")
    print(f"{CYAN}=== Defensive & Monitoring ==={RESET}")
    print(f"{YELLOW}** Use only on systems you are authorized to monitor **{RESET}\n")

def show_saved_files(paths):
    """Print a persistent message of saved files and wait until user presses Enter."""
    print(f"{GREEN}[+] Saved files:{RESET}")
    for p in paths:
        try:
            print(f" - {Path(p).resolve()}")
        except Exception:
            print(f" - {p}")
    input(f"{CYAN}Press Enter to return to menu...{RESET}")

# --- Helper: action logging inside run folder (journal_new1, journal_new2...) ---
def log_action(prefix, content):
    """Save content to a numbered file like prefix_new1.txt in RUN_FOLDER/actions."""
    actions_dir = RUN_FOLDER / "actions"
    actions_dir.mkdir(parents=True, exist_ok=True)
    existing = [p for p in actions_dir.iterdir() if p.is_file() and p.name.startswith(prefix)]
    nums = []
    for p in existing:
        try:
            name = p.stem  # e.g., journal_new1
            tail = name.replace(prefix + "_new", "")
            nums.append(int(tail))
        except Exception:
            continue
    n = max(nums) + 1 if nums else 1
    fname = actions_dir / f"{prefix}_new{n}.txt"
    try:
        fname.write_text(content, encoding="utf-8")
    except Exception:
        try:
            fname.write_text(str(content), encoding="utf-8", errors="ignore")
        except Exception:
            pass
    try_fix_ownership(fname)
    return fname

# --- Metadata collection for reports (client, creator, owner) ---
REPORT_METADATA = {
    'client_name': '',
    'creator_name': '',
    'system_owner': ''
}

def collect_metadata():
    # ask once per run
    if REPORT_METADATA['client_name']:
        return
    print(f"{CYAN}Report metadata setup (optional) — press Enter to skip.{RESET}")
    REPORT_METADATA['client_name'] = input('Client name: ').strip()
    REPORT_METADATA['creator_name'] = input('Creator name: ').strip()
    REPORT_METADATA['system_owner'] = input('System owner name: ').strip()

# --- 1) Real-time network capture (pcap + summary) ---
def real_time_network():
    print(f"{MAGENTA}[+] Real-time network capture{RESET}")
    collect_metadata()
    iface = input(f"{YELLOW}Enter interface (leave blank for default): {RESET}").strip()
    dur = input(f"{YELLOW}Duration seconds (default 30): {RESET}").strip()
    try:
        dur = int(dur) if dur else 30
    except:
        dur = 30

    pcap_path = RUN_FOLDER / f"run{RUN_ID}_network.pcap"
    summary_path = RUN_FOLDER / f"run{RUN_ID}_network_summary.txt"

    # Prefer tcpdump if available; otherwise try tshark; if none, exit gracefully
    if check_tool("tcpdump"):
        cmd = ["sudo", "timeout", str(dur), "tcpdump", "-w", str(pcap_path)]
        if iface:
            cmd.extend(["-i", iface])
        print(f"{YELLOW}Running tcpdump for {dur}s... (this requires sudo){RESET}")
        try:
            subprocess.run(list(map(str,cmd)), check=False)
            if pcap_path.exists() and pcap_path.stat().st_size > 0:
                print(f"{GREEN}[+] tcpdump produced {pcap_path.resolve()} ({pcap_path.stat().st_size} bytes){RESET}")
            else:
                print(f"{YELLOW}[WARN]{RESET} tcpdump finished but {pcap_path} is missing or empty.")
        except Exception as e:
            print(f"{RED}tcpdump failed: {e}{RESET}")
    elif check_tool("tshark"):
        cmd = ["sudo", "timeout", str(dur), "tshark", "-w", str(pcap_path)]
        if iface:
            cmd.extend(["-i", iface])
        print(f"{YELLOW}Running tshark for {dur}s... (this requires sudo){RESET}")
        try:
            subprocess.run(list(map(str,cmd)), check=False)
            if pcap_path.exists() and pcap_path.stat().st_size > 0:
                print(f"{GREEN}[+] tshark produced {pcap_path.resolve()} ({pcap_path.stat().st_size} bytes){RESET}")
            else:
                print(f"{YELLOW}[WARN]{RESET} tshark finished but {pcap_path} is missing or empty.")
        except Exception as e:
            print(f"{RED}tshark capture failed: {e}{RESET}")
    else:
        print(f"{RED}Neither tcpdump nor tshark found. Install one to capture network traffic.{RESET}")
        return

    # Generate human-readable summary (prefer tshark -r or tcpdump -nn -r)
    if check_tool("tshark"):
        cmd = ["tshark", "-r", str(pcap_path), "-V"]
        run_and_save(cmd, summary_path, binary=False)
    elif check_tool("tcpdump"):
        cmd = ["tcpdump", "-nn", "-r", str(pcap_path)]
        run_and_save(cmd, summary_path, binary=False)
    else:
        summary_path.write_text("No tool available to create human-readable summary. Install tshark or tcpdump.\n")

    # Try to make files owned by running user if root-owned
    try_fix_ownership(pcap_path)
    try_fix_ownership(summary_path)

    # Log and show saved files (pcap + summary)
    saved = []
    if pcap_path.exists():
        saved.append(pcap_path)
    if summary_path.exists():
        saved.append(summary_path)

    summary_text = ''
    try:
        if summary_path.exists():
            summary_text = summary_path.read_text(errors='ignore')
    except Exception:
        summary_text = ''

    log_action('journal', f"Real-time network capture\nDuration: {dur}s\nFiles:\n" + '\n'.join([str(p) for p in saved]) + "\n\nSummary:\n" + summary_text)
    show_saved_files(saved)
    print(f"{GREEN}[+] Capture complete.{RESET}")

# --- 2) Detect open ports & services (nmap) ---
def detect_ports_services():
    print(f"{MAGENTA}[+] Nmap scan{RESET}")
    collect_metadata()
    if not check_tool("nmap"):
        print(f"{RED}nmap not found. Install nmap to use this option.{RESET}")
        return
    target = input(f"{YELLOW}Target IP or network (e.g. 127.0.0.1 or 192.168.1.0/24): {RESET}").strip()
    if not target:
        print(f"{RED}No target provided.{RESET}")
        return
    # Safety check: warn user if target is not local
    if not is_local_target(target):
        print(f"{YELLOW}[!] Warning: target {target} does not look like a local subnet. Ensure you have permission!{RESET}")
        confirm = input("Type YES to continue: ").strip()
        if confirm != "YES":
            print("Cancelled.")
            return
    out_file = RUN_FOLDER / f"run{RUN_ID}_nmap.txt"
    cmd = ["nmap", "-sV", "-T4", "-oN", str(out_file), target]
    try:
        subprocess.run(cmd, check=False)
        if out_file.exists():
            print(f"{GREEN}[+] Nmap saved to {out_file.resolve()}{RESET}")
        else:
            print(f"{YELLOW}[WARN]{RESET} nmap did not produce {out_file}. Falling back to capturing stdout.")
            run_and_save(["nmap", "-sV", "-T4", target], out_file, binary=False)
    except Exception as e:
        print(f"{YELLOW}[WARN]{RESET} nmap execution failed: {e}. Falling back to capture.")
        run_and_save(["nmap", "-sV", "-T4", target], out_file, binary=False)

    # Log results and show saved file
    saved = []
    if out_file.exists():
        saved.append(out_file)
    nmap_text = ''
    try:
        if out_file.exists():
            nmap_text = out_file.read_text(errors='ignore')
    except Exception:
        nmap_text = ''
    log_action('nmap', f"Nmap scan target: {target}\nFiles:\n" + '\n'.join([str(p) for p in saved]) + "\n\nResults:\n" + nmap_text)
    show_saved_files(saved)
    print(f"{GREEN}[+] Nmap completed.{RESET}")

def is_local_target(target):
    t = str(target).strip()
    if t == "localhost" or t.startswith("127."):
        return True
    if t.startswith("10.") or t.startswith("192.168."):
        return True
    # basic check for RFC1918 172.16-31
    if t.startswith("172."):
        try:
            second = int(t.split(".")[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            pass
    if "/" in t:
        # simple net check: starts with RFC1918 prefixes
        if t.startswith("10.") or t.startswith("192.168.") or t.startswith("172."):
            return True
    return False

# --- 3) Monitor running processes ---
def monitor_processes():
    print(f"{MAGENTA}[+] Collecting process info{RESET}")
    collect_metadata()
    prefix = RUN_FOLDER / "processes"
    prefix.mkdir(parents=True, exist_ok=True)
    ps_file = prefix / "ps_aux.txt"
    top_file = prefix / "top.txt"
    run_and_save(["ps", "aux"], ps_file)
    run_and_save(["top", "-b", "-n", "1"], top_file)
    # htop is interactive — just inform user
    if check_tool("htop"):
        print(f"{YELLOW}[!] htop available (interactive). Run manually in a terminal if needed: htop{RESET}")
    print(f"{GREEN}[+] Processes saved in {prefix.resolve()}{RESET}")
    # log and show saved
    saved = [ps_file, top_file]
    combined = ''
    try:
        combined = ps_file.read_text(errors='ignore') + "\n\n" + top_file.read_text(errors='ignore')
    except Exception:
        combined = ''
    log_action('processes', f"Collected process snapshots. Files:\n" + '\n'.join([str(p) for p in saved]) + "\n\nContents:\n" + combined)
    show_saved_files(saved)

# --- 4) File integrity implemented in pure Python (sha256 of files) ---
def file_integrity():
    print(f"{MAGENTA}[+] File integrity check (sha256){RESET}")
    collect_metadata()
    target = input(f"{YELLOW}Directory to hash (default /etc): {RESET}").strip()
    if not target:
        target = "/etc"
    target_path = Path(target)
    if not target_path.exists():
        print(f"{RED}Target {target} does not exist{RESET}")
        return
    out_file = RUN_FOLDER / f"run{RUN_ID}_file_integrity.txt"
    with out_file.open("w", errors="ignore") as fh:
        fh.write(f"File integrity run: {datetime.utcnow().isoformat()}Z\n")
        fh.write(f"Target: {target}\n\n")
        # Walk directory and hash files
        for root, dirs, files in os.walk(target):
            for fn in files:
                p = Path(root) / fn
                try:
                    # skip special files we cannot read
                    if not p.is_file():
                        continue
                    h = hash_file_sha256(p)
                    fh.write(f"{h}  {p}\n")
                except Exception as e:
                    fh.write(f"[ERROR] {p}: {e}\n")
    try_fix_ownership(out_file)
    print(f"{GREEN}[+] File integrity written to {out_file.resolve()}{RESET}")
    # log and show
    saved = [out_file]
    try:
        content = out_file.read_text(errors='ignore')
    except Exception:
        content = ''
    log_action('file_integrity', f"File integrity check target: {target}\nFiles:\n" + '\n'.join([str(p) for p in saved]) + "\n\nResults:\n" + content)
    show_saved_files(saved)

def hash_file_sha256(path: Path, block_size=65536):
    """Return hex sha256 of file. Read in binary."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            b = fh.read(block_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

# --- 5) Log collection ---
def log_monitoring():
    print(f"{MAGENTA}[+] Collecting logs{RESET}")
    collect_metadata()
    prefix = RUN_FOLDER / "logs"
    prefix.mkdir(parents=True, exist_ok=True)
    saved = []
    if check_tool("journalctl"):
        p = prefix / "journal_recent.txt"
        run_and_save(["journalctl", "--no-pager", "-n", "300"], p)
        saved.append(p)
    else:
        candidates = ["/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/var/log/kern.log"]
        found = False
        for c in candidates:
            p = Path(c)
            if p.exists():
                outp = prefix / p.name
                run_and_save(["tail", "-n", "300", str(p)], outp)
                saved.append(outp)
                found = True
        if not found:
            notice = prefix / "notice.txt"
            notice.write_text("No journalctl and no common syslog files found.\n")
            saved.append(notice)
    try_fix_ownership(prefix)
    print(f"{GREEN}[+] Logs saved in {prefix.resolve()}{RESET}")
    # aggregate and log
    combined = ''
    try:
        for p in saved:
            combined += f"== {p.name} ==\n"
            combined += p.read_text(errors='ignore') + "\n\n"
    except Exception:
        pass
    log_action('logs', f"Collected logs. Files:\n" + '\n'.join([str(p) for p in saved]) + "\n\nContents:\n" + combined)
    show_saved_files(saved)

# --- 6) IDS status check ---
def ids_check():
    print(f"{MAGENTA}[+] IDS check{RESET}")
    collect_metadata()
    saved = []
    if check_tool("snort"):
        p = RUN_FOLDER / f"run{RUN_ID}_snort_version.txt"
        run_and_save(["snort", "-V"], p)
        saved.append(p)
    elif check_tool("suricata"):
        p = RUN_FOLDER / f"run{RUN_ID}_suricata_version.txt"
        run_and_save(["suricata", "-V"], p)
        saved.append(p)
    else:
        print(f"{YELLOW}No snort or suricata detected on PATH.{RESET}")
        notice = RUN_FOLDER / 'ids_notice.txt'
        notice.write_text('No snort or suricata detected on PATH.\n')
        saved.append(notice)
    combined = ''
    try:
        for p in saved:
            combined += f"== {p.name} ==\n"
            combined += p.read_text(errors='ignore') + "\n\n"
    except Exception:
        pass
    log_action('ids', f"IDS check. Files:\n" + '\n'.join([str(p) for p in saved]) + "\n\nContents:\n" + combined)
    show_saved_files(saved)

# --- 7) System resource snapshots ---
def monitor_resources():
    print(f"{MAGENTA}[+] System resources{RESET}")
    collect_metadata()
    prefix = RUN_FOLDER / "resources"
    prefix.mkdir(parents=True, exist_ok=True)
    uptime_file = prefix / "uptime.txt"
    mem_file = prefix / "memory.txt"
    disk_file = prefix / "disk_usage.txt"
    top_file = prefix / "top.txt"
    run_and_save(["uptime"], uptime_file)
    run_and_save(["free", "-h"], mem_file)
    run_and_save(["df", "-h"], disk_file)
    run_and_save(["top", "-b", "-n", "1"], top_file)
    try_fix_ownership(prefix)
    print(f"{GREEN}[+] Resources saved in {prefix.resolve()}{RESET}")
    # log and show
    saved = [uptime_file, mem_file, disk_file, top_file]
    combined = ''
    try:
        for p in saved:
            combined += f"== {p.name} ==\n"
            combined += p.read_text(errors='ignore') + "\n\n"
    except Exception:
        pass
    log_action('resources', f"System resources snapshot. Files:\n" + '\n'.join([str(p) for p in saved]) + "\n\nContents:\n" + combined)
    show_saved_files(saved)

# --- 8) Generate text & HTML report ---
def extract_text_if_small(p: Path, max_chars=20000):
    """Return the text contents of p if readable and within size limits; otherwise return a short note."""
    try:
        if not p.exists():
            return f"(missing: {p})"
        size = p.stat().st_size
        if size > max_chars:
            return f"(file too large to include inline: {p.name}, {size} bytes)"
        return p.read_text(errors='ignore')
    except Exception as e:
        return f"(error reading {p}: {e})"

def save_numbered_copy(src: Path, base_name: str):
    """Copy src to RUN_FOLDER/{base_name}_new{N}.ext using next available N. Returns the new Path or None on failure."""
    try:
        ext = src.suffix
        n = 1
        while True:
            candidate = RUN_FOLDER / f"{base_name}_new{n}{ext}"
            if not candidate.exists():
                shutil.copy2(str(src), str(candidate))
                try_fix_ownership(candidate)
                return candidate
            n += 1
    except Exception:
        return None

def generate_report():
    """Enhanced report: embeds results content, metadata, per-option sections, and simple charts."""
    print(f"{MAGENTA}[+] Generating enhanced report{RESET}")
    # Ask for metadata (allow empty to skip)
    client_name = input(f"{YELLOW}Client name (optional): {RESET}").strip() or REPORT_METADATA.get('client_name', '')
    creator_name = input(f"{YELLOW}Creator name (optional): {RESET}").strip() or REPORT_METADATA.get('creator_name', '')
    system_owner = input(f"{YELLOW}System owner name (optional): {RESET}").strip() or REPORT_METADATA.get('system_owner', '')
    title = input(f"{YELLOW}Report title (default: Rajasploit Defensive Monitoring Report): {RESET}").strip() or "Rajasploit Defensive Monitoring Report"

    report_txt = RUN_FOLDER / f"run{RUN_ID}_report.txt"
    report_html = RUN_FOLDER / f"run{RUN_ID}_report.html"

    # Build sections: for each major directory/file created by options, include inline results where sensible
    sections = []

    # 1) Network capture
    net_pcap = RUN_FOLDER / f"run{RUN_ID}_network.pcap"
    net_summary = RUN_FOLDER / f"run{RUN_ID}_network_summary.txt"
    net_summary_text = extract_text_if_small(net_summary) if net_summary.exists() else "(no network summary)"
    sections.append(("Network Capture", net_summary_text))

    # 2) Nmap
    nmap_file = RUN_FOLDER / f"run{RUN_ID}_nmap.txt"
    nmap_text = extract_text_if_small(nmap_file) if nmap_file.exists() else "(no nmap results)"
    sections.append(("Port & Service Scan (nmap)", nmap_text))

    # 3) Processes
    proc_dir = RUN_FOLDER / "processes"
    proc_text = ""
    if proc_dir.exists():
        for p in sorted(proc_dir.glob("*.txt")):
            proc_text += f"=== {p.name} ===\n" + extract_text_if_small(p) + "\n\n"
    else:
        proc_text = "(no process outputs)"
    sections.append(("Process Snapshot", proc_text))

    # 4) File integrity
    fi_file = RUN_FOLDER / f"run{RUN_ID}_file_integrity.txt"
    fi_text = extract_text_if_small(fi_file) if fi_file.exists() else "(no file integrity results)"
    sections.append(("File Integrity (sha256)", fi_text))

    # 5) Logs
    logs_dir = RUN_FOLDER / "logs"
    logs_text = ""
    if logs_dir.exists():
        for p in sorted(logs_dir.glob("*.txt")):
            logs_text += f"=== {p.name} ===\n" + extract_text_if_small(p) + "\n\n"
    else:
        logs_text = "(no logs collected)"
    sections.append(("Logs", logs_text))

    # 6) IDS
    ids_text = ""
    for f in [RUN_FOLDER / f"run{RUN_ID}_snort_version.txt", RUN_FOLDER / f"run{RUN_ID}_suricata_version.txt"]:
        if f.exists():
            ids_text += f"=== {f.name} ===\n" + extract_text_if_small(f) + "\n\n"
    if not ids_text:
        ids_text = "(no IDS detected or no IDS output)"
    sections.append(("IDS Check", ids_text))

    # 7) Resources
    res_dir = RUN_FOLDER / "resources"
    res_text = ""
    if res_dir.exists():
        for p in sorted(res_dir.glob("*.txt")):
            res_text += f"=== {p.name} ===\n" + extract_text_if_small(p) + "\n\n"
    else:
        res_text = "(no resources snapshot)"
    sections.append(("System Resources", res_text))

    # Write plain text report (human readable, includes embedded results where small)
    with report_txt.open("w", errors="ignore") as rf:
        rf.write(f"{title}\n")
        rf.write(f"Client: {client_name}\nCreator: {creator_name}\nSystem owner: {system_owner}\n")
        rf.write(f"Timestamp: {datetime.utcnow().isoformat()}Z\nRun folder: {RUN_FOLDER.resolve()}\n\n")
        rf.write("Short summary:\n")
        # Auto-generate a short summary from available sections (first lines)
        summary_lines = []
        for name, content in sections:
            snippet = (content.splitlines()[:5]) if content else ["(no data)"]
            summary_lines.append(f"- {name}: {snippet[0] if snippet else '(no data)'}")
        rf.write('\n'.join(summary_lines) + '\n\n')

        for name, content in sections:
            rf.write(f"== {name} ==\n")
            rf.write(content + "\n\n")

    # Build HTML report with a summary box and per-section content
    html_lines = []
    html_lines.append("<html><head><meta charset='utf-8'><title>" + title + "</title></head><body style='font-family:Arial,Helvetica,sans-serif'>")
    html_lines.append(f"<h1 style='background:#eee;padding:10px;border-radius:6px'>{title}</h1>")
    html_lines.append(f"<p><strong>Client:</strong> {client_name} &nbsp;&nbsp; <strong>Creator:</strong> {creator_name} &nbsp;&nbsp; <strong>Owner:</strong> {system_owner}</p>")
    html_lines.append(f"<p><strong>Timestamp:</strong> {datetime.utcnow().isoformat()}Z</p>")

    # Short summary box
    html_lines.append("<div style='border:1px solid #ccc;padding:10px;background:#fafafa;margin:10px 0;border-radius:6px'>")
    html_lines.append("<h3>Executive Summary</h3>")
    html_lines.append("<ul>")
    for line in summary_lines:
        html_lines.append(f"<li>{line}</li>")
    html_lines.append("</ul></div>")

    # Per-section details
    for name, content in sections:
        html_lines.append(f"<h2>{name}</h2>")
        if len(content) > 1000:
            html_lines.append("<div style='max-height:300px;overflow:auto;border:1px solid #ddd;padding:8px;background:#fff'><pre>")
            html_lines.append(content)
            html_lines.append("</pre></div>")
        else:
            html_lines.append(f"<pre style='white-space:pre-wrap'>{content}</pre>")

    # Attempt to add simple charts if possible (e.g., disk usage)
    charts = []
    try:
        dfp = RUN_FOLDER / "resources" / "disk_usage.txt"
        if dfp.exists():
            lines = dfp.read_text(errors='ignore').splitlines()
            sizes = []
            labels = []
            for l in lines[1:]:
                parts = l.split()
                if len(parts) >= 6:
                    labels.append(parts[5])
                    used = parts[2]
                    try:
                        val = float(''.join(ch for ch in used if (ch.isdigit() or ch=='.')))
                    except Exception:
                        val = 0.0
                    sizes.append(val)
            if sizes and len(sizes) <= 10:
                try:
                    import matplotlib
                    matplotlib.use('Agg')
                    import matplotlib.pyplot as plt
                    fig, ax = plt.subplots()
                    ax.bar(range(len(sizes)), sizes)
                    ax.set_xticks(range(len(labels)))
                    ax.set_xticklabels(labels, rotation=45, ha='right')
                    ax.set_ylabel('Used (approx)')
                    chart_path = RUN_FOLDER / f"run{RUN_ID}_disk_usage_chart.png"
                    fig.tight_layout()
                    fig.savefig(str(chart_path))
                    charts.append(chart_path)
                    plt.close(fig)
                except Exception:
                    pass
    except Exception:
        pass

    # Embed charts
    for c in charts:
        html_lines.append(f"<div style='margin:10px 0'><img src='{c.name}' alt='chart' style='max-width:100%'></div>")

    html_lines.append("</body></html>")
    report_html.write_text("\n".join(html_lines), encoding="utf-8")
    try_fix_ownership(report_txt)
    try_fix_ownership(report_html)

    print(f"{GREEN}[+] Reports generated:\n - {report_txt.resolve()}\n - {report_html.resolve()}{RESET}")
    # Try to produce PDF if wkhtmltopdf is present
    if check_tool("wkhtmltopdf"):
        pdf_path = RUN_FOLDER / f"run{RUN_ID}_report.pdf"
        try:
            subprocess.run(["wkhtmltopdf", str(report_html), str(pdf_path)], check=False)
            if pdf_path.exists():
                print(f"{GREEN}[+] PDF report generated: {pdf_path.resolve()}{RESET}")
        except Exception as e:
            print(f"{YELLOW}wkhtmltopdf failed: {e}{RESET}")

# --- Menu & main loop ---
def menu():
    banner()
    print(f"{GREEN}1){RESET} Real-time network monitoring (tcpdump/tshark) — capture + summary")
    print(f"{GREEN}2){RESET} Detect open ports & services (nmap)")
    print(f"{GREEN}3){RESET} Monitor running processes (ps, top)")
    print(f"{GREEN}4){RESET} File integrity monitoring (sha256)")
    print(f"{GREEN}5){RESET} Log monitoring & alerting (journalctl / syslog)")
    print(f"{GREEN}6){RESET} IDS check (Snort / Suricata)")
    print(f"{GREEN}7){RESET} System resource snapshot (uptime, free, df)")
    print(f"{GREEN}8){RESET} Generate defensive report")
    print(f"{GREEN}0){RESET} Exit")
    return input(f"\n{CYAN}Defensive > {RESET}").strip()

def main():
    while True:
        choice = menu()
        if choice == "1":
            real_time_network()
        elif choice == "2":
            detect_ports_services()
        elif choice == "3":
            monitor_processes()
        elif choice == "4":
            file_integrity()
        elif choice == "5":
            log_monitoring()
        elif choice == "6":
            ids_check()
        elif choice == "7":
            monitor_resources()
        elif choice == "8":
            generate_report()
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print(f"{RED}Invalid choice{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
