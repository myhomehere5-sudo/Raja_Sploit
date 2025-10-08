#!/usr/bin/env python3
"""
modules/forensics_incident_response.py

Forensics & Incident Response module for Rajasploit.
Drop this file in the `modules/` folder as forensics_incident_response.py
and call it from Rajasploit menu (option 3).

Requires:
 - Python 3
 - sudo/root for memory dump or disk imaging
 - tcpdump, dd, tar, fls/mactime (sleuthkit), yara, clamscan, matplotlib, reportlab
"""

import os
import sys
import time
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from matplotlib import pyplot as plt
import json
import tarfile

# color helpers
RESET = "\033[0m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"

# Ensure results folder
BASE_RESULTS = Path("results/forensics")
BASE_RESULTS.mkdir(parents=True, exist_ok=True)

def banner():
    os.system("clear")
    print(f"{CYAN}=== Forensics & Incident Response ==={RESET}")
    print(f"{YELLOW}** Use only on systems you are authorized to examine **{RESET}\n")

def next_run_id():
    existing = list(BASE_RESULTS.glob("run*_summary.json"))
    if not existing:
        return 1
    nums = []
    for f in existing:
        try:
            n = int(f.name.split("_")[0].replace("run",""))
            nums.append(n)
        except:
            continue
    return max(nums)+1 if nums else 1

RUN_ID = next_run_id()
RUN_FOLDER = BASE_RESULTS / f"run{RUN_ID}"
RUN_FOLDER.mkdir(parents=True, exist_ok=True)

def menu():
    banner()
    print(f"{GREEN}1){RESET} Collect system & volatile evidence (basic)")
    print(f"{GREEN}2){RESET} Memory dump (volatility3 fallback)")
    print(f"{GREEN}3){RESET} Disk image (dd)")
    print(f"{GREEN}4){RESET} Build filesystem timeline (fls + mactime)")
    print(f"{GREEN}5){RESET} Aggregate logs (/var/log) into tar.gz")
    print(f"{GREEN}6){RESET} Capture network traffic to pcap (tcpdump)")
    print(f"{GREEN}7){RESET} YARA scan")
    print(f"{GREEN}8){RESET} Malware scan with ClamAV")
    print(f"{GREEN}9){RESET} Generate detailed incident report (PDF+HTML)")
    print(f"{GREEN}0){RESET} Return to Rajasploit menu")
    return input(f"\n{CYAN}Forensics > {RESET}").strip()

# Utility: run command safely and save output to file (stdout+stderr)
def run_and_save(cmd_list, out_path, timeout=None):
    out_path = Path(out_path)
    try:
        with out_path.open("w", errors="ignore") as fh:
            subprocess.run(cmd_list, stdout=fh, stderr=subprocess.STDOUT, check=False, timeout=timeout)
        return True
    except Exception as e:
        with open(out_path, "a") as fh:
            fh.write(f"\n[ERROR] {e}\n")
        return False

# 1. Basic evidence collection
def collect_basic():
    prefix = RUN_FOLDER / "basic"
    prefix.mkdir(parents=True, exist_ok=True)
    tasks = [
        (["uname","-a"], prefix/"uname.txt"),
        (["date"], prefix/"date.txt"),
        (["whoami"], prefix/"whoami.txt"),
        (["id"], prefix/"id.txt"),
        (["uptime"], prefix/"uptime.txt"),
        (["ps","aux"], prefix/"ps_aux.txt"),
        (["ss","-tunap"], prefix/"ss_tunap.txt"),
        (["mount"], prefix/"mounts.txt"),
        (["df","-h"], prefix/"df_h.txt"),
    ]
    for cmd,outfile in tasks:
        run_and_save(cmd,outfile)

    with open(prefix/"env.txt","w") as fh:
        for k,v in os.environ.items():
            fh.write(f"{k}={v}\n")
    print(f"{GREEN}[+] Basic evidence saved to {prefix}{RESET}")
    input("Press Enter to return to Forensics menu.")

# 2. Memory dump (volatility3 fallback)
def memory_dump():
    print(f"{MAGENTA}[+] Memory dump using volatility3 (if available){RESET}")
    vol3 = shutil.which("vol")
    out_mem = RUN_FOLDER/f"run{RUN_ID}_memory.raw"
    if vol3:
        print(f"{YELLOW}[!] Please follow volatility3 docs for memory acquisition{RESET}")
    else:
        print(f"{RED}[!] No memory acquisition tool found.{RESET}")
    input("Press Enter to return to Forensics menu.")

# 3. Disk image
def disk_image():
    device = input(f"{YELLOW}Enter device to image (/dev/sdX): {RESET}").strip()
    if not device or not Path(device).exists():
        print(f"{RED}[!] Device not found.{RESET}")
        input("Press Enter to return to menu."); return
    out_img = RUN_FOLDER/f"{Path(device).name}_image.dd"
    confirm = input(f"{YELLOW}Confirm imaging {device} -> {out_img} (type 'YES'): {RESET}")
    if confirm!="YES":
        print(f"{RED}[!] Aborted.{RESET}"); input("Enter to continue."); return
    print(f"{MAGENTA}[+] Imaging...{RESET}")
    subprocess.run(["dd","if="+device,"of="+str(out_img),"bs=4M","conv=sync,noerror"],check=False)
    print(f"{GREEN}[+] Disk image saved: {out_img}{RESET}")
    input("Press Enter to return to menu.")

# 4. Timeline
def build_timeline():
    fls = shutil.which("fls")
    mactime = shutil.which("mactime")
    if not fls or not mactime:
        print(f"{YELLOW}[!] Install sleuthkit for timeline feature{RESET}")
        input("Press Enter to return to menu."); return
    img = input(f"{YELLOW}Enter image or path: {RESET}").strip()
    if not img: print(f"{RED}[!] No input.{RESET}"); input("Enter to continue."); return
    timeline_raw = RUN_FOLDER/f"run{RUN_ID}_timeline_raw.txt"
    timeline_html = RUN_FOLDER/f"run{RUN_ID}_timeline.html"
    subprocess.run([fls,"-r",img],stdout=open(timeline_raw,"w"),stderr=subprocess.STDOUT,check=False)
    subprocess.run([mactime,"-b",str(timeline_raw)],stdout=open(timeline_html,"w"),stderr=subprocess.STDOUT,check=False)
    print(f"{GREEN}[+] Timeline saved: {timeline_html}{RESET}")
    input("Press Enter to return to menu.")

# 5. Aggregate logs
def aggregate_logs():
    tarfile_path = RUN_FOLDER/f"run{RUN_ID}_logs.tar.gz"
    subprocess.run(["tar","czf",str(tarfile_path),"/var/log"],check=False)
    print(f"{GREEN}[+] Logs archived: {tarfile_path}{RESET}")
    input("Enter to return.")

# 6. Capture network traffic
def capture_pcap():
    iface = input(f"{YELLOW}Interface (blank=any): {RESET}").strip()
    duration = input(f"{YELLOW}Duration seconds: {RESET}").strip()
    try: duration=int(duration)
    except: duration=60
    out_pcap = RUN_FOLDER/f"run{RUN_ID}_capture.pcap"
    cmd = ["sudo","timeout",str(duration),"tcpdump","-w",str(out_pcap)]
    if iface: cmd.insert(-2,"-i"); cmd.insert(-2,iface)
    subprocess.run(cmd,check=False)
    print(f"{GREEN}[+] Capture saved: {out_pcap}{RESET}")
    input("Enter to return.")

# 7. YARA scan
def yara_scan():
    rules = input(f"{YELLOW}Path to YARA rules: {RESET}").strip()
    if not rules or not Path(rules).exists(): print(f"{RED}[!] Rules not found"); input(); return
    out_file = RUN_FOLDER/f"run{RUN_ID}_yara.txt"
    subprocess.run(["yara","-r",rules,str(RUN_FOLDER)],stdout=open(out_file,"w"),stderr=subprocess.STDOUT,check=False)
    print(f"{GREEN}[+] YARA results saved: {out_file}{RESET}")
    input("Enter to return.")

# 8. ClamAV scan
def clamav_scan():
    out_file = RUN_FOLDER/f"run{RUN_ID}_clamav.txt"
    subprocess.run(["clamscan","-r",str(RUN_FOLDER)],stdout=open(out_file,"w"),stderr=subprocess.STDOUT,check=False)
    print(f"{GREEN}[+] ClamAV results saved: {out_file}{RESET}")
    input("Enter to return.")

# 9. Generate detailed incident report (PDF+HTML)
def generate_report():
    print(f"{MAGENTA}[+] Generating report...{RESET}")
    client_name = input("Client Name: ").strip()
    creator_name = input("Report Creator: ").strip()
    system_owner = input("System Owner: ").strip()
    title = input("Report Title: ").strip()

    report_json = {
        "client": client_name,
        "creator": creator_name,
        "owner": system_owner,
        "title": title,
        "datetime": datetime.now().isoformat(),
        "sections": []
    }

    # Sections 1-8
    sections = [
        ("Basic Evidence", list((RUN_FOLDER/"basic").glob("*"))),
        ("Memory Dump", list(RUN_FOLDER.glob("*memory*"))),
        ("Disk Image", list(RUN_FOLDER.glob("*_image*"))),
        ("Timeline", list(RUN_FOLDER.glob("*timeline*"))),
        ("Logs Archive", list(RUN_FOLDER.glob("*_logs*"))),
        ("Network Capture", list(RUN_FOLDER.glob("*capture*"))),
        ("YARA Scan", list(RUN_FOLDER.glob("*_yara*"))),
        ("ClamAV Scan", list(RUN_FOLDER.glob("*_clamav*")))
    ]

    for name, files in sections:
        report_json["sections"].append({
            "name": name,
            "summary": f"{len(files)} file(s) generated",
            "files": [str(f) for f in files]
        })

    # Save JSON
    json_file = RUN_FOLDER/f"run{RUN_ID}_report.json"
    with open(json_file,"w") as jf: json.dump(report_json,jf,indent=2)

    # HTML report
    html_file = RUN_FOLDER/f"run{RUN_ID}_report.html"
    with open(html_file,"w") as hf:
        hf.write(f"<html><head><title>{title}</title></head><body>")
        hf.write(f"<h1>{title}</h1>")
        hf.write(f"<p>Client: {client_name}, Creator: {creator_name}, Owner: {system_owner}</p>")
        hf.write(f"<p>Date: {datetime.now().isoformat()}</p>")
        hf.write("<hr>")
        for sec in report_json["sections"]:
            hf.write(f"<h2>{sec['name']}</h2>")
            hf.write(f"<p>Summary: {sec['summary']}</p>")
            hf.write("<ul>")
            for f in sec.get('files',[]):
                hf.write(f"<li>{Path(f).name}</li>")
            hf.write("</ul>")
        hf.write("</body></html>")

    # PDF report
    pdf_file = RUN_FOLDER/f"run{RUN_ID}_report.pdf"
    doc = SimpleDocTemplate(str(pdf_file), pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph(title, styles['Title']))
    elements.append(Paragraph(f"Client: {client_name}", styles['Normal']))
    elements.append(Paragraph(f"Creator: {creator_name}", styles['Normal']))
    elements.append(Paragraph(f"System Owner: {system_owner}", styles['Normal']))
    elements.append(Paragraph(f"Date: {datetime.now().isoformat()}", styles['Normal']))
    elements.append(Spacer(1,12))
    for sec in report_json["sections"]:
        elements.append(Paragraph(sec["name"], styles['Heading2']))
        elements.append(Paragraph(sec["summary"], styles['Italic']))
        if sec.get('files'):
            elements.append(Paragraph(
                "Files: " + ", ".join([Path(f).name for f in sec.get('files',[])]),
                styles['Italic']
            ))
        elements.append(Spacer(1,12))
    doc.build(elements)

    print(f"{GREEN}[+] Report generated: {html_file} (HTML) & {pdf_file} (PDF){RESET}")
    input("Enter to return.")

# Main loop
def main():
    while True:
        choice = menu()
        if choice=="1": collect_basic()
        elif choice=="2": memory_dump()
        elif choice=="3": disk_image()
        elif choice=="4": build_timeline()
        elif choice=="5": aggregate_logs()
        elif choice=="6": capture_pcap()
        elif choice=="7": yara_scan()
        elif choice=="8": clamav_scan()
        elif choice=="9": generate_report()
        elif choice=="0": break
        else:
            print(f"{RED}[!] Invalid option{RESET}"); time.sleep(1)

if __name__=="__main__":
    main()
