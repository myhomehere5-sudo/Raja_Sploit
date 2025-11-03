# Rajasploit(Pronunced as Reja_sploit)

**Rajasploit** is a professional, modular cybersecurity toolkit for ethical hackers, penetration testers, and security enthusiasts. It provides reconnaissance, exploitation, forensics, monitoring, honeypot deployment, and extra utility modules. The tool automatically collects session results and generates polished PDF and HTML reports.

# Important things to make sure while using Rajasploit
- Make  sure you are using the tool as a Root user 
- In honeypot while you try to use it it will ask a App password that password should create   your self .For that search "How to set app password in Google account"
-You can modilfy this tool asper your comfort
-Make sure the requirement.txt & setup.sh exicuted 

## Features

- **Reconnaissance** — network scanning, subdomain discovery, footprinting.
- **Attacks & Exploitation** — auto-detect vulnerabilities and exploitation attempts.
- **Forensics & Incident Response** — analyze artifacts, logs, and disk/memory captures.
- **Defensive & Monitoring** — network & endpoint monitoring, alerts.
- **Honeypot Module** — detect and log suspicious activity.
- **Extra Utilities** — optional modules like automated scripts and tools.

**Reporting Module:**

- Automatically detects session folders.
- Summarizes module activities and counts files.
- Generates PDF (ReportLab) and HTML reports with embedded charts and images.
- Supports visual charts of visuals vs logs/data per module.

---

## Installation

### Requirements

- Python 3.10+
- Linux/macOS (Windows may work with WSL)
- `pip3` package manager

### Install Dependencies

```bash
git clone https://github.com/yourusername/rajasploit.git
cd rajasploit
chmod +x setup.sh
./setup.sh
