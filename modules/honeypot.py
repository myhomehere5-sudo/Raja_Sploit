#!/usr/bin/env python3
"""
modules/honeypot.py

Corrected single-file Rajasploit Honeypot with interactive CLI, Telegram + Gmail alerts,
background server, logging, auto-ban heuristics, and deploy helper.

Usage:
    python3 modules/honeypot.py
"""

from __future__ import annotations
import os
import sys
import time
import json
import socket
import random
import threading
import socketserver
import tarfile
import subprocess
import traceback
from email.message import EmailMessage
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict, deque

# Optional extras
try:
    import paramiko
except Exception:
    paramiko = None

# ---------------- configuration ----------------
BASE = Path("results/honeypot")
LOGDIR = BASE / "logs"
REPORT_DIR = BASE / "reports"
BANNED_FILE = BASE / "banned.json"
ALERT_CONFIG = Path.home() / ".rajasploit_honey_conf.json"

DEFAULT_PORT = 2222
MAX_LOG_SIZE = 8 * 1024 * 1024
ENCODING = "utf-8"

ALERT_MIN_INTERVAL = 300           # seconds between alerts per IP (default)
AUTO_BAN_THRESHOLD = 20            # connections/min threshold to auto-ban
BAN_TIME_SECONDS = 3600            # ban duration default
MAX_CONCURRENT = 100
CAPTURE_FIRST_LINES = 20
CONN_TIMEOUT = 120                 # seconds

# CLI colors
RESET = "\033[0m"
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"

# ensure directories
BASE.mkdir(parents=True, exist_ok=True)
LOGDIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------- Email / Telegram defaults (env overrides) ----------------
MY_GMAIL = os.environ.get("HONEY_GMAIL_USER", os.environ.get("RAJASPLOIT_GMAIL", "myhomehere5@gmail.com"))
MY_APP_PASSWORD = os.environ.get("HONEY_GMAIL_APP_PASSWORD", os.environ.get("RAJASPLOIT_GMAIL_APP_PASS", "ednqyoxbtuxnfvpm"))
NOTIFY_TO = os.environ.get("HONEY_ALERT_RECIPIENT", "myhomehere5@gmail.com")

ENABLE_EMAIL_ALERTS = os.environ.get("HONEY_ENABLE_EMAIL_ALERTS", "1") not in ("0", "false", "False")
ENABLE_TELEGRAM = os.environ.get("HONEY_ENABLE_TELEGRAM", "0") not in ("0", "false", "False")
TELEGRAM_TOKEN = os.environ.get("HONEY_TELEGRAM_TOKEN", "7600223112:AAEAZlTAepT9u-cGw6gTdGzhTUjQ1yApcwY")
TELEGRAM_CHAT_ID = os.environ.get("HONEY_TELEGRAM_CHAT_ID", "7494990730")

EMAIL_RETRY_COUNT = int(os.environ.get("HONEY_EMAIL_RETRY_COUNT", "1"))
EMAIL_RETRY_DELAY = float(os.environ.get("HONEY_EMAIL_RETRY_DELAY", "0.5"))

# ---------------- global state ----------------
_honey_server = None
_honey_thread = None
_server_lock = threading.Lock()
_active_connections = {}       # ip -> {'start': ts, 'port': port}
_conn_count = 0
_conn_count_lock = threading.Lock()

BANNED_IPS = {}  # ip -> expiry_ts (0=permanent)

_ip_counters = defaultdict(lambda: deque(maxlen=1000))
_last_alert = {}   # ip -> last alert timestamp
_alert_cfg = {}    # loaded from ALERT_CONFIG

# ---------------- helpers ----------------
def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def load_alert_config():
    global _alert_cfg, ALERT_MIN_INTERVAL, AUTO_BAN_THRESHOLD, BAN_TIME_SECONDS, MAX_CONCURRENT, ENABLE_TELEGRAM, TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
    if ALERT_CONFIG.exists():
        try:
            cfg = json.loads(ALERT_CONFIG.read_text())
            _alert_cfg = cfg or {}
            ALERT_MIN_INTERVAL = int(_alert_cfg.get("alert_min_interval", ALERT_MIN_INTERVAL))
            AUTO_BAN_THRESHOLD = int(_alert_cfg.get("auto_ban_threshold", AUTO_BAN_THRESHOLD))
            BAN_TIME_SECONDS = int(_alert_cfg.get("ban_time_seconds", BAN_TIME_SECONDS))
            MAX_CONCURRENT = int(_alert_cfg.get("max_concurrent", MAX_CONCURRENT))
            if _alert_cfg.get("telegram_token"):
                TELEGRAM_TOKEN = _alert_cfg.get("telegram_token")
                ENABLE_TELEGRAM = True
            if _alert_cfg.get("telegram_chat_id"):
                TELEGRAM_CHAT_ID = _alert_cfg.get("telegram_chat_id")
            return True
        except Exception:
            _alert_cfg = {}
            return False
    _alert_cfg = {}
    return False

def save_banned():
    try:
        BANNED_FILE.write_text(json.dumps({k: v for k, v in BANNED_IPS.items()}))
    except Exception:
        pass

def load_banned():
    global BANNED_IPS
    if BANNED_FILE.exists():
        try:
            data = json.loads(BANNED_FILE.read_text())
            BANNED_IPS = {k: float(v) for k, v in data.items()}
        except Exception:
            BANNED_IPS = {}
    else:
        BANNED_IPS = {}

load_alert_config()
load_banned()

def _safe_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in s)

def client_log_path(client_ip):
    ts = int(time.time())
    safe_ip = _safe_filename(client_ip.replace(":", "_"))
    return LOGDIR / f"{safe_ip}_{ts}.log"

def rotate_logs():
    for p in LOGDIR.glob("*.log"):
        try:
            if p.stat().st_size > MAX_LOG_SIZE:
                p.rename(p.with_suffix(p.suffix + ".old"))
        except Exception:
            pass

# ---------------- network helpers ----------------
def get_primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def get_all_local_ips():
    ips = []
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True).strip()
        for ip in out.split():
            if ip and ip != "127.0.0.1" and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    p = get_primary_ip()
    if p and p not in ips and p != "127.0.0.1":
        ips.append(p)
    if not ips:
        ips = ["127.0.0.1"]
    return ips

def get_mac(ip):
    try:
        out = subprocess.check_output(["arp", "-n", ip], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if ip in line:
                parts = line.split()
                for p in parts:
                    if ":" in p and len(p.split(":")) == 6:
                        return p
    except Exception:
        pass
    return "N/A"

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

# ---------------- fake FS / shell simulation ----------------
def _make_fake_fs():
    now = datetime.now(timezone.utc).strftime("%b %d %H:%M")
    return {
        "/etc/hostname": socket.gethostname() + "\n",
        "/etc/issue": "Ubuntu 18.04.5 LTS \\n \\l\n",
        "/etc/passwd": ("root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"),
        "/root/.bash_history": "whoami\npwd\nls -la\ncat /etc/passwd\nuname -a\n",
        "/var/log/auth.log": f"{now} host sshd[1234]: Accepted password for root from 10.0.0.1 port 1234 ssh2\n",
        "/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\n",
    }

_FAKE_FS = _make_fake_fs()

def _fake_ls(path):
    if path in (".", "/"): return "bin  boot  dev  etc  home  lib  tmp  var\n"
    if path == "/etc": return "hosts  hostname  passwd  issue  ssh\n"
    if path == "/home": return "user\n"
    return ""

def _fake_ps():
    lines = [
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
        "root         1  0.0  0.1  22504  4100 ?        Ss   Jan01   0:05 /sbin/init",
        f"root      1201  0.0  0.3  50000 12000 ?        Sl   {datetime.now(timezone.utc).strftime('%b%d')}   0:20 /usr/bin/python3 honeypot.py",
    ]
    return "\n".join(lines) + "\n"

def _fake_netstat():
    lines = [
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State",
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN",
        "tcp        0      0 127.0.0.1:631          0.0.0.0:*               LISTEN",
    ]
    return "\n".join(lines) + "\n"

def _simulate_progress(conn, label="Downloading"):
    for p in range(0, 101, 20):
        try:
            conn.sendall(f"{label}: {p}%\r\n".encode(ENCODING))
        except Exception:
            return
        time.sleep(random.uniform(0.05, 0.18))

# ---------------- module registry ----------------
_MODULES = {}
def register_module(name, func):
    _MODULES[name] = func

def run_module(name, *args):
    fn = _MODULES.get(name)
    if not fn:
        return f"[module:{name}] not found\n"
    try:
        return fn(*args)
    except Exception as e:
        return f"[module:{name}] error: {e}\n"

def _mod_recon_scan(target="127.0.0.1"):
    return f"[recon] quick scan of {target}: 22/tcp open, 80/tcp open\n"
def _mod_ssh_brute(target="127.0.0.1"):
    return f"[ssh.brute] simulated brute against {target}: 0 success after 100 tries\n"

register_module("recon.scan", _mod_recon_scan)
register_module("ssh.brute", _mod_ssh_brute)

# ---------------- simulated interactive shell ----------------
def simulate_shell_interaction(conn, fh, client_ip, first_capture_list, timeout=CONN_TIMEOUT):
    try:
        conn.settimeout(timeout)
        user = "root"; host = socket.gethostname()
        prompt = f"[{user}@{host} ~]$ ".encode(ENCODING)
        try: conn.sendall(f" {host}\n\n".encode(ENCODING))
        except: return
        try: conn.sendall(prompt)
        except: return
        buf = b""
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                break
            except Exception:
                break
            if not data:
                break
            buf += data
            if b"\n" in buf or b"\r\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = rest
                line_text = line.decode(ENCODING, errors="replace").strip()
                if not line_text:
                    try: conn.sendall(prompt); continue
                    except: break
                fh.write(f"[{now_iso()}] CMD: {line_text}\n"); fh.flush()
                if len(first_capture_list) < CAPTURE_FIRST_LINES:
                    first_capture_list.append(line_text)
                parts = line_text.split()
                cmd = parts[0]
                # help
                if line_text in ("help", "?"):
                    out = ("Supported: whoami, id, pwd, ls, ls -la, cat, tail, head, ps, netstat, ss, nmap, "
                           "wget, curl, python, sudo, recon.scan, ssh.brute, exit\n")
                    conn.sendall(out.encode(ENCODING)); conn.sendall(prompt); continue
                # module dispatch
                if "." in cmd and cmd.split(".",1)[0] in ("recon","ssh"):
                    out = run_module(cmd, *(parts[1:]))
                    conn.sendall(out.encode(ENCODING)); conn.sendall(prompt); continue
                # direct commands (common set)
                resp = ""
                if cmd == "whoami":
                    resp = user + "\n"
                elif cmd == "id":
                    resp = "uid=0(root) gid=0(root) groups=0(root)\n"
                elif cmd in ("pwd","cwd"):
                    resp = "/root\n"
                elif cmd == "hostname":
                    resp = host + "\n"
                elif cmd == "uname":
                    resp = f"Linux {host} 4.15.0-66-generic x86_64\n"
                elif cmd == "ls":
                    arg = parts[1] if len(parts)>1 else "."
                    resp = _fake_ls(arg)
                elif cmd == "cat":
                    path = parts[1] if len(parts)>1 else ""
                    resp = _FAKE_FS.get(path, f"cat: {path}: No such file or directory\n")
                elif cmd == "tail":
                    path = parts[-1] if len(parts)>1 else ""
                    content = _FAKE_FS.get(path,"").splitlines()
                    resp = "\n".join(content[-10:]) + ("\n" if content else "")
                elif cmd == "head":
                    path = parts[-1] if len(parts)>1 else ""
                    content = _FAKE_FS.get(path,"").splitlines()
                    resp = "\n".join(content[:10]) + ("\n" if content else "")
                elif cmd == "ps":
                    resp = _fake_ps()
                elif cmd in ("netstat","ss"):
                    resp = _fake_netstat()
                elif cmd == "nmap":
                    target = parts[-1] if len(parts)>1 else "127.0.0.1"
                    resp = (f"Starting Nmap 7.60 ( https://nmap.org ) at {datetime.now(timezone.utc).strftime('%H:%M')}\n"
                            f"Nmap scan report for {target}\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n\nNmap done.\n")
                elif cmd in ("wget","curl"):
                    t = threading.Thread(target=_simulate_progress, args=(conn,"Downloading"), daemon=True); t.start()
                    filename = parts[-1] if len(parts)>1 else "index.html"
                    resp = f"Saved to: {filename}\n"
                elif cmd == "python":
                    resp = "Python 3.8.10 (default, ...)\\n>>> \n"
                elif cmd == "sudo":
                    try:
                        conn.sendall(b"[sudo] password for root: ")
                        pwdbuf = b""
                        while b"\n" not in pwdbuf:
                            p = conn.recv(1024)
                            if not p: break
                            pwdbuf += p
                        if random.random() < 0.5:
                            resp = "Sorry, try again.\n"
                        else:
                            resp = ""
                    except Exception:
                        resp = "sudo: unable to authenticate\n"
                elif cmd in ("exit","logout","quit"):
                    try: conn.sendall(b"exit\n"); conn.close()
                    except: pass
                    return
                else:
                    if random.random() < 0.25:
                        resp = f"-bash: {cmd}: command not found\n"
                    else:
                        resp = f"{cmd}: ELF 64-bit LSB executable, x86-64\n"
                time.sleep(random.uniform(0.03,0.45))
                try:
                    if resp: conn.sendall(str(resp).encode(ENCODING, errors="replace"))
                except Exception:
                    return
                try: conn.sendall(prompt)
                except Exception: return
    except Exception:
        pass

# ---------------- proxy helper ----------------
def proxy_to_external_sandbox(in_sock, sandbox_host, sandbox_port, timeout=10):
    try:
        out = socket.create_connection((sandbox_host, int(sandbox_port)), timeout=timeout)
    except Exception as e:
        return False, f"connect_failed:{e}"
    out.settimeout(timeout); in_sock.settimeout(timeout)
    def forward(src,dst):
        try:
            while True:
                data = src.recv(4096)
                if not data: break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try: dst.shutdown(socket.SHUT_WR)
            except: pass
    t1 = threading.Thread(target=forward, args=(in_sock,out), daemon=True)
    t2 = threading.Thread(target=forward, args=(out,in_sock), daemon=True)
    t1.start(); t2.start(); t1.join(timeout); t2.join(timeout)
    try: out.close()
    except: pass
    return True, "proxied"

# ---------------- heuristics / ban ----------------
def is_banned(ip):
    v = BANNED_IPS.get(ip)
    if v is None:
        return False
    if v == 0:
        return True
    if time.time() > v:
        try:
            del BANNED_IPS[ip]; save_banned()
        except Exception:
            pass
        return False
    return True

def record_connection(ip):
    now = time.time(); dq = _ip_counters[ip]; dq.append(now)
    recent = [t for t in dq if now - t <= 60]
    if len(recent) >= AUTO_BAN_THRESHOLD:
        BANNED_IPS[ip] = now + BAN_TIME_SECONDS; save_banned(); return True
    return False

# ---------------- server handler ----------------
class HPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global _conn_count
        client_ip, client_port = self.client_address[0], self.client_address[1]

        if is_banned(client_ip):
            try:
                self.request.close()
            except Exception:
                pass
            return

        with _conn_count_lock:
            if _conn_count >= MAX_CONCURRENT:
                try:
                    self.request.sendall(b"Too many connections\r\n")
                except Exception:
                    pass
                try:
                    self.request.close()
                except Exception:
                    pass
                return
            _conn_count += 1

        with _server_lock:
            _active_connections[client_ip] = {"start": time.time(), "port": self.server.server_address[1]}

        logfile = client_log_path(client_ip)
        started = now_iso()
        captured_first = []
        mac = get_mac(client_ip)
        rdns = reverse_dns(client_ip)

        try:
            with open(logfile, "w", errors="ignore") as fh:
                fh.write(f"connection_from: {client_ip}:{client_port}\n")
                fh.write(f"start: {started}\n")
                fh.write(f"mac: {mac}\n")
                fh.write(f"reverse_dns: {rdns}\n\n")
                fh.flush()

                # send a standard SSH-like banner first (bots often expect it)
                try:
                    self.request.sendall(b"SSH-2.0-OpenSSH_7.9p1\r\n")
                except Exception:
                    pass

                sandbox_cfg = _alert_cfg.get("sandbox", {}) if _alert_cfg else {}
                s_enabled = sandbox_cfg.get("enabled", True) if sandbox_cfg else True
                s_type = sandbox_cfg.get("type", "simulated") if sandbox_cfg else "simulated"

                if s_enabled and s_type == "external" and sandbox_cfg.get("host") and sandbox_cfg.get("port"):
                    fh.write(f"[{now_iso()}] ACTION: proxy -> {sandbox_cfg.get('host')}:{sandbox_cfg.get('port')}\n"); fh.flush()
                    ok, reason = proxy_to_external_sandbox(self.request, sandbox_cfg.get("host"), sandbox_cfg.get("port"), timeout=sandbox_cfg.get("timeout", 10))
                    fh.write(f"[{now_iso()}] PROXY_RESULT: {ok} {reason}\n"); fh.flush()
                else:
                    fh.write(f"[{now_iso()}] ACTION: simulated_shell\n"); fh.flush()
                    simulate_shell_interaction(self.request, fh, client_ip, captured_first, timeout=sandbox_cfg.get("timeout", CONN_TIMEOUT) if sandbox_cfg else CONN_TIMEOUT)

                fh.write(f"\nend: {now_iso()}\n")
                fh.flush()
        except Exception as e:
            try:
                with open(logfile, "a", errors="ignore") as fh:
                    fh.write(f"[{now_iso()}] HANDLER_ERROR: {e}\n")
            except Exception:
                pass

        # Upon close: force-send an alert (bypasses rate limit) for immediate notification
        try:
            first_blob = "\n".join(captured_first)[:4000]
            _last_alert[client_ip] = 0
            ok = force_send_alert_email(client_ip, client_port, first_blob, str(logfile))
            if ENABLE_TELEGRAM:
                send_telegram_alert(client_ip, client_port, first_blob)
        except Exception:
            pass

        try:
            recorded_banned = record_connection(client_ip)
            if recorded_banned:
                try:
                    with open(logfile, "a", errors="ignore") as fh:
                        fh.write(f"[{now_iso()}] AUTO_BANNED: True\n")
                except Exception:
                    pass
        except Exception:
            pass

        with _server_lock:
            if client_ip in _active_connections:
                del _active_connections[client_ip]
        with _conn_count_lock:
            _conn_count -= 1

# ---------------- threaded server ----------------
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def start_honeypot(port=DEFAULT_PORT, bind_address="0.0.0.0"):
    global _honey_server, _honey_thread
    if _honey_server is not None:
        print(f"{YELLOW}[!] Honeypot already running on port {_honey_server.server_address[1]}{RESET}")
        return False
    try:
        server = ThreadedTCPServer((bind_address, port), HPHandler)
    except Exception as e:
        print(f"{RED}[!] Failed to bind {bind_address}:{port}: {e}{RESET}")
        traceback.print_exc()
        return False

    def serve():
        try:
            server.serve_forever()
        except Exception:
            traceback.print_exc()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    _honey_server = server
    _honey_thread = t
    print(f"{GREEN}[+] Honeypot started on {bind_address}:{port} — logs -> {LOGDIR}{RESET}")
    if bind_address == "0.0.0.0":
        print(f"{GREEN}[+] Reachable addresses:{RESET}")
        for ip in get_all_local_ips():
            print(f"    {ip}:{port}")
    return True

def stop_honeypot():
    global _honey_server, _honey_thread
    if _honey_server is None:
        print(f"{YELLOW}[!] Honeypot is not running.{RESET}"); return False
    try:
        _honey_server.shutdown(); _honey_server.server_close()
    except Exception:
        pass
    _honey_server = None; _honey_thread = None
    print(f"{GREEN}[+] Honeypot stopped.{RESET}"); return True

# ---------------- email + telegram alerting ----------------
def _write_logfile_error(logfile_path, msg):
    try:
        with open(logfile_path, "a", encoding=ENCODING, errors="ignore") as lf:
            lf.write(f"[{now_iso()}] ALERT_LOG: {msg}\n")
    except Exception:
        print(f"{YELLOW}[!] Failed to write alert log to {logfile_path}{RESET}")

def _send_email_via_smtp(cfg, client_ip, client_port, first_lines, logfile_path, force=False):
    smtp_user = (cfg.get("smtp_user") or cfg.get("smtp") or cfg.get("smtp_user_email")) if cfg else None
    app_password = (cfg.get("app_password") or cfg.get("app_pass") or cfg.get("password")) if cfg else None
    notify_to = (cfg.get("notify_to") or cfg.get("notify") or None) if cfg else None

    if not smtp_user:
        smtp_user = MY_GMAIL
    if not app_password:
        app_password = MY_APP_PASSWORD
    if not notify_to:
        notify_to = NOTIFY_TO

    if not smtp_user or not app_password:
        msg = "SMTP credentials missing (smtp_user/app_password)"
        _write_logfile_error(logfile_path, msg)
        print(f"{YELLOW}[!] {msg}{RESET}")
        return False

    subject = f"[Rajasploit Honeypot] Connection from {client_ip}:{client_port}"
    body = (
        f"Honeypot detected connection\n\n"
        f"Source: {client_ip}\nPort: {client_port}\nTime (UTC): {now_iso()}\n\n"
        f"Captured (first lines):\n{first_lines}\n\nLog file: {logfile_path}\n"
    )
    msg = EmailMessage()
    msg["From"] = smtp_user
    msg["To"] = notify_to
    msg["Subject"] = subject
    msg.set_content(body)

    attempts = [
        ("SSL", "smtp.gmail.com", 465),
        ("STARTTLS", "smtp.gmail.com", 587),
    ]
    last_exc = None
    for method, host, port in attempts:
        try:
            if method == "SSL":
                import smtplib
                with smtplib.SMTP_SSL(host, port, timeout=15) as s:
                    s.login(smtp_user, app_password)
                    s.send_message(msg)
                _write_logfile_error(logfile_path, f"ALERT_SENT: method=SSL to={notify_to}")
                print(f"{GREEN}[+] Alert email sent via SSL to {notify_to}{RESET}")
                return True
            else:
                import smtplib
                with smtplib.SMTP(host, port, timeout=15) as s:
                    s.ehlo(); s.starttls(); s.ehlo()
                    s.login(smtp_user, app_password)
                    s.send_message(msg)
                _write_logfile_error(logfile_path, f"ALERT_SENT: method=STARTTLS to={notify_to}")
                print(f"{GREEN}[+] Alert email sent via STARTTLS to {notify_to}{RESET}")
                return True
        except Exception as e:
            last_exc = e
            _write_logfile_error(logfile_path, f"ALERT_SEND_FAILED method={method} exception={e}")
            print(f"{YELLOW}[!] Alert send failed via {method}: {e}{RESET}")
            time.sleep(0.6)
    _write_logfile_error(logfile_path, f"ALERT_SEND_ALL_FAILED last_exception: {last_exc}")
    print(f"{RED}[!] All alert send attempts failed. Last exception: {last_exc}{RESET}")
    return False

def can_alert_for(ip):
    nowt = time.time()
    last = _last_alert.get(ip, 0)
    min_interval = int(_alert_cfg.get("alert_min_interval", ALERT_MIN_INTERVAL)) if _alert_cfg else ALERT_MIN_INTERVAL
    if nowt - last >= min_interval:
        _last_alert[ip] = nowt
        return True
    return False

def send_alert_email_sync(client_ip, client_port, first_lines, logfile_path):
    try:
        cfg = _alert_cfg or {}
        if not (cfg or ENABLE_EMAIL_ALERTS):
            return False
        if cfg and not cfg.get("enable_alerts", True):
            return False
        if not can_alert_for(client_ip):
            return False
        return _send_email_via_smtp(cfg, client_ip, client_port, first_lines, logfile_path)
    except Exception as e:
        _write_logfile_error(logfile_path, f"send_alert_email_sync exception: {e}\n{traceback.format_exc()}")
        print(f"{YELLOW}[!] send_alert_email_sync exception: {e}{RESET}")
        return False

def send_alert_email_async(client_ip, client_port, first_lines, logfile_path):
    threading.Thread(target=send_alert_email_sync, args=(client_ip, client_port, first_lines, logfile_path), daemon=True).start()

def force_send_alert_email(client_ip, client_port, first_lines, logfile_path):
    try:
        cfg = _alert_cfg or {}
        if not (cfg or ENABLE_EMAIL_ALERTS):
            _write_logfile_error(logfile_path, "force_send_alert_email: alerts disabled")
            return False
        return _send_email_via_smtp(cfg, client_ip, client_port, first_lines, logfile_path, force=True)
    except Exception as e:
        _write_logfile_error(logfile_path, f"force_send_alert_email exception: {e}\n{traceback.format_exc()}")
        print(f"{YELLOW}[!] force_send_alert_email exception: {e}{RESET}")
        return False

# Telegram helper
def send_telegram_alert(client_ip, client_port, first_lines=""):
    token = TELEGRAM_TOKEN or _alert_cfg.get("telegram_token", "")
    chat = TELEGRAM_CHAT_ID or _alert_cfg.get("telegram_chat_id", "")
    if not token or not chat:
        return False
    text = f"Rajasploit Honeypot\nTime: {now_iso()}\nIP: {client_ip}:{client_port}\n\n{first_lines[:400]}"
    def _tg():
        try:
            import urllib.parse, urllib.request
            payload = urllib.parse.urlencode({"chat_id": chat, "text": text})
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            req = urllib.request.Request(url, data=payload.encode(), headers={"Content-Type":"application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return True
        except Exception as e:
            print(f"{YELLOW}[!] Telegram alert failed: {e}{RESET}")
            return False
    threading.Thread(target=_tg, daemon=True).start()
    return True

# ---------------- remote deploy helpers (paramiko optional) ----------------
def _connect_ssh(host, port, username, password=None, key_filename=None, timeout=10):
    if paramiko is None:
        raise RuntimeError("paramiko not installed")
    client = paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    conn_kwargs = dict(hostname=host, port=int(port), username=username, timeout=timeout)
    if key_filename:
        conn_kwargs["key_filename"] = str(key_filename)
    else:
        conn_kwargs["password"] = password
    client.connect(**conn_kwargs)
    return client

def deploy_remote_honeypot_single(host, username, password=None, ssh_port=22,
                          remote_path="/tmp/remote_honeypot.py", remote_config_path="~/.rajasploit_honey_conf.json",
                          local_script_path=None, local_config_path=None, key_filename=None, run_background=True):
    if paramiko is None:
        print(f"{RED}[!] paramiko required. Install: pip3 install paramiko{RESET}"); return False
    try:
        if local_script_path is None: raise ValueError("local_script_path must be provided")
        local_script_path = Path(local_script_path)
        if not local_script_path.exists():
            print(f"{RED}[!] Local script not found: {local_script_path}{RESET}"); return False
        ssh = _connect_ssh(host, ssh_port, username, password, key_filename)
        sftp = ssh.open_sftp()
        try: ssh.exec_command(f"mkdir -p {os.path.dirname(remote_path)}")
        except: pass
        try:
            sftp.put(str(local_script_path), remote_path); ssh.exec_command(f"chmod 700 {remote_path}")
        except Exception as e:
            print(f"{RED}[!] Upload script failed: {e}{RESET}"); sftp.close(); ssh.close(); return False
        uploaded_config = False
        if local_config_path:
            cfg_path = Path(local_config_path)
        else:
            cfg_path = Path.home() / ".rajasploit_honey_conf.json"
        if cfg_path.exists():
            try:
                remote_cfg_final = remote_config_path.replace('~', f"/home/{username}")
                ssh.exec_command(f"mkdir -p {os.path.dirname(remote_cfg_final)}")
                sftp.put(str(cfg_path), remote_cfg_final); ssh.exec_command(f"chmod 600 {remote_cfg_final}")
                uploaded_config = True
            except Exception as e:
                print(f"{YELLOW}[!] Upload config failed: {e}{RESET}")
        try:
            if run_background: cmd = f"nohup python3 {remote_path} > /tmp/honey.log 2>&1 &"
            else: cmd = f"python3 {remote_path}"
            ssh.exec_command(cmd)
        except Exception as e:
            print(f"{RED}[!] Start remote failed: {e}{RESET}"); sftp.close(); ssh.close(); return False
        sftp.close(); ssh.close()
        print(f"{GREEN}[+] Deployed on {host} (config uploaded: {uploaded_config}){RESET}")
        return True
    except Exception as e:
        print(f"{RED}[!] Deploy failed for {host}: {e}{RESET}"); return False

def deploy_remote_honeypot():
    if paramiko is None:
        print(f"{RED}[!] paramiko not installed. Install: pip3 install paramiko{RESET}"); return
    hosts_raw = input("Target host(s) (comma separated): ").strip()
    if not hosts_raw:
        print(f"{YELLOW}[!] No hosts provided.{RESET}"); return
    hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]
    username = input("SSH Username: ").strip()
    use_key = input("Use private key? (y/N): ").strip().lower() == "y"
    key_path = None; password = None
    if use_key:
        key_path = input("Path to private key (e.g. ~/.ssh/id_rsa): ").strip()
        if key_path.startswith("~"): key_path = os.path.expanduser(key_path)
    else:
        import getpass; password = getpass.getpass(f"Password for {username}@hosts: ")
    ssh_port = input("SSH port (default 22): ").strip() or "22"
    remote_path = input("Remote path for script (default /tmp/remote_honeypot.py): ").strip() or "/tmp/remote_honeypot.py"
    remote_config_path = input("Remote config path (default /.rajasploit_honey_conf.json): ").strip() or "/.rajasploit_honey_conf.json"
    local_script = Path(__file__).resolve()
    cfg_local = Path.home() / ".rajasploit_honey_conf.json"
    for h in hosts:
        deploy_remote_honeypot_single(host=h, username=username, password=password, ssh_port=int(ssh_port),
                                      remote_path=remote_path, remote_config_path=remote_config_path,
                                      local_script_path=local_script,
                                      local_config_path=str(cfg_local) if cfg_local.exists() else None,
                                      key_filename=key_path if key_path else None, run_background=True)

# ---------------- CLI / utilities ----------------
def list_logs():
    logs = sorted(LOGDIR.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not logs:
        print(f"{YELLOW}[!] No logs found.{RESET}"); return []
    for p in logs:
        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime).isoformat()
            print(f"- {p.name} ({p.stat().st_size} bytes) modified: {mtime}")
        except Exception:
            print(f"- {p.name}")
    return logs

def export_logs(tar_name=None):
    if tar_name is None: tar_name = BASE / f"honeypot_logs_{int(time.time())}.tar.gz"
    else: tar_name = Path(tar_name)
    with tarfile.open(tar_name, "w:gz") as tar:
        for p in LOGDIR.glob("*"):
            tar.add(p, arcname=p.name)
    print(f"{GREEN}[+] Logs exported to {tar_name}{RESET}"); return tar_name

def view_log_detail(logname):
    p = LOGDIR / logname
    if not p.exists(): print(f"{RED}[!] Log not found: {logname}{RESET}"); return
    print(f"{CYAN}---- {logname} ----{RESET}")
    print(p.read_text(errors="ignore"))
    print(f"{CYAN}---- end ----{RESET}")

def ban_ip(ip, duration_seconds=0):
    expiry = 0 if duration_seconds == 0 else time.time() + duration_seconds
    BANNED_IPS[ip] = expiry; save_banned(); print(f"{GREEN}[+] Banned IP: {ip} expiry: {expiry}{RESET}")

def unban_ip(ip):
    if ip in BANNED_IPS:
        del BANNED_IPS[ip]; save_banned(); print(f"{GREEN}[+] Unbanned IP: {ip}{RESET}")
    else:
        print(f"{YELLOW}[!] IP not in banned list.{RESET}")

def show_banned():
    if not BANNED_IPS:
        print(f"{CYAN}[*] No banned IPs.{RESET}"); return
    for ip, expiry in BANNED_IPS.items():
        exp_str = "permanent" if expiry==0 else datetime.fromtimestamp(expiry).isoformat()
        print(f"- {ip}: {exp_str}")

def show_active():
    with _server_lock:
        if not _active_connections:
            print(f"{CYAN}[*] No active connections.{RESET}"); return
        for ip, meta in _active_connections.items():
            age = int(time.time() - meta["start"]); port = meta.get("port")
            print(f"- {ip}:{port} (started {age}s ago)")

# ---------------- interactive CLI ----------------
def banner():
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass
    print(f"{CYAN}=== Rajasploit Honeypot Module ==={RESET}")

def interactive_cli():
    # declare globals that will be reassigned here
    global ENABLE_TELEGRAM
    while True:
        try:
            banner()
            print(f"{GREEN}1){RESET} Start honeypot")
            print(f"{GREEN}2){RESET} Stop honeypot")
            print(f"{GREEN}3){RESET} List logs")
            print(f"{GREEN}4){RESET} View log details")
            print(f"{GREEN}5) {RESET}Show active connections")
            print(f"{GREEN}6) {RESET}Ban IP")
            print(f"{GREEN}7) {RESET}Unban IP")
            print(f"{GREEN}8) {RESET}Show banned IPs")
            print(f"{GREEN}9) {RESET}Deploy honeypot on remote device(s)")
            print(f"{GREEN}10){RESET} Export logs")
            print(f"{GREEN}11){RESET} Generate report")
            print(f"{GREEN}12) {RESET}Reload config")
            print(f"{GREEN}0) {RESET}Exit")
            choice = input(f"{CYAN}Honeypot>{RESET} ").strip()

            if choice == "1":
                p = input(f"Port (default {DEFAULT_PORT}): ").strip()
                try:
                    port = int(p) if p else DEFAULT_PORT
                except Exception:
                    port = DEFAULT_PORT
                bind = input("Bind address (default 0.0.0.0): ").strip() or "0.0.0.0"
                start_honeypot(port=port, bind_address=bind)
                input("Press Enter to continue...")

            elif choice == "2":
                stop_honeypot(); input("Press Enter to continue...")

            elif choice == "3":
                list_logs(); input("Press Enter to continue...")

            elif choice == "4":
                logs = list_logs()
                if not logs:
                    input("Press Enter to continue..."); continue
                sel = input("Enter log filename (or number): ").strip()
                if sel.isdigit():
                    idx = int(sel) - 1
                    if 0 <= idx < len(logs):
                        view_log_detail(logs[idx].name)
                    else:
                        print(f"{YELLOW}[!] Invalid selection{RESET}")
                else:
                    view_log_detail(sel)
                input("Press Enter to continue...")

            elif choice == "5":
                show_active(); input("Press Enter to continue...")

            elif choice == "6":
                ip = input("IP to ban: ").strip()
                if not ip:
                    print(f"{YELLOW}[!] No IP entered{RESET}"); input("Press Enter to continue..."); continue
                dur = input("Duration seconds (0 = permanent, default 0): ").strip()
                dur_s = int(dur) if dur and dur.isdigit() else 0
                ban_ip(ip, dur_s); input("Press Enter to continue...")

            elif choice == "7":
                ip = input("IP to unban: ").strip()
                if not ip:
                    print(f"{YELLOW}[!] No IP entered{RESET}"); input("Press Enter to continue..."); continue
                unban_ip(ip); input("Press Enter to continue...")

            elif choice == "8":
                show_banned(); input("Press Enter to continue...")

            elif choice == "9":
                deploy_remote_honeypot(); input("Press Enter to continue...")

            elif choice == "10":
                tname = input("Export filename (leave blank for autogenerated): ").strip() or None
                res = export_logs(tname)
                print(f"Exported: {res}"); input("Press Enter to continue...")

            elif choice == "11":
                # placeholder for generate_report if implemented
                if 'generate_report' in globals() and callable(globals()['generate_report']):
                    try:
                        generate_report()
                    except Exception as e:
                        print(f"{YELLOW}[!] generate_report failed: {e}{RESET}")
                else:
                    print(f"{YELLOW}[!] generate_report() not implemented{RESET}")
                input("Press Enter to continue...")

            elif choice == "12":
                ok = load_alert_config(); print(f"{GREEN if ok else YELLOW}[+] Reloaded config (success={ok}){RESET}")
                input("Press Enter to continue...")

            elif choice == "0":
                print("Exiting honeypot module menu.")
                return

            else:
                print(f"{YELLOW}[!] Unknown option: {choice}{RESET}")
                input("Press Enter to continue...")

        except KeyboardInterrupt:
            print("\nInterrupted. Returning to menu.")
            continue
        except Exception as e:
            print(f"{RED}[!] Error in menu loop: {e}{RESET}")
            traceback.print_exc()
            time.sleep(0.5)

# ---------------- summary / simple report ----------------
def summary_report():
    logs = list(LOGDIR.glob("*.log"))
    if not logs:
        print(f"{YELLOW}[!] No logs to summarize.{RESET}"); return
    ip_counter = Counter()
    total = 0
    keywords = Counter()
    for p in logs:
        total += 1
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            text = ""
        first = text.splitlines()[0] if text else ""
        if first.startswith("connection_from:"):
            ip = first.split(":", 1)[1].strip()
            ip_counter[ip] += 1
        lowered = text.lower()
        for word in ["root","ssh","password","admin","get","post","login","pwd","passwd"]:
            keywords[word] += lowered.count(word)
    print(f"Total logs: {total}")
    print("Top IPs:")
    for ip, cnt in ip_counter.most_common(10):
        print(f" - {ip}: {cnt}")
    print("Keywords:")
    for k, v in keywords.most_common(20):
        print(f" - {k}: {v}")

# ---------------- main guard ----------------
if __name__ == "__main__":
    # Show menu and allow starting server manually (matches your requested UX)
    try:
        interactive_cli()
    except KeyboardInterrupt:
        print("\n[!] Interrupted — stopping honeypot if running.")
        try:
            stop_honeypot()
        except Exception:
            pass
        sys.exit(0)
