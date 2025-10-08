#!/usr/bin/env python3
"""
Integrated Rajasploit Honeypot (single file)
Features:
 - Simulated interactive shell (realistic responses)
 - Logging per connection
 - Auto-ban heuristics
 - Gmail alerts (configurable)
 - HTML + PDF reports with charts (matplotlib + reportlab)
 - Remote deploy via paramiko (optional)
 - CLI menu (start/stop/list/view/export/summary/active/ban/unban/banned/deploy/reload/report)
Usage:
  python3 honeypot.py
Config example (~/.rajasploit_honey_conf.json):
{
  "enable_alerts": true,
  "smtp_user": "youremail@gmail.com",
  "app_password": "your_app_password",
  "notify_to": "alerts@example.com",
  "alert_min_interval": 60,
  "sandbox": {"enabled": true, "type": "simulated", "timeout": 120}
}
"""
import os, sys, time, json, socket, random, threading, socketserver, tarfile, subprocess, smtplib
from email.message import EmailMessage
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict, deque

# Optional libs
try:
    import paramiko
except Exception:
    paramiko = None
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception:
    plt = None
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet
except Exception:
    SimpleDocTemplate = None

# ---------------- configuration ----------------
BASE = Path("results/honeypot")
LOGDIR = BASE / "logs"
REPORT_DIR = BASE / "reports"
BANNED_FILE = BASE / "banned.json"
ALERT_CONFIG = Path.home() / ".rajasploit_honey_conf.json"

DEFAULT_PORT = 2222
MAX_LOG_SIZE = 8 * 1024 * 1024
ENCODING = "utf-8"

ALERT_MIN_INTERVAL = 300
AUTO_BAN_THRESHOLD = 20
BAN_TIME_SECONDS = 3600
MAX_CONCURRENT = 100
CAPTURE_FIRST_LINES = 20
CONN_TIMEOUT = 120

# CLI colors
RESET = "\033[0m"; RED = "\033[1;31m"; GREEN = "\033[1;32m"; YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"; MAGENTA = "\033[1;35m"

# create dirs
BASE.mkdir(parents=True, exist_ok=True)
LOGDIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------- global state ----------------
_honey_server = None
_honey_thread = None
_server_lock = threading.Lock()
_active_connections = {}       # ip -> {'start': ts, 'port': port}
_conn_count = 0
_conn_count_lock = threading.Lock()

BANNED_IPS = {}
def load_banned():
    global BANNED_IPS
    if BANNED_FILE.exists():
        try:
            raw = json.loads(BANNED_FILE.read_text())
            BANNED_IPS = {k: float(v) for k,v in raw.items()}
        except Exception:
            BANNED_IPS = {}
    else:
        BANNED_IPS = {}
def save_banned():
    try:
        BANNED_FILE.write_text(json.dumps(BANNED_IPS))
    except Exception:
        pass
load_banned()

_alert_cfg = {}
_last_alert = {}
_ip_counters = defaultdict(lambda: deque(maxlen=1000))

# ---------------- config loader ----------------
def load_alert_config():
    global _alert_cfg, ALERT_MIN_INTERVAL, AUTO_BAN_THRESHOLD, BAN_TIME_SECONDS, MAX_CONCURRENT
    if ALERT_CONFIG.exists():
        try:
            cfg = json.loads(ALERT_CONFIG.read_text())
            _alert_cfg = cfg
            ALERT_MIN_INTERVAL = int(cfg.get("alert_min_interval", ALERT_MIN_INTERVAL))
            AUTO_BAN_THRESHOLD = int(cfg.get("auto_ban_threshold", AUTO_BAN_THRESHOLD))
            BAN_TIME_SECONDS = int(cfg.get("ban_time_seconds", BAN_TIME_SECONDS))
            MAX_CONCURRENT = int(cfg.get("max_concurrent", MAX_CONCURRENT))
            return True
        except Exception:
            _alert_cfg = {}
            return False
    _alert_cfg = {}
    return False

# load at start
load_alert_config()

# ---------------- helpers ----------------
def now_iso(): return datetime.utcnow().isoformat() + "Z"
def client_log_path(client_ip):
    ts = int(time.time()); safe_ip = client_ip.replace(":", "_")
    return LOGDIR / f"{safe_ip}_{ts}.log"
def rotate_logs():
    for p in LOGDIR.glob("*.log"):
        try:
            if p.stat().st_size > MAX_LOG_SIZE:
                p.rename(p.with_suffix(".log.old"))
        except Exception:
            pass
def is_banned(ip):
    v = BANNED_IPS.get(ip)
    if not v: return False
    if v == 0: return True
    if time.time() > v:
        try: del BANNED_IPS[ip]; save_banned()
        except: pass
        return False
    return True
def record_connection(ip):
    now = time.time(); dq = _ip_counters[ip]; dq.append(now)
    recent = [t for t in dq if now - t <= 60]
    if len(recent) >= AUTO_BAN_THRESHOLD:
        BANNED_IPS[ip] = now + BAN_TIME_SECONDS; save_banned(); return True
    return False
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
    try: return socket.gethostbyaddr(ip)[0]
    except: return "N/A"

# ---------------- fake FS & helpers ----------------
def _make_fake_fs():
    now = datetime.now().strftime("%b %d %H:%M")
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
        f"root      1201  0.0  0.3  50000 12000 ?        Sl   {datetime.utcnow().strftime('%b%d')}   0:20 /usr/bin/python3 honeypot.py",
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
        try: conn.sendall(f"{label}: {p}%\r\n".encode(ENCODING))
        except Exception: return
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

# example modules
def _mod_recon_scan(target="127.0.0.1"):
    return f"[recon] quick scan of {target}: 22/tcp open, 80/tcp open\n"
def _mod_ssh_brute(target="127.0.0.1"):
    return f"[ssh.brute] simulated brute against {target}: 0 success after 100 tries\n"

register_module("recon.scan", _mod_recon_scan)
register_module("ssh.brute", _mod_ssh_brute)

# ---------------- realistic simulated shell ----------------
def simulate_shell_interaction(conn, fh, client_ip, first_capture_list, timeout=CONN_TIMEOUT):
    """
    Realistic interactive shell.
    Logs each CMD to fh. Supports many common commands and module dispatch.
    """
    try:
        conn.settimeout(timeout)
        user = "root"; host = socket.gethostname()
        prompt = f"[{user}@{host} ~]$ ".encode(ENCODING)
        try: conn.sendall(f"Welcome to {host}\nType 'help' for commands.\n".encode(ENCODING))
        except: return
        try: conn.sendall(prompt)
        except: return
        buf = b""
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            buf += data
            # treat newline or CRLF
            if b"\n" in buf or b"\r\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = rest
                line_text = line.decode(ENCODING, errors="replace").strip()
                if not line_text:
                    try: conn.sendall(prompt); continue
                    except: break
                # log
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
                # module dispatch (recon.scan etc.)
                if "." in cmd and cmd.split(".",1)[0] in ("recon","ssh"):
                    out = run_module(cmd, *(parts[1:]))
                    conn.sendall(out.encode(ENCODING)); conn.sendall(prompt); continue
                # direct commands
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
                    resp = (f"Starting Nmap 7.60 ( https://nmap.org ) at {datetime.utcnow().strftime('%H:%M')}\n"
                            f"Nmap scan report for {target}\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n\nNmap done.\n")
                elif cmd in ("wget","curl"):
                    # simulate progress in background and then show saved
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
                        # pretend incorrect half the time
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

# ---------------- proxy helper (optional) ----------------
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

# ---------------- honeypot handler ----------------
class HPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global _conn_count
        client_ip, client_port = self.client_address[0], self.client_address[1]
        if is_banned(client_ip):
            try: self.request.close()
            except: pass
            return
        with _conn_count_lock:
            if _conn_count >= MAX_CONCURRENT:
                try: self.request.sendall(b"Too many connections\r\n")
                except: pass
                try: self.request.close()
                except: pass
                return
            _conn_count += 1
        with _server_lock:
            _active_connections[client_ip] = {"start": time.time(), "port": self.server.server_address[1]}
        logfile = client_log_path(client_ip)
        started = now_iso(); captured_first = []
        mac = get_mac(client_ip); rdns = reverse_dns(client_ip)
        try:
            with open(logfile, "w", errors="ignore") as fh:
                fh.write(f"connection_from: {client_ip}:{client_port}\n")
                fh.write(f"start: {started}\n")
                fh.write(f"mac: {mac}\n")
                fh.write(f"reverse_dns: {rdns}\n\n"); fh.flush()
                sandbox_cfg = _alert_cfg.get("sandbox", {}) if _alert_cfg else {}
                s_enabled = sandbox_cfg.get("enabled", True)
                s_type = sandbox_cfg.get("type", "simulated") if s_enabled else None
                if s_enabled and s_type == "external" and sandbox_cfg.get("host") and sandbox_cfg.get("port"):
                    fh.write(f"[{now_iso()}] ACTION: proxy -> {sandbox_cfg.get('host')}:{sandbox_cfg.get('port')}\n"); fh.flush()
                    ok, reason = proxy_to_external_sandbox(self.request, sandbox_cfg.get("host"), sandbox_cfg.get("port"), timeout=sandbox_cfg.get("timeout", 10))
                    fh.write(f"[{now_iso()}] PROXY_RESULT: {ok} {reason}\n"); fh.flush()
                else:
                    fh.write(f"[{now_iso()}] ACTION: simulated_shell\n"); fh.flush()
                    simulate_shell_interaction(self.request, fh, client_ip, captured_first, timeout=sandbox_cfg.get("timeout", CONN_TIMEOUT) if sandbox_cfg else CONN_TIMEOUT)
                fh.write(f"\nend: {now_iso()}\n"); fh.flush()
        except Exception as e:
            try:
                with open(logfile, "a", errors="ignore") as fh:
                    fh.write(f"[{now_iso()}] HANDLER_ERROR: {e}\n")
            except: pass
        # auto-ban heuristics
        try:
            recorded = record_connection(client_ip)
            if recorded:
                with open(logfile, "a", errors="ignore") as fh:
                    fh.write(f"[{now_iso()}] AUTO_BANNED: True\n")
        except:
            pass
        # send alert (first captured lines)
        try:
            first_blob = "\n".join(captured_first)[:4000]
            if _alert_cfg and _alert_cfg.get("enable_alerts", True):
                # asynchronous send uses stored SMTP config
                threading.Thread(target=send_alert_email_async, args=(client_ip, client_port, first_blob, str(logfile)), daemon=True).start()
        except Exception:
            pass
        # cleanup
        with _server_lock:
            if client_ip in _active_connections: del _active_connections[client_ip]
        with _conn_count_lock:
            _conn_count -= 1

# ---------------- server wrapper ----------------
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
        print(f"{RED}[!] Failed to bind: {e}{RESET}")
        return False
    def serve():
        try: server.serve_forever()
        except: pass
    t = threading.Thread(target=serve, daemon=True); t.start()
    _honey_server = server; _honey_thread = t
    ips = get_all_local_ips()
    print(f"{GREEN}[+] Honeypot started on {bind_address}:{port} — logs -> {LOGDIR}{RESET}")
    if bind_address == "0.0.0.0":
        print(f"{GREEN}[+] Reachable addresses:{RESET}")
        for ip in ips: print(f"    {ip}:{port}")
    return True

def stop_honeypot():
    global _honey_server, _honey_thread
    if _honey_server is None:
        print(f"{YELLOW}[!] Honeypot is not running.{RESET}"); return False
    try:
        _honey_server.shutdown(); _honey_server.server_close()
    except: pass
    _honey_server = None; _honey_thread = None
    print(f"{GREEN}[+] Honeypot stopped.{RESET}"); return True

# ---------------- email alerting ----------------
def can_alert_for(ip):
    now = time.time(); last = _last_alert.get(ip, 0)
    if now - last >= _alert_cfg.get("alert_min_interval", ALERT_MIN_INTERVAL):
        _last_alert[ip] = now; return True
    return False

def send_alert_email_sync(client_ip, client_port, first_lines, logfile_path):
    if not _alert_cfg or not _alert_cfg.get("enable_alerts", True):
        return False
    try:
        if not can_alert_for(client_ip): return False
        smtp_user = _alert_cfg.get("myhomehere5@gmail.com")
        app_password = _alert_cfg.get("ednqyoxbtuxnfvpm")
        notify_to = _alert_cfg.get("myhomehere5@gmail.com") or smtp_user
        if not smtp_user or not app_password:
            print(f"{YELLOW}[!] SMTP config missing{RESET}"); return False
        subject = f"[Rajasploit Honeypot] Connection from {client_ip}:{client_port}"
        body = (f"Honeypot detected connection\n\nSource: {client_ip}\nPort: {client_port}\nTime (UTC): {now_iso()}\n\n"
                f"Captured (first lines):\n{first_lines}\n\nLog file: {logfile_path}\n")
        msg = EmailMessage(); msg["From"] = smtp_user; msg["To"] = notify_to; msg["Subject"] = subject
        msg.set_content(body)
        # use SSL if possible
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as s:
                s.login(smtp_user, app_password); s.send_message(msg)
        except Exception as e:
            # try STARTTLS fallback
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as s:
                s.ehlo(); s.starttls(); s.login(smtp_user, app_password); s.send_message(msg)
        return True
    except Exception as e:
        print(f"{YELLOW}[!] Email send failed: {e}{RESET}"); return False

def send_alert_email_async(client_ip, client_port, first_lines, logfile_path):
    threading.Thread(target=send_alert_email_sync, args=(client_ip, client_port, first_lines, logfile_path), daemon=True).start()

# ---------------- remote deploy helpers ----------------
LOCAL_CONFIG = Path.home() / ".rajasploit_honey_conf.json"
def _connect_ssh(host, port, username, password=None, key_filename=None, timeout=10):
    if paramiko is None: raise RuntimeError("paramiko not installed")
    client = paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    conn_kwargs = dict(hostname=host, port=int(port), username=username, timeout=timeout)
    if key_filename: conn_kwargs["key_filename"] = str(key_filename)
    else: conn_kwargs["password"] = password
    client.connect(**conn_kwargs); return client

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
        if local_config_path is None: cfg_path = Path.home() / ".rajasploit_honey_conf.json"
        else: cfg_path = Path(local_config_path)
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
    if paramiko is None: print(f"{RED}[!] paramiko not installed. Install: pip3 install paramiko{RESET}"); return
    hosts_raw = input("Target host(s) (comma separated): ").strip()
    if not hosts_raw: print(f"{YELLOW}[!] No hosts provided.{RESET}"); return
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
    remote_config_path = input("Remote config path (default ~/.rajasploit_honey_conf.json): ").strip() or "~/.rajasploit_honey_conf.json"
    local_script = Path(__file__).resolve()
    for h in hosts:
        deploy_remote_honeypot_single(host=h, username=username, password=password, ssh_port=int(ssh_port),
                                      remote_path=remote_path, remote_config_path=remote_config_path,
                                      local_script_path=local_script,
                                      local_config_path=LOCAL_CONFIG if (LOCAL_CONFIG := Path.home() / ".rajasploit_honey_conf.json") and (LOCAL_CONFIG.exists()) else None,
                                      key_filename=key_path if key_path else None, run_background=True)

# ---------------- CLI helpers (logs, report) ----------------
def list_logs():
    logs = sorted(LOGDIR.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not logs: print(f"{YELLOW}[!] No logs found.{RESET}"); return []
    for p in logs:
        mtime = datetime.fromtimestamp(p.stat().st_mtime).isoformat()
        print(f"- {p.name} ({p.stat().st_size} bytes) modified: {mtime}")
    return logs

def export_logs(tar_name=None):
    if tar_name is None: tar_name = BASE / f"honeypot_logs_{int(time.time())}.tar.gz"
    else: tar_name = Path(tar_name)
    with tarfile.open(tar_name, "w:gz") as tar:
        for p in LOGDIR.glob("*"): tar.add(p, arcname=p.name)
    print(f"{GREEN}[+] Logs exported to {tar_name}{RESET}"); return tar_name

def view_log_detail(logname):
    p = LOGDIR / logname
    if not p.exists(): print(f"{RED}[!] Log not found: {logname}{RESET}"); return
    print(f"{CYAN}---- {logname} ----{RESET}"); print(p.read_text(errors="ignore")); print(f"{CYAN}---- end ----{RESET}")

def ban_ip(ip, duration_seconds=0):
    expiry = 0 if duration_seconds == 0 else time.time() + duration_seconds
    BANNED_IPS[ip] = expiry; save_banned(); print(f"{GREEN}[+] Banned IP: {ip} expiry: {expiry}{RESET}")

def unban_ip(ip):
    if ip in BANNED_IPS:
        del BANNED_IPS[ip]; save_banned(); print(f"{GREEN}[+] Unbanned IP: {ip}{RESET}")
    else: print(f"{YELLOW}[!] IP not in banned list.{RESET}")

def show_banned():
    if not BANNED_IPS: print(f"{CYAN}[*] No banned IPs.{RESET}"); return
    for ip, expiry in BANNED_IPS.items():
        exp_str = "permanent" if expiry==0 else datetime.fromtimestamp(expiry).isoformat()
        print(f"- {ip}: {exp_str}")

def show_active():
    with _server_lock:
        if not _active_connections: print(f"{CYAN}[*] No active connections.{RESET}"); return
        for ip, meta in _active_connections.items():
            age = int(time.time() - meta["start"]); port = meta.get("port")
            print(f"- {ip}:{port} (started {age}s ago)")

def get_primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception: return None

def get_all_local_ips():
    ips = []
    try:
        out = subprocess.check_output(["hostname","-I"], text=True).strip()
        for ip in out.split():
            if ip and ip != "127.0.0.1" and ip not in ips: ips.append(ip)
    except Exception: pass
    p = get_primary_ip()
    if p and p not in ips and p != "127.0.0.1": ips.append(p)
    if not ips: ips = ["127.0.0.1"]
    return ips

# ---------------- reporting (charts + PDF) ----------------
def _gather_logs():
    sessions = []; cmd_counter = Counter(); ip_counter = Counter()
    for p in sorted(LOGDIR.glob("*.log")):
        text = p.read_text(errors="ignore"); sessions.append({"file": p.name, "text": text})
        for line in text.splitlines():
            if line.startswith("connection_from:"):
                ip = line.split(":",1)[1].strip(); ip_counter[ip] += 1; break
        for line in text.splitlines():
            if "CMD:" in line:
                try:
                    cmd = line.split("CMD:",1)[1].strip().split()[0]; cmd_counter[cmd] += 1
                except: pass
    return sessions, cmd_counter, ip_counter

def generate_charts(cmd_counter, ip_counter, out_dir=REPORT_DIR):
    out = {}
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    if plt and cmd_counter:
        top_cmds = cmd_counter.most_common(10); labels = [c for c,_ in top_cmds]; vals = [v for _,v in top_cmds]
        plt.figure(figsize=(8,4)); plt.bar(range(len(vals)), vals); plt.xticks(range(len(vals)), labels, rotation=45, ha='right'); plt.tight_layout()
        chart1 = out_dir / f"chart_cmds_{int(time.time())}.png"; plt.savefig(chart1); plt.close(); out['cmds']=str(chart1)
    if plt and ip_counter:
        top_ips = ip_counter.most_common(5); labels = [c for c,_ in top_ips]; vals = [v for _,v in top_ips]
        plt.figure(figsize=(6,6)); plt.pie(vals, labels=labels, autopct="%1.1f%%"); plt.tight_layout()
        chart2 = out_dir / f"chart_ips_{int(time.time())}.png"; plt.savefig(chart2); plt.close(); out['ips']=str(chart2)
    return out

def generate_report():
    sessions, cmd_counter, ip_counter = _gather_logs()
    if not sessions:
        print(f"{YELLOW}[!] No logs to include in report.{RESET}"); return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_file = REPORT_DIR / f"honeypot_report_{timestamp}.html"
    pdf_file = REPORT_DIR / f"honeypot_report_{timestamp}.pdf"
    charts = generate_charts(cmd_counter, ip_counter)
    # HTML
    with open(html_file,"w",encoding="utf-8") as h:
        h.write("<html><head><meta charset='utf-8'><title>Honeypot Report</title></head><body>")
        h.write(f"<h1>Rajasploit Honeypot Report</h1><p>Generated: {datetime.now().isoformat()}</p>")
        h.write("<h2>Summary</h2>")
        h.write(f"<p>Total sessions: {len(sessions)}</p>")
        h.write("<h3>Top commands</h3><ul>")
        for cmd,cnt in cmd_counter.most_common(20): h.write(f"<li>{cmd}: {cnt}</li>")
        h.write("</ul>")
        if 'cmds' in charts: h.write(f\"<h3>Commands chart</h3><img src='{os.path.basename(charts['cmds'])}' style='max-width:800px'>\")
        h.write("<h3>Top IPs</h3><ul>")
        for ip,cnt in ip_counter.most_common(20): h.write(f"<li>{ip}: {cnt}</li>")
        h.write("</ul>")
        if 'ips' in charts: h.write(f\"<h3>IP distribution</h3><img src='{os.path.basename(charts['ips'])}' style='max-width:600px'>\")
        h.write("<h2>Sessions detail</h2>")
        for s in sessions: h.write(f\"<h3>{s['file']}</h3><pre>{s['text']}</pre>\")
        h.write("</body></html>")
    # copy charts next to html
    for k,v in charts.items():
        try:
            dst = html_file.parent / os.path.basename(v)
            if not dst.exists():
                with open(v,"rb") as rf, open(dst,"wb") as wf: wf.write(rf.read())
        except: pass
    print(f"{GREEN}[+] HTML report generated: {html_file}{RESET}")
    # PDF via ReportLab
    if SimpleDocTemplate is None:
        print(f"{YELLOW}[!] reportlab not available — skipping PDF generation.{RESET}"); return
    styles = getSampleStyleSheet(); doc = SimpleDocTemplate(str(pdf_file), pagesize=letter); story=[]
    story.append(Paragraph("Rajasploit Honeypot Report", styles["Title"])); story.append(Spacer(1,12))
    story.append(Paragraph(f"Generated on: {datetime.now().isoformat()}", styles["Normal"])); story.append(Spacer(1,12))
    story.append(Paragraph("Summary", styles["Heading2"])); story.append(Paragraph(f"Total sessions: {len(sessions)}", styles["Normal"])); story.append(Spacer(1,8))
    story.append(Paragraph("Top commands", styles["Heading3"]))
    for cmd,cnt in cmd_counter.most_common(20): story.append(Paragraph(f"{cmd}: {cnt}", styles["Normal"]))
    story.append(Spacer(1,8))
    if 'cmds' in charts:
        try: story.append(Paragraph("Commands chart", styles["Heading3"])); story.append(RLImage(charts['cmds'], width=450, height=200)); story.append(Spacer(1,8))
        except: pass
    story.append(Paragraph("Top IPs", styles["Heading3"]))
    for ip,cnt in ip_counter.most_common(20): story.append(Paragraph(f"{ip}: {cnt}", styles["Normal"]))
    story.append(Spacer(1,8))
    if 'ips' in charts:
        try: story.append(Paragraph("IP distribution", styles["Heading3"])); story.append(RLImage(charts['ips'], width=350, height=350)); story.append(Spacer(1,8))
        except: pass
    story.append(Paragraph("Sessions detail (latest first)", styles["Heading2"]))
    for s in sessions:
        story.append(Paragraph(s['file'], styles["Heading3"]))
        for chunk in (s['text'] or "").splitlines():
            story.append(Paragraph(chunk.replace("&","&amp;").replace("<","&lt;"), styles["Normal"]))
        story.append(Spacer(1,6))
    try:
        doc.build(story); print(f"{GREEN}[+] PDF report generated: {pdf_file}{RESET}")
    except Exception as e:
        print(f"{YELLOW}[!] PDF generation failed: {e}{RESET}")

# ---------------- CLI/menu ----------------
def banner_cli():
    os.system("clear"); print(f"{CYAN}=== Rajasploit Honeypot (Full) ==={RESET}")
    print(f"{YELLOW}** Use only on systems you are authorized to run this on. Misuse may be illegal. **{RESET}\n")

def menu():
    banner_cli()
    print(f"{GREEN}1){RESET} Start honeypot (default port {DEFAULT_PORT})")
    print(f"{GREEN}2){RESET} Stop honeypot")
    print(f"{GREEN}3){RESET} Show active connections")
    print(f"{GREEN}4){RESET} Ban IP")
    print(f"{GREEN}5){RESET} Unban IP")
    print(f"{GREEN}6){RESET} Show banned IPs")
    print(f"{GREEN}7){RESET} List logs")
    print(f"{GREEN}8){RESET} View log detail")
    print(f"{GREEN}9){RESET} Export logs")
    print(f"{GREEN}10){RESET} Reload config")
    print(f"{GREEN}11){RESET} Deploy honeypot on remote device(s)")
    print(f"{GREEN}12){RESET} Summary report (HTML + PDF with graphs)")
    print(f"{GREEN}0){RESET} Exit honeypot menu")
    return input(f"\n{CYAN}Honeypot > {RESET}").strip()

def interactive_cli():
    load_alert_config()
    while True:
        choice = menu()
        if choice == "1":
            p = input("Port (default 2222): ").strip()
            try: port = int(p) if p else DEFAULT_PORT
            except: port = DEFAULT_PORT
            bind = input("Bind to (blank for all '0.0.0.0'): ").strip() or "0.0.0.0"
            start_honeypot(port=port, bind_address=bind); input("Press Enter to continue...")
        elif choice == "2":
            stop_honeypot(); input("Press Enter to continue...")
        elif choice == "3":
            show_active(); input("Press Enter to continue...")
        elif choice == "4":
            ip = input("IP to ban: ").strip(); dur = input("Ban duration seconds (0 = permanent, default 3600): ").strip() or "3600"
            try: d = int(dur)
            except: d = 3600
            if ip: ban_ip(ip, duration_seconds=d)
            input("Press Enter to continue...")
        elif choice == "5":
            ip = input("IP to unban: ").strip()
            if ip: unban_ip(ip)
            input("Press Enter to continue...")
        elif choice == "6":
            show_banned(); input("Press Enter to continue...")
        elif choice == "7":
            list_logs(); input("Press Enter to continue...")
        elif choice == "8":
            name = input("Enter log filename: ").strip(); view_log_detail(name); input("Press Enter to continue...")
        elif choice == "9":
            tname = input("Output tar name (optional): ").strip() or None; export_logs(tname); input("Press Enter to continue...")
        elif choice == "10":
            load_alert_config(); print(f"{GREEN}[+] Config reloaded{RESET}"); input("Press Enter to continue...")
        elif choice == "11":
            deploy_remote_honeypot(); input("Press Enter to continue...")
        elif choice == "12":
            generate_report(); input("Press Enter to continue...")
        elif choice == "0":
            stop_honeypot(); print(f"{MAGENTA}[+] Exiting honeypot menu.{RESET}"); break
        else:
            print(f"{RED}[!] Invalid choice.{RESET}"); time.sleep(0.4)

# ---------------- main ----------------
if __name__ == "__main__":
    try:
        interactive_cli()
    except KeyboardInterrupt:
        print("\n[!] Interrupted — stopping honeypot if running.")
        stop_honeypot()
        sys.exit(0)
