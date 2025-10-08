#!/usr/bin/env python3
"""
modules/extra_features.py

Extra Utilities module for Rajasploit (utilities toolbox).
Keep honeypot as Module 7 (separate).

Features:
 - Random Password Generator
 - Base64 Encode / Decode
 - Encrypt / Decrypt (Fernet if cryptography installed)
 - QR Code generator (requires qrcode + Pillow)
 - Link masker (creates local HTML redirect page for authorized testing)
 - SHA256 hash generator
 - Password Strength Checker

All output files/logs are stored under results/extras/.
Use only on systems/networks you are authorized to test.
"""

import os
import sys
import time
import base64
import hashlib
import secrets
import string
from pathlib import Path
from datetime import datetime

# Optional libs
try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
try:
    import qrcode
    from PIL import Image
except Exception:
    qrcode = None

# Colors
RESET = "\033[0m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"

# Results folder
BASE = Path("results/extras")
BASE.mkdir(parents=True, exist_ok=True)
LOG = BASE / f"extras_{int(time.time())}.log"

def log(msg):
    ts = datetime.utcnow().isoformat() + "Z"
    with open(LOG, "a", errors="ignore") as fh:
        fh.write(f"[{ts}] {msg}\n")

def banner():
    os.system("clear")
    print(f"{CYAN}=== Extra Utilities ==={RESET}")
    print(f"{YELLOW}** Use only on systems you are authorized to test. Misuse is illegal. **{RESET}\n")

def menu():
    banner()
    print(f"{GREEN}1){RESET} Random Password Generator")
    print(f"{GREEN}2){RESET} Base64 Encode / Decode")
    print(f"{GREEN}3){RESET} Encrypt / Decrypt (Fernet recommended)")
    print(f"{GREEN}4){RESET} QR Code generator (text/link -> image)")
    print(f"{GREEN}5){RESET} Link masker (create local redirect HTML)")
    print(f"{GREEN}6){RESET} SHA256 Hash generator")
    print(f"{GREEN}7){RESET} Password Strength Checker")
    print(f"{GREEN}0){RESET} Return to Rajasploit menu")
    choice = input(f"\n{CYAN}Extras > {RESET}")
    return choice.strip()

# 1. Random Password Generator
def gen_password():
    print(f"{MAGENTA}[+] Random Password Generator{RESET}")
    length = input("Length (default 16): ").strip()
    try:
        length = int(length) if length else 16
    except:
        length = 16
    use_upper = input("Include UPPERCASE? (Y/n): ").strip().lower() != "n"
    use_digits = input("Include digits? (Y/n): ").strip().lower() != "n"
    use_symbols = input("Include symbols? (Y/n): ").strip().lower() != "n"

    alphabet = string.ascii_lowercase
    if use_upper:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>/?"

    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    print(f"{GREEN}Password:{RESET} {password}")
    log(f"Generated password (len={length})")
    input("Press Enter to return to Extras menu.")

# 2. Base64 Encode / Decode
def base64_tool():
    print(f"{MAGENTA}[+] Base64 Encode / Decode{RESET}")
    mode = input("Mode (e)ncode / (d)ecode [e]: ").strip().lower() or "e"
    text = input("Enter text: ").strip()
    if mode == "e" or mode == "encode":
        encoded = base64.b64encode(text.encode()).decode()
        print(f"{GREEN}Encoded:{RESET} {encoded}")
        log("Base64 encode performed")
    else:
        try:
            decoded = base64.b64decode(text.encode()).decode()
            print(f"{GREEN}Decoded:{RESET} {decoded}")
            log("Base64 decode performed")
        except Exception as e:
            print(f"{RED}[!] Failed to decode: {e}{RESET}")
            log(f"Base64 decode failed: {e}")
    input("Press Enter to return to Extras menu.")

# 3. Encrypt / Decrypt using Fernet if available
def encrypt_decrypt():
    print(f"{MAGENTA}[+] Encrypt / Decrypt (Fernet){RESET}")
    if Fernet is None:
        print(f"{YELLOW}[!] cryptography not installed. To enable strong encryption, install: pip install cryptography{RESET}")
        input("Press Enter to return to Extras menu.")
        return

    action = input("(e)ncrypt / (d)ecrypt [e]: ").strip().lower() or "e"
    if action == "e":
        # allow generating a new key or using provided
        use_new = input("Generate new key? (Y/n): ").strip().lower() != "n"
        if use_new:
            key = Fernet.generate_key()
            print(f"{GREEN}Generated Key:{RESET} {key.decode()}")
            log("Generated new Fernet key")
        else:
            key = input("Enter base64 key: ").strip().encode()
        f = Fernet(key)
        plaintext = input("Enter plaintext: ").encode()
        token = f.encrypt(plaintext)
        print(f"{GREEN}Ciphertext (base64):{RESET} {token.decode()}")
        # Save sample to results
        out = BASE / f"fernet_encrypt_{int(time.time())}.txt"
        out.write_text(f"key:{key.decode()}\nct:{token.decode()}\n")
        print(f"{GREEN}Saved: {out}{RESET}")
        log("Performed Fernet encryption and saved result")
    else:
        key = input("Enter base64 key: ").strip().encode()
        token = input("Enter ciphertext (base64): ").strip().encode()
        try:
            f = Fernet(key)
            plaintext = f.decrypt(token)
            print(f"{GREEN}Plaintext:{RESET} {plaintext.decode(errors='ignore')}")
            log("Performed Fernet decryption")
        except InvalidToken:
            print(f"{RED}[!] Invalid key or token. Decryption failed.{RESET}")
            log("Fernet decryption failed: InvalidToken")
        except Exception as e:
            print(f"{RED}[!] Error: {e}{RESET}")
            log(f"Fernet decryption error: {e}")
    input("Press Enter to return to Extras menu.")

# 4. QR Code generator
def qrcode_generator():
    print(f"{MAGENTA}[+] QR Code Generator{RESET}")
    if qrcode is None:
        print(f"{YELLOW}[!] qrcode or Pillow not installed. Install with: pip install qrcode[pil]{RESET}")
        input("Press Enter to return to Extras menu.")
        return
    data = input("Enter text or URL to encode: ").strip()
    filename = input("Output filename (default qr.png): ").strip() or "qr.png"
    img = qrcode.make(data)
    out = BASE / filename
    img.save(out)
    print(f"{GREEN}QR saved: {out}{RESET}")
    log(f"Generated QR code -> {out}")
    input("Press Enter to return to Extras menu.")

import time
from pathlib import Path

# adjust this to your project structure; BASE should be a Path where results are written
BASE = Path("results/extras")
BASE.mkdir(parents=True, exist_ok=True)

MAGENTA = "\033[95m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def link_masker():
    print(f"{MAGENTA}[+] Link Masker (local redirect HTML){RESET}")
    target = input("Enter target URL (the real link) — use https://example.com to test: ").strip()
    if not target:
        print(f"{RED}[!] No URL provided.{RESET}")
        input("Press Enter to return to Extras menu.")
        return

    # visible text shown to users (not the actual href)
    fake_display = input("Anchor text to show (default 'Click here'): ").strip() or "Click here"
    filename = input("Output HTML filename (default masked.html): ").strip() or "masked.html"
    out = (BASE / filename).resolve()

    # meta refresh delay in seconds
    delay_seconds = 2

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{fake_display}</title>

  <!-- Meta refresh as fallback -->
  <meta http-equiv="refresh" content="{delay_seconds};url={target}">

  <!-- Basic responsive viewport -->
  <meta name="viewport" content="width=device-width,initial-scale=1">

  <script>
    // Primary redirect: open the target in a new tab after a short delay.
    // This uses window.open to avoid replacing the masking page in the original tab.
    (function() {{
      var target = {target!r};
      var delay = {delay_seconds} * 1000;
      // Try to open in a new tab (some browsers may block popups when not triggered by user gesture)
      setTimeout(function() {{
        try {{
          window.open(target, '_blank', 'noopener');
        }} catch (e) {{
          // fallback: navigate the current page
          window.location.replace(target);
        }}
      }}, delay);
    }})();
  </script>

  <style>
    body{{font-family:Arial,Helvetica,sans-serif;background:#f6f8fa;margin:0;padding:40px;display:flex;align-items:center;justify-content:center;height:100vh}}
    .card{{background:#fff;padding:22px;border-radius:10px;box-shadow:0 8px 24px rgba(12,20,30,0.08);max-width:680px;text-align:center}}
    .fake-link{{display:inline-block;padding:10px 14px;border-radius:8px;border:1px solid #e1e4e8;text-decoration:none;font-weight:600}}
    .hint{{margin-top:12px;color:#666;font-size:0.9rem}}
  </style>
</head>
<body>
  <div class="card">
    <h2>Opening <span class="fake-link">{fake_display}</span></h2>
    <p class="hint">If the page does not open automatically, <a href="{target}" target="_blank" rel="noopener">click here</a>.</p>
    <p class="hint">This page will automatically open the target in a new tab in {delay_seconds} seconds.</p>
  </div>
</body>
</html>
"""
    out.write_text(html, encoding="utf-8")
    print(f"{GREEN}Masked HTML saved: {out}{RESET}")

    # optional small info file, purely local and informative (no logging of visitors)
    fake_info = input("Optional fake display link text to record in local info file (press Enter to skip): ").strip()
    if fake_info:
        info_file = BASE / f"mask_info_{int(time.time())}.txt"
        info_file.write_text(f"Displayed: {fake_info}\nReal: {target}\nFile: {out}\n", encoding="utf-8")
        print(f"{GREEN}Mask info saved: {info_file}{RESET}")

    print("\nTest instructions (local):")
    print("1) Serve the folder where the file was saved, e.g.:")
    print(f"   cd {BASE}")
    print("   python3 -m http.server 8000")
    print("2) In a browser open: http://localhost:8000/" + filename)
    print("3) The page will attempt to open the target in a new tab after the delay.")
    print("If the target blocks direct access, try testing with https://example.com first.")
    input("Press Enter to return to Extras menu.")



# 6. SHA256 Hash generator
def sha256_tool():
    print(f"{MAGENTA}[+] SHA256 Hash Generator{RESET}")
    data = input("Enter text to hash: ").encode()
    h = hashlib.sha256(data).hexdigest()
    print(f"{GREEN}SHA256:{RESET} {h}")
    log("SHA256 generated")
    input("Press Enter to return to Extras menu.")

# 7. Password strength checker
def password_strength():
    print(f"{MAGENTA}[+] Password Strength Checker{RESET}")
    pwd = input("Enter password to check: ").strip()
    length = len(pwd)
    categories = 0
    if any(c.islower() for c in pwd): categories += 1
    if any(c.isupper() for c in pwd): categories += 1
    if any(c.isdigit() for c in pwd): categories += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>/?`~" for c in pwd): categories += 1

    score = 0
    if length >= 12: score += 2
    elif length >= 8: score += 1
    score += categories

    verdict = "Very Weak"
    if score >= 5:
        verdict = "Strong"
    elif score == 4:
        verdict = "Good"
    elif score == 3:
        verdict = "Weak"
    print(f"{GREEN}Length:{RESET} {length}  {GREEN}Categories:{RESET} {categories}")
    print(f"{CYAN}Strength:{RESET} {verdict}")
    log(f"Password strength checked: {verdict}")
    input("Press Enter to return to Extras menu.")

# Main loop
def main():
    while True:
        choice = menu()
        if choice == "1":
            gen_password()
        elif choice == "2":
            base64_tool()
        elif choice == "3":
            encrypt_decrypt()
        elif choice == "4":
            qrcode_generator()
        elif choice == "5":
            link_masker()
        elif choice == "6":
            sha256_tool()
        elif choice == "7":
            password_strength()
        elif choice == "0":
            break
        else:
            print(f"{RED}[!] Invalid option{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
