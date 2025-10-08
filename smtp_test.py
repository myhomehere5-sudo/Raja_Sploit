# smtp_test.py
import smtplib
from email.message import EmailMessage

SMTP_USER = "myhomehere5@gmail.com"
APP_PASS = "ednqyoxbtuxnfvpm"
TO = "myhomehere5@gmail.com"

msg = EmailMessage()
msg["From"] = SMTP_USER
msg["To"] = TO
msg["Subject"] = "Honeypot SMTP test"
msg.set_content("This is a test from honeypot SMTP.")

try:
    # SSL
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as s:
        s.login(SMTP_USER, APP_PASS)
        s.send_message(msg)
    print("SMTP_SSL success")
except Exception as e:
    print("SMTP_SSL failed:", e)
    try:
        # STARTTLS fallback
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_USER, APP_PASS)
            s.send_message(msg)
        print("STARTTLS success")
    except Exception as e2:
        print("STARTTLS failed:", e2)
