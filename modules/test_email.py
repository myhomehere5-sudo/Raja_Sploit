import smtplib
from email.message import EmailMessage

smtp_user = "myhomeher5@gmail.com"         # your smtp_user
app_password = "rjpjreovhjzqckoq"          # your app password
notify_to = "myhomeher5@gmail.com"         # recipient

msg = EmailMessage()
msg["From"] = smtp_user
msg["To"] = notify_to
msg["Subject"] = "Honeypot SMTP test"
msg.set_content("This is a test email from your honeypot SMTP settings.")

with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as s:
    s.ehlo()
    s.starttls()
    s.login(smtp_user, app_password)
    s.send_message(msg)
print("Email sent")
