import imaplib
import email
from email.header import decode_header
import time
import os
import subprocess
from dotenv import load_dotenv

load_dotenv()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")

def clean_header(text: str) -> str:
    if not text:
        return "Not Specified"
    decoded = decode_header(text)
    parts = []
    for frag, enc in decoded:
        if isinstance(frag, bytes):
            parts.append(frag.decode(enc or "utf-8", errors="ignore"))
        else:
            parts.append(str(frag))
    return "".join(parts)

def trigger_system_alert(subject: str, sender: str, score: int):
    title = f"🚨 FRAUD EMAIL DETECTED (Risk Score: {score}/100)"
    message = f"From: {sender}\nSubject: {subject}"
    subprocess.run(["notify-send", "-u", "critical", "-i", "dialog-warning", title, message])
    subprocess.run(["paplay", "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"], check=False)

def analyze_email(msg):
    from_addr = clean_header(msg.get("From", ""))
    reply_to = clean_header(msg.get("Reply-To", ""))
    subject = clean_header(msg.get("Subject", ""))
    
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                break
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

    score = 0
    cue_keywords = ["invoice", "wire", "urgent", "bank", "transfer", "ceo", "payment", "verify account", "unauthorized login"]
    content_text = f"{subject} {body}".lower()
    
    for kw in cue_keywords:
        if kw in content_text:
            score += 15

    from_domain = from_addr.split("@")[-1].replace(">", "").strip() if "@" in from_addr else ""
    reply_domain = reply_to.split("@")[-1].replace(">", "").strip() if "@" in reply_to else ""
    
    if reply_to and reply_domain and from_domain and (from_domain != reply_domain):
        score += 45

    risk_score = min(score, 100)

    if risk_score >= 40:
        print(f"\n[🚨 THREAT] High Risk Email Detected! Score: {risk_score}")
        trigger_system_alert(subject, from_addr, risk_score)

def start_monitoring():
    if not EMAIL_ACCOUNT or not EMAIL_APP_PASSWORD:
        print("[!] Missing EMAIL_ACCOUNT or EMAIL_APP_PASSWORD in .env file.")
        return

    print(f"[+] Starting 24/7 background listener for {EMAIL_ACCOUNT}...")
    while True:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL_ACCOUNT, EMAIL_APP_PASSWORD)
            mail.select("inbox")

            while True:
                status, messages = mail.search(None, 'UNSEEN')
                if status == "OK" and messages[0]:
                    for num in messages[0].split():
                        status, data = mail.fetch(num, '(RFC822)')
                        if status == "OK":
                            raw_email = data[0][1]
                            msg = email.message_from_bytes(raw_email)
                            analyze_email(msg)
                
                time.sleep(10)

        except Exception as e:
            print(f"[!] Connection error: {e}. Reconnecting in 15s...")
            time.sleep(15)

if __name__ == "__main__":
    start_monitoring()