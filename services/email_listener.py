import imaplib
import email
from email.header import decode_header
import time
import os
from dotenv import load_dotenv

load_dotenv()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")

def clean_header_text(text: str) -> str:
    """Decodes MIME encoded headers (e.g., =?UTF-8?Q?...?=) into plain text."""
    if not text:
        return ""
    decoded_fragments = decode_header(text)
    header_parts = []
    for fragment, encoding in decoded_fragments:
        if isinstance(fragment, bytes):
            header_parts.append(fragment.decode(encoding or "utf-8", errors="ignore"))
        else:
            header_parts.append(str(fragment))
    return "".join(header_parts)

def extract_email_data(msg) -> dict:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                break
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

    return {
        "headers": {
            "from": clean_header_text(msg.get("From", "")),
            "reply_to": clean_header_text(msg.get("Reply-To", "")),
            "subject": clean_header_text(msg.get("Subject", "")),
            "message_id": clean_header_text(msg.get("Message-ID", ""))
        },
        "body": body
    }

def process_and_alert(email_data: dict):
    from_addr = email_data['headers']['from'].lower()
    reply_to = email_data['headers']['reply_to'].lower()
    subject = email_data['headers']['subject']
    body = email_data['body'].lower()
    
    print(f"\n[+] Analyzing Email from: {email_data['headers']['from']}")
    print(f"    Subject: {subject}")
    
    suspicious_flags = []

    # Check for urgent financial / BEC phishing keywords
    phishing_keywords = ["urgent", "verify account", "password reset", "wire transfer", "action required", "unauthorized login"]
    found_keywords = [kw for kw in phishing_keywords if kw in subject.lower() or kw in body]
    if found_keywords:
        suspicious_flags.append(f"Suspicious Phishing Keywords: {', '.join(found_keywords)}")

    # Refined Reply-To check (Flag only if domains completely mismatch)
    if reply_to and reply_to != from_addr:
        from_domain = from_addr.split("@")[-1].replace(">", "").strip() if "@" in from_addr else ""
        reply_domain = reply_to.split("@")[-1].replace(">", "").strip() if "@" in reply_to else ""
        
        if from_domain and reply_domain and from_domain != reply_domain:
            suspicious_flags.append(f"Domain Mismatch: From '@{from_domain}' vs Reply-To '@{reply_domain}'")

    if suspicious_flags:
        print("    [🚨 THREAT DETECTED]")
        for flag in suspicious_flags:
            print(f"       └── {flag}")
    else:
        print("    [✔] Email verified. No threat detected.")

def connect_and_listen():
    if not EMAIL_ACCOUNT or not EMAIL_APP_PASSWORD:
        print("[!] Error: Missing credentials in .env file.")
        return

    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, EMAIL_APP_PASSWORD)
        mail.select("inbox")
        print(f"[+] Connected to {EMAIL_ACCOUNT}. Live inbox monitoring active...\n")

        while True:
            status, messages = mail.search(None, 'UNSEEN')
            if status == "OK" and messages[0]:
                for num in messages[0].split():
                    status, data = mail.fetch(num, '(RFC822)')
                    if status == "OK":
                        raw_email = data[0][1]
                        msg = email.message_from_bytes(raw_email)
                        parsed_payload = extract_email_data(msg)
                        process_and_alert(parsed_payload)
            
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[+] Engine stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    connect_and_listen()
