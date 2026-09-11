import imaplib
import email
import asyncio
import time
import os
from email.header import decode_header
from typing import Dict, Any
from dotenv import load_dotenv

# Import upgraded forensic engine components
from app.forensics.bec_engine import ExplainableScoringEngine
from app.forensics.chain_of_custody import ChainOfCustodyTracker
from app.api.websockets import manager as websocket_manager

load_dotenv()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")

# Initialize Forensic Core Components
scoring_engine = ExplainableScoringEngine()
custody_tracker = ChainOfCustodyTracker(parser_version="2.4.0")


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


def extract_email_data(msg) -> Dict[str, Any]:
    """Extracts email headers, authentication results, and plain text content."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                break
    else:
        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")

    # Extract Authentication-Results header if available
    auth_header = clean_header_text(msg.get("Authentication-Results", "")).lower()
    spf_status = "PASS" if "spf=pass" in auth_header else ("FAIL" if "spf=fail" in auth_header else "NONE")
    dkim_status = "PASS" if "dkim=pass" in auth_header else ("FAIL" if "dkim=fail" in auth_header else "NONE")
    dmarc_status = "PASS" if "dmarc=pass" in auth_header else ("FAIL" if "dmarc=fail" in auth_header else "NONE")

    return {
        "headers": {
            "from_address": clean_header_text(msg.get("From", "")),
            "reply_to": clean_header_text(msg.get("Reply-To", "")),
            "subject": clean_header_text(msg.get("Subject", "")),
            "message_id": clean_header_text(msg.get("Message-ID", "")),
        },
        "auth_results": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "spf_reason": f"SPF status evaluated as {spf_status}",
            "dkim_reason": f"DKIM status evaluated as {dkim_status}",
            "dmarc_reason": f"DMARC alignment evaluated as {dmarc_status}",
        },
        "body_text": body,
    }


async def process_and_alert_async(raw_bytes: bytes, parsed_email: Dict[str, Any]):
    """Calculates risk score, records custody hash block, and broadcasts live alerts."""
    # 1. Cryptographic Chain-of-Custody Block Generation
    custody_block = custody_tracker.generate_custody_block(raw_bytes)

    # 2. Advanced Explainable BEC Assessment
    risk_assessment = scoring_engine.calculate_risk(parsed_email)

    from_addr = parsed_email["headers"]["from_address"]
    subject = parsed_email["headers"]["subject"]

    print(f"\n[+] Analyzing Email from: {from_addr}")
    print(f"    Subject: {subject}")
    print(f"    Risk Score: {risk_assessment.final_score}/100 [{risk_assessment.threat_level}]")
    print(f"    SHA-256 Hash: {custody_block['current_hash']}")

    if risk_assessment.factors:
        print("    [🚨 THREAT / ANOMALIES DETECTED]")
        for factor in risk_assessment.factors:
            print(f"       └── [{factor['category']}] +{factor['score']} pts: {factor['label']} -> {factor['evidence']}")
    else:
        print("    [✔] Email verified clean. No active threat detected.")

    # 3. Broadcast Event to Real-time WebSockets Frontend
    payload = {
        "message_id": parsed_email["headers"]["message_id"],
        "from": from_addr,
        "subject": subject,
        "risk_score": risk_assessment.final_score,
        "risk_level": risk_assessment.threat_level,
        "risk_factors": risk_assessment.factors,
        "auth": parsed_email["auth_results"],
        "hash": custody_block["current_hash"],
        "timestamp": custody_block["timestamp"],
    }
    await websocket_manager.broadcast(event_type="NEW_EMAIL_ANALYZED", payload=payload)


def connect_and_listen():
    """Connects to IMAP mailbox and polls for unread messages."""
    if not EMAIL_ACCOUNT or not EMAIL_APP_PASSWORD:
        print("[!] Error: Missing EMAIL_ACCOUNT or EMAIL_APP_PASSWORD in environment.")
        return

    # Initialize asyncio event loop for WebSocket broadcasting
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, EMAIL_APP_PASSWORD)
        mail.select("inbox")
        print(f"[+] Connected to {EMAIL_ACCOUNT}. Live inbox monitoring active...\n")

        while True:
            status, messages = mail.search(None, "UNSEEN")
            if status == "OK" and messages[0]:
                for num in messages[0].split():
                    status, data = mail.fetch(num, "(RFC822)")
                    if status == "OK":
                        raw_email = data[0][1]
                        msg = email.message_from_bytes(raw_email)
                        parsed_payload = extract_email_data(msg)

                        # Run async threat assessment and WebSocket alert dispatch
                        loop.run_until_complete(process_and_alert_async(raw_email, parsed_payload))

            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[+] Engine stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    connect_and_listen()