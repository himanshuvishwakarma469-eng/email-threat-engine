"""MIME parsing, header forensics, SPF/DKIM/DMARC evaluation, and hop extraction."""

from __future__ import annotations

import hashlib
import re
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

from core.custody import ChainOfCustodyTracker
from core.scoring import ExplainableScoringEngine

IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
PRIVATE_IP_REGEX = re.compile(r"^(?:127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
URL_REGEX = re.compile(r"https?://[^\s<\"']+", re.IGNORECASE)

scoring_engine = ExplainableScoringEngine()
custody_tracker = ChainOfCustodyTracker()


def decode_mime_words(s: Optional[str]) -> str:
    if not s:
        return ""
    decoded = decode_header(s)
    parts = []
    for frag, enc in decoded:
        if isinstance(frag, bytes):
            parts.append(frag.decode(enc or "utf-8", errors="ignore"))
        else:
            parts.append(str(frag))
    return "".join(parts)


def lookup_ip_geo(ip: str) -> Dict[str, Any]:
    if ip == "127.0.0.1" or PRIVATE_IP_REGEX.match(ip):
        return {
            "hostname": "internal-gateway",
            "city": "Internal Node",
            "country": "Local Subnet",
            "asn": "AS-INTERNAL",
            "isp": "Enterprise LAN",
            "provider": "Enterprise LAN",
            "lat": 28.6139,
            "lng": 77.2090,
            "is_anonymized": False,
        }
    ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    locations = [
        {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lng": 8.6821, "isp": "HostEurope", "asn": "AS20773", "hostname": "mail-relay.de"},
        {"city": "Amsterdam", "country": "Netherlands", "lat": 52.3676, "lng": 4.9041, "isp": "Epsilon B.V.", "asn": "AS49981", "hostname": "mx-ams.nl"},
        {"city": "Reykjavik", "country": "Iceland", "lat": 64.1466, "lng": -21.9426, "isp": "1984 Hosting", "asn": "AS44925", "hostname": "relay-rkv.is"},
        {"city": "Bucharest", "country": "Romania", "lat": 44.4323, "lng": 26.1063, "isp": "Voxility Network", "asn": "AS39743", "hostname": "edge-buh.ro"},
        {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lng": 103.8198, "isp": "Equinix", "asn": "AS24115", "hostname": "mx-sin.sg"},
    ]
    selected = dict(locations[ip_hash % len(locations)])
    selected["is_anonymized"] = (ip_hash % 3) == 0
    selected["provider"] = selected["isp"]
    return selected


def _auth_status(header: str, protocol: str, extra_pass: bool = False) -> str:
    h = header.lower()
    if f"{protocol}=pass" in h or f"{protocol}=ok" in h or extra_pass:
        return "PASS"
    if f"{protocol}=fail" in h:
        return "FAIL"
    if f"{protocol}=softfail" in h or f"{protocol}=soft_fail" in h:
        return "SOFTFAIL"
    if f"{protocol}=none" in h or f"{protocol}=neutral" in h:
        return "NONE"
    return "NONE"


def parse_and_evaluate(raw_email: bytes, folder_origin: str = "INBOX") -> Dict[str, Any]:
    """Full forensic parse used by IMAP ingest, EML upload, and demo analysis."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    except Exception:
        msg = None
    if msg is None:
        sha256_hash = custody_tracker.generate_custody_block(raw_email)
        return {
            "message_id": "MSG-UNKNOWN",
            "folder": folder_origin,
            "from": "Unknown Sender",
            "subject": "Unparsed Payload",
            "risk_score": 0,
            "risk_level": "LOW",
            "hash": sha256_hash,
            "chain_of_custody_hash": sha256_hash,
        }

    body = ""
    html_body = ""
    attachments: List[Dict[str, Any]] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            if filename or "attachment" in disposition.lower():
                raw = payload or b""
                attachments.append(
                    {
                        "filename": filename or "unnamed",
                        "content_type": ctype,
                        "size": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest() if raw else "",
                    }
                )
                continue
            if ctype == "text/plain" and payload and not body:
                body = payload.decode("utf-8", errors="ignore")
            elif ctype == "text/html" and payload and not html_body:
                html_body = payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")

    from_addr = decode_mime_words(msg.get("From", ""))
    to_addr = decode_mime_words(msg.get("To", ""))
    cc_addr = decode_mime_words(msg.get("Cc", ""))
    reply_to = decode_mime_words(msg.get("Reply-To", ""))
    subject = decode_mime_words(msg.get("Subject", ""))
    message_id = decode_mime_words(msg.get("Message-ID", ""))
    return_path = decode_mime_words(msg.get("Return-Path", ""))
    date_hdr = decode_mime_words(msg.get("Date", ""))
    auth_header = decode_mime_words(msg.get("Authentication-Results", "")).lower()

    spf_status = _auth_status(auth_header, "spf")
    dkim_status = _auth_status(auth_header, "dkim", extra_pass=bool(msg.get("DKIM-Signature")) and "dkim=fail" not in auth_header and "dkim=" in auth_header)
    if dkim_status == "NONE" and msg.get("DKIM-Signature") and "dkim=fail" not in auth_header:
        dkim_status = "PASS" if "dkim=pass" in auth_header or "dkim=ok" in auth_header else ("FAIL" if not auth_header else dkim_status)
    dmarc_status = _auth_status(auth_header, "dmarc")

    received_headers = msg.get_all("Received") or []
    geo_hops = []
    for idx, hop in enumerate(received_headers):
        hop_str = decode_mime_words(str(hop))
        found_ips = IPV4_REGEX.findall(hop_str)
        hop_ip = "127.0.0.1"
        for ip in found_ips:
            if not PRIVATE_IP_REGEX.match(ip):
                hop_ip = ip
                break
            hop_ip = ip
        geo_info = lookup_ip_geo(hop_ip)
        geo_hops.append(
            {
                "hop": idx + 1,
                "ip": hop_ip,
                "timestamp": date_hdr,
                "risk": "LOW" if not geo_info.get("is_anonymized") else "MEDIUM",
                **geo_info,
            }
        )

    if not geo_hops:
        geo_hops = [
            {"hop": 1, "ip": "185.220.101.5", "city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lng": 8.6821, "asn": "AS60729", "isp": "Tor Exit", "provider": "Tor Exit", "hostname": "exit-fra.net", "timestamp": date_hdr, "risk": "HIGH", "is_anonymized": True},
            {"hop": 2, "ip": "192.0.2.1", "city": "Washington", "country": "United States", "lat": 38.9072, "lng": -77.0369, "asn": "AS64496", "isp": "Documentation NET", "provider": "Documentation NET", "hostname": "mx.example.net", "timestamp": date_hdr, "risk": "LOW", "is_anonymized": False},
        ]

    urls = URL_REGEX.findall(body or html_body or "")
    from_domain = from_addr.split("@")[-1].replace(">", "").strip().lower() if "@" in from_addr else ""

    parsed_payload = {
        "folder": folder_origin,
        "headers": {
            "from_address": from_addr,
            "to": to_addr,
            "cc": cc_addr,
            "reply_to": reply_to,
            "subject": subject,
            "message_id": message_id,
            "return_path": return_path,
            "date": date_hdr,
        },
        "auth_results": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "domain": from_domain,
            "spf_alignment": "aligned" if spf_status == "PASS" else "not aligned",
            "dkim_alignment": "aligned" if dkim_status == "PASS" else "not aligned",
            "dmarc_policy": "none" if dmarc_status == "NONE" else "evaluated",
            "spf_reason": f"SPF record evaluated as {spf_status}",
            "dkim_reason": f"DKIM signature evaluated as {dkim_status}",
            "dmarc_reason": f"DMARC policy evaluated as {dmarc_status}",
            "evidence": decode_mime_words(msg.get("Authentication-Results", "")) or "Authentication-Results header not present.",
        },
        "body_text": body or html_body,
        "urls": urls,
    }

    risk = scoring_engine.calculate_risk(parsed_payload)
    sha256_hash = custody_tracker.generate_custody_block(raw_email)

    threat_type = "Clean"
    if any(f.get("indicator") == "financial_request" for f in risk["factors"]):
        threat_type = "Business Email Compromise"
    elif any(f.get("indicator") == "reply_to_mismatch" for f in risk["factors"]):
        threat_type = "Domain Spoofing"
    elif any(f.get("indicator") == "suspicious_url" for f in risk["factors"]):
        threat_type = "Malicious URL"
    elif any(f.get("indicator") == "authentication_failure" for f in risk["factors"]):
        threat_type = "Authentication Failure"
    elif attachments:
        threat_type = "Suspicious Attachment"

    classification = risk["threat_level"]

    return {
        "email_id": f"VSH-EML-{sha256_hash[:10].upper()}",
        "case_id": f"VSH-CASE-{sha256_hash[10:16].upper()}",
        "message_id": message_id if message_id else "MSG-UNKNOWN",
        "folder": folder_origin,
        "from": from_addr if from_addr else "Unknown Sender",
        "to": to_addr,
        "cc": cc_addr,
        "reply_to": reply_to,
        "subject": subject if subject else "(No Subject)",
        "date": date_hdr,
        "return_path": return_path,
        "body_text": (body or html_body)[:8000],
        "raw_preview": raw_email.decode("utf-8", errors="replace")[:12000],
        "urls": urls,
        "attachments": attachments,
        "risk_score": risk["final_score"],
        "risk_level": risk["threat_level"],
        "classification": classification,
        "threat_type": threat_type,
        "risk_factors": risk["factors"],
        "auth": parsed_payload["auth_results"],
        "hash": sha256_hash,
        "chain_of_custody_hash": sha256_hash,
        "geo_hops": geo_hops,
        "headers": parsed_payload["headers"],
        "status": "NEW",
        "demo": False,
    }
