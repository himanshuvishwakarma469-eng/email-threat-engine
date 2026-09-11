"""Labeled synthetic demonstration data. Not real government records."""

from __future__ import annotations

DEMO_NOTICE = (
    "DEMO DATA — Synthetic records for demonstration only. "
    "This is not real operational or Government of India information. "
    "Department names and emblems are placeholders."
)

DEMO_USERS = [
    {"user_id": "EMP-0001", "name": "A. Sharma", "email": "superadmin@vishwas.local", "department": "Cyber Security Cell (Placeholder)", "role": "SUPER_ADMIN"},
    {"user_id": "EMP-0002", "name": "R. Iyer", "email": "secadmin@vishwas.local", "department": "Security Operations (Placeholder)", "role": "SECURITY_ADMIN"},
    {"user_id": "EMP-0003", "name": "M. Khan", "email": "analyst@vishwas.local", "department": "Email Security (Placeholder)", "role": "SECURITY_ANALYST"},
    {"user_id": "EMP-0004", "name": "S. Patel", "email": "investigator@vishwas.local", "department": "Digital Forensics (Placeholder)", "role": "INVESTIGATOR"},
    {"user_id": "EMP-0005", "name": "P. Nair", "email": "auditor@vishwas.local", "department": "Internal Audit (Placeholder)", "role": "AUDITOR"},
    {"user_id": "EMP-0006", "name": "K. Das", "email": "viewer@vishwas.local", "department": "Programme Office (Placeholder)", "role": "VIEWER"},
]


def _email(**kwargs):
    base = {
        "to": "finance.desk@org.example",
        "cc": "",
        "folder": "INBOX",
        "status": "NEW",
        "demo": True,
        "attachments": [],
        "urls": [],
        "body_text": "This is synthetic demonstration content.",
        "raw_preview": "From: demo\nSubject: demo\n\nSynthetic message.",
        "headers": {},
        "geo_hops": [
            {"hop": 1, "ip": "185.220.101.5", "hostname": "origin-relay.example", "city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lng": 8.6821, "asn": "AS60729", "isp": "Transit Provider A", "provider": "Transit Provider A", "timestamp": "09 Sep 2026 08:12 IST", "risk": "MEDIUM", "is_anonymized": True},
            {"hop": 2, "ip": "203.0.113.10", "hostname": "mx.org.example", "city": "New Delhi", "country": "India", "lat": 28.6139, "lng": 77.2090, "asn": "AS4755", "isp": "Organisation MX", "provider": "Organisation MX", "timestamp": "09 Sep 2026 08:13 IST", "risk": "LOW", "is_anonymized": False},
        ],
    }
    base.update(kwargs)
    if "from_addr" in base:
        base["from"] = base["from_addr"]
    base["headers"] = {
        "from_address": base.get("from"),
        "to": base.get("to"),
        "cc": base.get("cc"),
        "reply_to": base.get("reply_to"),
        "subject": base.get("subject"),
        "message_id": base.get("message_id"),
        "return_path": base.get("return_path"),
        "date": base.get("date"),
    }
    return base


DEMO_EMAILS = [
    _email(
        email_id="VSH-EML-A1B2C3D4E5",
        case_id="VSH-CASE-A1B2C3",
        message_id="<bec-001@spoof.example>",
        date="09 Sep 2026 08:12 IST",
        from_addr="CEO Office <ceo@org-example.com>",
        reply_to="payments@wire-help.example",
        return_path="bounce@wire-help.example",
        subject="Urgent: Update vendor bank account today",
        threat_type="Business Email Compromise",
        risk_score=86,
        risk_level="CRITICAL",
        classification="CRITICAL",
        status="UNDER INVESTIGATION",
        hash="a" * 64,
        urls=["https://wire-help.example/update-account"],
        auth={
            "spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL",
            "domain": "org-example.com",
            "spf_alignment": "not aligned", "dkim_alignment": "not aligned",
            "dmarc_policy": "reject (simulated)",
            "spf_reason": "SPF record evaluated as FAIL",
            "dkim_reason": "DKIM signature evaluated as FAIL",
            "dmarc_reason": "DMARC policy evaluated as FAIL",
            "evidence": "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail",
        },
        risk_factors=[
            {"category": "Header Anomaly", "score": 15, "label": "Reply-To mismatch detected", "evidence": "From domain org-example.com vs Reply-To wire-help.example", "indicator": "reply_to_mismatch"},
            {"category": "Language/BEC", "score": 8, "label": "BEC Indicator (Urgency)", "evidence": "Matched risk pattern: urgent", "indicator": "urgency"},
            {"category": "Language/BEC", "score": 8, "label": "BEC Indicator (Financial)", "evidence": "Matched risk pattern: bank account", "indicator": "financial_request"},
            {"category": "Authentication", "score": 10, "label": "SPF Failure", "evidence": "Sender IP failed SPF policy verification.", "indicator": "authentication_failure"},
        ],
        body_text="Please process the overdue invoice and update the bank account for the wire transfer immediately. This is a confidential request from the executive office.",
    ),
    _email(
        email_id="VSH-EML-B2C3D4E5F6",
        case_id="VSH-CASE-B2C3D4",
        message_id="<phish-002@notify.example>",
        date="08 Sep 2026 16:40 IST",
        from_addr="IT Helpdesk <it-help@org.example>",
        reply_to="it-help@org.example",
        return_path="it-help@org.example",
        subject="Password expiry — verify credentials",
        threat_type="Credential Phishing",
        risk_score=58,
        risk_level="HIGH",
        classification="HIGH",
        status="ASSIGNED",
        hash="b" * 64,
        urls=["https://login-reset.example/session"],
        auth={
            "spf": "SOFTFAIL", "dkim": "NONE", "dmarc": "FAIL",
            "domain": "org.example",
            "spf_alignment": "not aligned", "dkim_alignment": "not aligned",
            "dmarc_policy": "quarantine (simulated)",
            "spf_reason": "SPF record evaluated as SOFTFAIL",
            "dkim_reason": "DKIM signature evaluated as NONE",
            "dmarc_reason": "DMARC policy evaluated as FAIL",
            "evidence": "Authentication-Results: mx; spf=softfail; dkim=none; dmarc=fail",
        },
        risk_factors=[
            {"category": "URL", "score": 5, "label": "URLs present in message body", "evidence": "1 URL(s) extracted", "indicator": "suspicious_url"},
            {"category": "Language/BEC", "score": 8, "label": "Credential request language", "evidence": "Password / verify credentials phrasing", "indicator": "credential_request"},
        ],
        body_text="Your official mailbox password will expire. Verify credentials at the link provided.",
    ),
    _email(
        email_id="VSH-EML-C3D4E5F6A1",
        case_id="VSH-CASE-C3D4E5",
        message_id="<clean-003@org.example>",
        date="08 Sep 2026 11:05 IST",
        from_addr="Records Cell <records@org.example>",
        reply_to="records@org.example",
        return_path="records@org.example",
        subject="Weekly meeting agenda",
        threat_type="Clean",
        risk_score=12,
        risk_level="LOW",
        classification="LOW",
        status="CLOSED",
        hash="c" * 64,
        auth={
            "spf": "PASS", "dkim": "PASS", "dmarc": "PASS",
            "domain": "org.example",
            "spf_alignment": "aligned", "dkim_alignment": "aligned",
            "dmarc_policy": "none",
            "spf_reason": "SPF record evaluated as PASS",
            "dkim_reason": "DKIM signature evaluated as PASS",
            "dmarc_reason": "DMARC policy evaluated as PASS",
            "evidence": "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass",
        },
        risk_factors=[],
        geo_hops=[
            {"hop": 1, "ip": "192.0.2.20", "hostname": "mta.org.example", "city": "Hyderabad", "country": "India", "lat": 17.3850, "lng": 78.4867, "asn": "AS4758", "isp": "Organisation MTA", "provider": "Organisation MTA", "timestamp": "08 Sep 2026 11:04 IST", "risk": "LOW", "is_anonymized": False},
            {"hop": 2, "ip": "192.0.2.21", "hostname": "mx.org.example", "city": "New Delhi", "country": "India", "lat": 28.6139, "lng": 77.2090, "asn": "AS4755", "isp": "Organisation MX", "provider": "Organisation MX", "timestamp": "08 Sep 2026 11:05 IST", "risk": "LOW", "is_anonymized": False},
        ],
        body_text="Please find the weekly coordination meeting agenda attached for internal use.",
        attachments=[{"filename": "agenda.pdf", "content_type": "application/pdf", "size": 84211, "sha256": "d" * 64}],
    ),
    _email(
        email_id="VSH-EML-D4E5F6A1B2",
        case_id="VSH-CASE-D4E5F6",
        message_id="<attach-004@cdn.example>",
        date="07 Sep 2026 19:22 IST",
        from_addr="Vendor Support <support@vend0r.example>",
        reply_to="support@vend0r.example",
        return_path="bounce@vend0r.example",
        subject="Revised contract scan",
        threat_type="Suspicious Attachment",
        risk_score=41,
        risk_level="MEDIUM",
        classification="MEDIUM",
        status="NEW",
        hash="e" * 64,
        auth={
            "spf": "NONE", "dkim": "FAIL", "dmarc": "NONE",
            "domain": "vend0r.example",
            "spf_alignment": "not aligned", "dkim_alignment": "not aligned",
            "dmarc_policy": "none",
            "spf_reason": "SPF record evaluated as NONE",
            "dkim_reason": "DKIM signature evaluated as FAIL",
            "dmarc_reason": "DMARC policy evaluated as NONE",
            "evidence": "Authentication-Results: mx; dkim=fail",
        },
        risk_factors=[
            {"category": "Authentication", "score": 10, "label": "DKIM Invalid", "evidence": "Cryptographic signature verification failed.", "indicator": "authentication_failure"},
        ],
        attachments=[{"filename": "contract.iso", "content_type": "application/octet-stream", "size": 1200444, "sha256": "f" * 64}],
    ),
]

DEMO_INCIDENTS = [
    {
        "incident_id": "VSH-INC-2026-00001",
        "incident_type": "Business Email Compromise",
        "severity": "CRITICAL",
        "date": "09 Sep 2026",
        "source": "Threat Inbox",
        "affected_account": "finance.desk@org.example",
        "assigned_officer": "S. Patel",
        "status": "Under Investigation",
        "description": "Synthetic BEC attempt requesting vendor bank-account change. Demonstration record only.",
        "notes": [{"by": "M. Khan", "time": "09 Sep 2026 08:40 IST", "text": "Escalated to investigator. Demo note."}],
        "related_email": "VSH-EML-A1B2C3D4E5",
        "demo": True,
    },
    {
        "incident_id": "VSH-INC-2026-00002",
        "incident_type": "Credential Phishing",
        "severity": "HIGH",
        "date": "08 Sep 2026",
        "source": "Email Forensics",
        "affected_account": "it-help@org.example",
        "assigned_officer": "M. Khan",
        "status": "Assigned",
        "description": "Synthetic credential harvesting message. Demonstration record only.",
        "notes": [],
        "related_email": "VSH-EML-B2C3D4E5F6",
        "demo": True,
    },
    {
        "incident_id": "VSH-INC-2026-00003",
        "incident_type": "Suspicious Attachment",
        "severity": "MEDIUM",
        "date": "07 Sep 2026",
        "source": "Mailbox Alert",
        "affected_account": "procurement@org.example",
        "assigned_officer": "R. Iyer",
        "status": "Contained",
        "description": "Synthetic attachment flagged for review. Demonstration record only.",
        "notes": [],
        "related_email": "VSH-EML-D4E5F6A1B2",
        "demo": True,
    },
]

DEMO_IOCS = [
    {"ioc": "wire-help.example", "type": "Domain", "first_seen": "01 Sep 2026", "last_seen": "09 Sep 2026", "risk": "CRITICAL", "confidence": "High", "source": "Internal detection (demo)", "occurrences": 4, "related_incidents": ["VSH-INC-2026-00001"], "demo": True},
    {"ioc": "185.220.101.5", "type": "IP", "first_seen": "20 Aug 2026", "last_seen": "09 Sep 2026", "risk": "HIGH", "confidence": "Medium", "source": "Header hop analysis (demo)", "occurrences": 7, "related_incidents": ["VSH-INC-2026-00001"], "demo": True},
    {"ioc": "https://login-reset.example/session", "type": "URL", "first_seen": "08 Sep 2026", "last_seen": "08 Sep 2026", "risk": "HIGH", "confidence": "High", "source": "Body extraction (demo)", "occurrences": 1, "related_incidents": ["VSH-INC-2026-00002"], "demo": True},
    {"ioc": "f" * 64, "type": "Hash", "first_seen": "07 Sep 2026", "last_seen": "07 Sep 2026", "risk": "MEDIUM", "confidence": "Medium", "source": "Attachment hashing (demo)", "occurrences": 1, "related_incidents": ["VSH-INC-2026-00003"], "demo": True},
    {"ioc": "payments@wire-help.example", "type": "Email", "first_seen": "09 Sep 2026", "last_seen": "09 Sep 2026", "risk": "CRITICAL", "confidence": "High", "source": "Reply-To field (demo)", "occurrences": 2, "related_incidents": ["VSH-INC-2026-00001"], "demo": True},
]

DEMO_AUDIT = [
    {"datetime": "09 Sep 2026 00:02 IST", "user": "analyst@vishwas.local", "action": "LOGIN", "module": "Authentication", "object": "session", "ip": "10.0.0.12", "result": "SUCCESS", "demo": True},
    {"datetime": "09 Sep 2026 00:05 IST", "user": "analyst@vishwas.local", "action": "EMAIL_VIEW", "module": "Email Forensics", "object": "VSH-EML-A1B2C3D4E5", "ip": "10.0.0.12", "result": "SUCCESS", "demo": True},
    {"datetime": "09 Sep 2026 00:08 IST", "user": "investigator@vishwas.local", "action": "CASE_CREATED", "module": "Incidents", "object": "VSH-INC-2026-00001", "ip": "10.0.0.18", "result": "SUCCESS", "demo": True},
    {"datetime": "08 Sep 2026 18:11 IST", "user": "auditor@vishwas.local", "action": "REPORT_GENERATED", "module": "Reports", "object": "VSH-RPT-2026-0012", "ip": "10.0.0.21", "result": "SUCCESS", "demo": True},
    {"datetime": "08 Sep 2026 17:40 IST", "user": "secadmin@vishwas.local", "action": "IOC_ADDED", "module": "Threat Intelligence", "object": "wire-help.example", "ip": "10.0.0.8", "result": "SUCCESS", "demo": True},
    {"datetime": "08 Sep 2026 09:00 IST", "user": "superadmin@vishwas.local", "action": "USER_UPDATED", "module": "Administration", "object": "EMP-0006", "ip": "10.0.0.2", "result": "SUCCESS", "demo": True},
    {"datetime": "07 Sep 2026 14:22 IST", "user": "superadmin@vishwas.local", "action": "SETTINGS_CHANGED", "module": "Administration", "object": "session_timeout", "ip": "10.0.0.2", "result": "SUCCESS", "demo": True},
]
