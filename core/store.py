"""In-memory portal store for demo/prototype sessions, incidents, audit, and IOCs."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.auth import hash_password, user_public
from core.demo import DEMO_AUDIT, DEMO_EMAILS, DEMO_INCIDENTS, DEMO_IOCS, DEMO_USERS, DEMO_NOTICE


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class PortalStore:
    def __init__(self) -> None:
        self.demo_mode = True
        self.users: List[Dict[str, Any]] = []
        self.emails: List[Dict[str, Any]] = []
        self.incidents: List[Dict[str, Any]] = []
        self.iocs: List[Dict[str, Any]] = []
        self.audit: List[Dict[str, Any]] = []
        self.notifications: List[Dict[str, Any]] = []
        self.custody: List[Dict[str, Any]] = []
        self.raw_evidence: Dict[str, bytes] = {}
        self.otp_by_user: Dict[str, str] = {}
        self.captcha: Dict[str, str] = {}
        self.mailbox: Dict[str, Any] = {"connected": False, "host": None, "account": None}
        self.metrics = {
            "emails_minute": 12,
            "avg_processing_ms": 84,
            "error_rate": 0.2,
            "queue": 3,
            "cpu": 18,
            "memory": 41,
        }
        self.load_demo()

    def load_demo(self) -> None:
        self.demo_mode = True
        self.users = []
        for u in DEMO_USERS:
            rec = dict(u)
            rec["password_hash"] = hash_password("Demo@123")
            rec["status"] = "ACTIVE"
            rec["last_login"] = None
            rec["mfa_enabled"] = True
            rec["mfa_methods"] = ["OTP", "AUTHENTICATOR", "HARDWARE_KEY"]
            self.users.append(rec)
        self.emails = [dict(e) for e in DEMO_EMAILS]
        self.incidents = [dict(i) for i in DEMO_INCIDENTS]
        self.iocs = [dict(x) for x in DEMO_IOCS]
        self.audit = [dict(a) for a in DEMO_AUDIT]
        self.notifications = [
            {"id": "N-1", "type": "Security Alert", "title": "High-risk BEC detected", "time": _now(), "read": False, "demo": True},
            {"id": "N-2", "type": "Incident Update", "title": "Incident VSH-INC-2026-00001 assigned", "time": _now(), "read": False, "demo": True},
            {"id": "N-3", "type": "Report Ready", "title": "Daily Security Report generated", "time": _now(), "read": True, "demo": True},
            {"id": "N-4", "type": "System Alert", "title": "Mailbox synchronisation completed", "time": _now(), "read": True, "demo": True},
        ]
        self.custody = []
        for e in self.emails:
            self.custody.append(
                {
                    "evidence_id": e["email_id"],
                    "file_or_email": e["subject"],
                    "sha256": e["hash"],
                    "created": e.get("date") or _now(),
                    "collected_by": "DEMO INGEST",
                    "processed_by": "VISHWAS Forensic Engine",
                    "verification_status": "RECORDED",
                    "demo": True,
                }
            )
        self.log("SYSTEM", "DEMO_LOADED", "Administration", "demo", "127.0.0.1", "SUCCESS")

    def reset_demo(self) -> None:
        self.mailbox = {"connected": False, "host": None, "account": None}
        self.load_demo()

    def find_user(self, username: str) -> Optional[Dict[str, Any]]:
        key = username.strip().lower()
        for u in self.users:
            if u["email"].lower() == key or u["user_id"].lower() == key:
                return u
        return None

    def log(self, user: str, action: str, module: str, obj: str, ip: str, result: str) -> None:
        self.audit.insert(
            0,
            {
                "datetime": _now(),
                "user": user,
                "action": action,
                "module": module,
                "object": obj,
                "ip": ip,
                "result": result,
                "demo": self.demo_mode,
            },
        )

    def issue_captcha(self) -> Dict[str, str]:
        a, b = secrets.randbelow(8) + 2, secrets.randbelow(8) + 2
        token = secrets.token_urlsafe(12)
        self.captcha[token] = str(a + b)
        return {"token": token, "challenge": f"{a} + {b} = ?"}

    def check_captcha(self, token: str, answer: str) -> bool:
        expected = self.captcha.pop(token, None)
        return expected is not None and expected == str(answer).strip()

    def issue_otp(self, user_id: str) -> str:
        code = "123456" if self.demo_mode else f"{secrets.randbelow(1000000):06d}"
        self.otp_by_user[user_id] = code
        return code

    def verify_otp(self, user_id: str, code: str) -> bool:
        expected = self.otp_by_user.get(user_id)
        return expected is not None and expected == code.strip()

    def stats(self) -> Dict[str, Any]:
        emails = self.emails
        threats = [e for e in emails if e.get("risk_level") in ("HIGH", "CRITICAL", "MEDIUM")]
        return {
            "total_emails": len(emails),
            "threats_detected": len(threats),
            "high_risk": len([e for e in emails if e.get("risk_level") in ("HIGH", "CRITICAL")]),
            "bec_incidents": len([e for e in emails if "BEC" in str(e.get("threat_type", "")).upper() or e.get("threat_type") == "Business Email Compromise"]),
            "suspicious_domains": len({(e.get("from") or "").split("@")[-1] for e in emails if e.get("risk_score", 0) >= 25}),
            "malicious_urls": sum(len(e.get("urls") or []) for e in emails if e.get("risk_score", 0) >= 50),
            "ioc_matches": len(self.iocs),
            "open_investigations": len([i for i in self.incidents if i.get("status") not in ("Resolved", "Closed", "False Positive")]),
            "clean": len([e for e in emails if e.get("risk_level") == "LOW"]),
            "suspicious": len([e for e in emails if e.get("risk_level") == "MEDIUM"]),
            "high": len([e for e in emails if e.get("risk_level") == "HIGH"]),
            "critical": len([e for e in emails if e.get("risk_level") == "CRITICAL"]),
            "demo": self.demo_mode,
            "notice": DEMO_NOTICE if self.demo_mode else None,
        }

    def add_email(self, analysis: Dict[str, Any], raw: Optional[bytes] = None) -> Dict[str, Any]:
        analysis["demo"] = False
        self.emails.insert(0, analysis)
        if raw is not None:
            self.raw_evidence[analysis.get("hash", "")] = raw
        self.custody.insert(
            0,
            {
                "evidence_id": analysis.get("email_id"),
                "file_or_email": analysis.get("subject"),
                "sha256": analysis.get("hash"),
                "created": _now(),
                "collected_by": "LIVE INGEST",
                "processed_by": "VISHWAS Forensic Engine",
                "verification_status": "RECORDED",
                "demo": False,
            },
        )
        if analysis.get("risk_score", 0) >= 50:
            self.notifications.insert(
                0,
                {
                    "id": f"N-{secrets.token_hex(3)}",
                    "type": "Security Alert",
                    "title": f"Threat detected: {analysis.get('subject')}",
                    "time": _now(),
                    "read": False,
                    "demo": False,
                },
            )
        return analysis


store = PortalStore()
