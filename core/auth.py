"""Session cookies, RBAC, MFA pending state, and password hashing."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any, Dict, Optional

SESSION_TTL_SECONDS = int(os.getenv("VISHWAS_SESSION_TTL", str(8 * 60 * 60)))
SECRET = os.getenv("VISHWAS_SECRET_KEY", "vishwas-dev-change-me")

ROLES = [
    "SUPER_ADMIN",
    "SECURITY_ADMIN",
    "SECURITY_ANALYST",
    "INVESTIGATOR",
    "AUDITOR",
    "VIEWER",
]

ROLE_MODULES = {
    "SUPER_ADMIN": {"*"},
    "SECURITY_ADMIN": {
        "dashboard", "email", "threat_intel", "incidents", "reports", "audit",
        "admin", "health", "search",
    },
    "SECURITY_ANALYST": {
        "dashboard", "email", "threat_intel", "incidents", "reports", "search", "health",
    },
    "INVESTIGATOR": {
        "dashboard", "email", "threat_intel", "incidents", "audit", "reports", "search",
    },
    "AUDITOR": {"dashboard", "reports", "audit", "search"},
    "VIEWER": {"dashboard", "reports", "search"},
}


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
    return hmac.compare_digest(check, digest)


def sign_token(payload: str, ttl: int = SESSION_TTL_SECONDS) -> str:
    exp = int(time.time()) + ttl
    body = f"{payload}|{exp}"
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}|{sig}"


def verify_token(token: str) -> Optional[str]:
    try:
        payload, exp_s, sig = token.rsplit("|", 2)
        exp = int(exp_s)
    except ValueError:
        return None
    if exp < time.time():
        return None
    body = f"{payload}|{exp_s}"
    expected = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    return payload


def role_allowed(role: str, module: str) -> bool:
    allowed = ROLE_MODULES.get(role, set())
    return "*" in allowed or module in allowed


def user_public(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "user_id": user["user_id"],
        "name": user["name"],
        "email": user["email"],
        "department": user["department"],
        "role": user["role"],
        "status": user["status"],
        "last_login": user.get("last_login"),
        "mfa_enabled": user.get("mfa_enabled", True),
        "mfa_methods": user.get("mfa_methods", ["OTP", "AUTHENTICATOR", "HARDWARE_KEY"]),
    }
