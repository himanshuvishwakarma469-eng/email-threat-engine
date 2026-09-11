"""SHA-256 chain-of-custody helpers."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class ChainOfCustodyTracker:
    """Generates SHA-256 hashes to guarantee data integrity."""

    def generate_custody_block(self, raw_bytes: bytes) -> str:
        return hashlib.sha256(raw_bytes).hexdigest()

    def verify(self, raw_bytes: bytes, expected_hash: str) -> bool:
        return hashlib.sha256(raw_bytes).hexdigest().lower() == (expected_hash or "").lower()

    def record(
        self,
        evidence_id: str,
        label: str,
        sha256: str,
        collected_by: str,
        processed_by: str = "VISHWAS Forensic Engine",
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "evidence_id": evidence_id,
            "file_or_email": label,
            "sha256": sha256,
            "created": now,
            "collected_by": collected_by,
            "processed_by": processed_by,
            "verification_status": "RECORDED",
            "demo": False,
        }
