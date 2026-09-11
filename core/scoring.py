"""Explainable BEC risk scoring (preserved from the original prototype)."""

from __future__ import annotations

import re
from typing import Any, Dict, List


class ExplainableScoringEngine:
    """Transparent risk scoring across authentication, headers, language, and mailbox flags."""

    BEC_KEYWORDS = {
        "urgency": [
            r"\burgent\b",
            r"\bimmediate action required\b",
            r"\bwire transfer\b",
            r"\bswift\b",
            r"\boverdue invoice\b",
        ],
        "financial": [
            r"\bbank account\b",
            r"\brouting number\b",
            r"\bupdate payment\b",
            r"\bpayroll\b",
            r"\bgift card\b",
        ],
        "authority": [
            r"\bceo\b",
            r"\bexecutive\b",
            r"\bdirector\b",
            r"\bconfidential request\b",
        ],
    }

    def calculate_risk(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        factors: List[Dict[str, Any]] = []
        scores = {"auth": 0, "header": 0, "language": 0, "domain": 0}

        auth = parsed_email.get("auth_results", {})
        if auth.get("spf") == "FAIL":
            scores["auth"] += 10
            factors.append(
                {
                    "category": "Authentication",
                    "score": 10,
                    "label": "SPF Failure",
                    "evidence": "Sender IP failed SPF policy verification.",
                    "indicator": "authentication_failure",
                }
            )
        if auth.get("dkim") == "FAIL":
            scores["auth"] += 10
            factors.append(
                {
                    "category": "Authentication",
                    "score": 10,
                    "label": "DKIM Invalid",
                    "evidence": "Cryptographic signature verification failed.",
                    "indicator": "authentication_failure",
                }
            )
        if auth.get("dmarc") == "FAIL":
            scores["auth"] += 10
            factors.append(
                {
                    "category": "Authentication",
                    "score": 10,
                    "label": "DMARC Alignment Failure",
                    "evidence": "From header domain does not align with SPF/DKIM.",
                    "indicator": "authentication_failure",
                }
            )

        headers = parsed_email.get("headers", {})
        from_addr = headers.get("from_address", "")
        reply_to = headers.get("reply_to", "")

        if reply_to and from_addr and (reply_to.lower() != from_addr.lower()):
            from_domain = from_addr.split("@")[-1].replace(">", "").strip() if "@" in from_addr else ""
            reply_domain = reply_to.split("@")[-1].replace(">", "").strip() if "@" in reply_to else ""
            if from_domain and reply_domain and (from_domain != reply_domain):
                scores["header"] += 15
                factors.append(
                    {
                        "category": "Header Anomaly",
                        "score": 15,
                        "label": "Reply-To mismatch detected",
                        "evidence": f"From: '@{from_domain}' vs Reply-To: '@{reply_domain}'",
                        "indicator": "reply_to_mismatch",
                    }
                )

        body = parsed_email.get("body_text", "")
        subject = headers.get("subject", "")
        content = f"{subject} {body}"
        for cat, patterns in self.BEC_KEYWORDS.items():
            for pat in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    scores["language"] += 8
                    indicator = "financial_request" if cat == "financial" else (
                        "credential_request" if "password" in content.lower() or "credential" in content.lower() else "urgency"
                    )
                    factors.append(
                        {
                            "category": "Language/BEC",
                            "score": 8,
                            "label": f"BEC Indicator ({cat.capitalize()})",
                            "evidence": f"Matched risk pattern: '{pat}'",
                            "indicator": indicator,
                        }
                    )
                    break

        folder = parsed_email.get("folder", "INBOX")
        if "spam" in folder.lower() or "junk" in folder.lower():
            scores["header"] += 20
            factors.append(
                {
                    "category": "Mailbox Flag",
                    "score": 20,
                    "label": "Spam Folder Origin",
                    "evidence": f"Ingested from folder: {folder}",
                    "indicator": "header_manipulation",
                }
            )

        urls = parsed_email.get("urls") or []
        if urls:
            scores["domain"] += 5
            factors.append(
                {
                    "category": "URL",
                    "score": 5,
                    "label": "URLs present in message body",
                    "evidence": f"{len(urls)} URL(s) extracted for intelligence review.",
                    "indicator": "suspicious_url",
                }
            )

        raw_total = sum(scores.values())
        final_score = min(100, raw_total) if raw_total > 0 else 10

        if final_score >= 80:
            level = "CRITICAL"
        elif final_score >= 50:
            level = "HIGH"
        elif final_score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "final_score": final_score,
            "threat_level": level,
            "factors": factors,
        }
