"""
PII Detection + Redaction
--------------------------
MVP scope: email + phone number (as required by spec).
Tradeoff: regex-based detection has false positives/negatives
(e.g. international phone formats). Documented as a limitation.
"""
import re

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Matches common phone formats: +91 9876543210, (123) 456-7890, 123-456-7890, etc.
PHONE_PATTERN = re.compile(
    r"(\+?\d{1,3}[\s-]?)?(\(?\d{3,4}\)?[\s-]?)?\d{3}[\s-]?\d{4}\b|\+?\d{10,13}\b"
)


def detect_and_redact_pii(text: str):
    """
    Returns (score_contribution, reasons_list, redacted_text)
    """
    if not text:
        return 0, [], text

    reasons = []
    score = 0
    redacted = text

    emails = EMAIL_PATTERN.findall(text)
    if emails:
        redacted = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", redacted)
        reasons.append({
            "tag": "pii",
            "evidence": f"found {len(emails)} email address(es)"
        })
        score = max(score, 30)

    phones = PHONE_PATTERN.findall(redacted)
    phone_matches = PHONE_PATTERN.findall(redacted)
    if phone_matches:
        # avoid re-matching already redacted text
        new_redacted = PHONE_PATTERN.sub("[REDACTED_PHONE]", redacted)
        if new_redacted != redacted:
            redacted = new_redacted
            reasons.append({
                "tag": "pii",
                "evidence": "found phone number pattern"
            })
            score = max(score, 25)

    return score, reasons, redacted
