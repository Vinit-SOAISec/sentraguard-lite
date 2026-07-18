"""
Scoring + Decision Engine
--------------------------
Combines detector outputs into a single risk_score (0-100) and
decision (allow/block/transform) based on configured thresholds.
"""
from app.core.injection_detector import detect_prompt_injection
from app.core.pii_detector import detect_and_redact_pii
from app.core.rag_injection_detector import detect_rag_injection

BLOCK_THRESHOLD = 80
TRANSFORM_THRESHOLD = 40

# Bonus applied when 2+ distinct threat categories fire together.
# A single strong signal is scored on its own merit (max), but a prompt
# that combines multiple attack vectors (e.g. injection + PII + RAG) is
# genuinely more dangerous than any one signal alone, so it gets bumped.
COMPOUND_THREAT_BONUS = 20


def analyze_request(prompt: str, context_docs: list):
    """
    context_docs: list of {"id": str, "text": str}
    Returns a dict matching the /analyze response schema.
    """
    reasons = []
    scores = []

    # 1. Prompt injection check on the main prompt
    inj_score, inj_reasons = detect_prompt_injection(prompt)
    scores.append(inj_score)
    reasons.extend(inj_reasons)

    # 2. PII check + redaction on the main prompt
    pii_score, pii_reasons, sanitized_prompt = detect_and_redact_pii(prompt)
    scores.append(pii_score)
    reasons.extend(pii_reasons)

    # 3. RAG injection check on each context doc + PII redaction on docs too
    sanitized_context_docs = []
    for doc in context_docs:
        doc_id = doc.get("id", "unknown")
        doc_text = doc.get("text", "")

        rag_score, rag_reasons = detect_rag_injection(doc_id, doc_text)
        scores.append(rag_score)
        reasons.extend(rag_reasons)

        _, _, sanitized_doc_text = detect_and_redact_pii(doc_text)
        sanitized_context_docs.append({"id": doc_id, "text": sanitized_doc_text})

    base_score = max(scores) if scores else 0

    # Collect unique tags that actually fired
    risk_tags = sorted(set(r["tag"] for r in reasons))

    # Compound threat bonus: if 2+ distinct categories fired, this prompt
    # is attacking on multiple fronts at once, which is more dangerous
    # than any single signal in isolation.
    if len(risk_tags) >= 2:
        risk_score = min(base_score + COMPOUND_THREAT_BONUS, 100)
    else:
        risk_score = base_score

    if risk_score >= BLOCK_THRESHOLD:
        decision = "block"
    elif risk_score >= TRANSFORM_THRESHOLD:
        decision = "transform"
    else:
        decision = "allow"

    return {
        "decision": decision,
        "risk_score": risk_score,
        "risk_tags": risk_tags,
        "sanitized_prompt": sanitized_prompt,
        "sanitized_context_docs": sanitized_context_docs,
        "reasons": reasons,
    }