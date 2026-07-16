"""
RAG Injection Heuristic Detector
----------------------------------
Detects malicious instructions hidden inside retrieved context documents
(a common attack: poisoning a knowledge base / search result with
instructions meant to hijack the model).
"""
import re

RAG_INJECTION_PATTERNS = [
    r"system\s*:",
    r"override (the )?(policy|instructions|rules)",
    r"ignore (the )?(guidelines|instructions|rules)",
    r"new instructions\s*:",
    r"admin\s*:",
    r"you must now",
    r"disregard (the )?(context|document) above",
]

COMPILED = [re.compile(p, re.IGNORECASE) for p in RAG_INJECTION_PATTERNS]


def detect_rag_injection(doc_id: str, text: str):
    """
    Returns (score_contribution, reasons_list)
    """
    if not text:
        return 0, []

    reasons = []
    score = 0

    for pattern in COMPILED:
        match = pattern.search(text)
        if match:
            reasons.append({
                "tag": "rag_injection",
                "evidence": f"doc '{doc_id}': matched phrase: {match.group(0)}"
            })
            score = max(score, 40)

    return score, reasons
