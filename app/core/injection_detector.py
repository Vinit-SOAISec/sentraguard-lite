"""
Prompt Injection / Jailbreak Heuristic Detector
------------------------------------------------
Simple deterministic pattern matching (no LLM calls, fully offline).
Tradeoff: regex/keyword matching is fast + explainable but can be
bypassed by paraphrasing or obfuscation. Documented in Design Notes.
"""
import re

# Each pattern has a tag + weight (contributes to risk score)
INJECTION_PATTERNS = [
    (r"ignore (all )?previous instructions", 40),
    (r"ignore (the )?above", 35),
    (r"disregard (all )?(previous|prior) (instructions|prompts)", 40),
    (r"reveal (the )?system prompt", 45),
    (r"show me your (system )?prompt", 40),
    (r"act as (dan|do anything now)", 45),
    (r"you are now (dan|jailbroken|unrestricted)", 45),
    (r"pretend you have no (restrictions|rules|guidelines)", 40),
    (r"bypass (your )?(safety|content) (filters?|guidelines?)", 45),
    (r"developer mode", 30),
    (r"jailbreak", 35),
    (r"forget (everything|all)( you (know|were told))?", 30),
]

COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), tag, weight) for p, tag, weight in
                      [(pat, pat, w) for pat, w in INJECTION_PATTERNS]]


def detect_prompt_injection(text: str):
    """
    Returns (score_contribution, list_of_reason_dicts)
    """
    if not text:
        return 0, []

    reasons = []
    max_score = 0

    for pattern, label, weight in COMPILED_PATTERNS:
        match = pattern.search(text)
        if match:
            reasons.append({
                "tag": "prompt_injection",
                "evidence": f"matched phrase: {match.group(0)}"
            })
            max_score = max(max_score, weight)

    return max_score, reasons
