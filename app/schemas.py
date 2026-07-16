from pydantic import BaseModel, Field
from typing import List, Optional


class ContextDoc(BaseModel):
    id: str
    text: str


class Metadata(BaseModel):
    app_id: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="The incoming prompt to analyze")
    context_docs: List[ContextDoc] = Field(default_factory=list)
    metadata: Optional[Metadata] = None


class Reason(BaseModel):
    tag: str
    evidence: str


class AnalyzeResponse(BaseModel):
    decision: str
    risk_score: int
    risk_tags: List[str]
    sanitized_prompt: str
    sanitized_context_docs: List[ContextDoc]
    reasons: List[Reason]


class PolicyResponse(BaseModel):
    version: str
    detectors: List[str]
    thresholds: dict
