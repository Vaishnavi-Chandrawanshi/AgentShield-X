from pydantic import BaseModel, Field, field_validator
from typing import Optional, List

class GatewayPromptRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=255, description="The unique session identifier for the browser or client")
    prompt: Optional[str] = Field(None, description="The raw prompt query input to be sanitized and verified")
    file_bytes_base64: Optional[str] = Field(None, description="Optional Base64 encoded file attachment bytes")
    file_name: Optional[str] = Field(None, description="Optional filename of the file attachment")

class ExploitSignatureCreate(BaseModel):
    exploit_pattern: str = Field(..., min_length=1, description="The textual representation of a known prompt injection signature")
    embedding: List[float] = Field(..., description="The 1536-dimensional embedding vector representing this signature")

    @field_validator("embedding")
    @classmethod
    def validate_embedding_dimensions(cls, v: List[float]) -> List[float]:
        if len(v) != 1536:
            raise ValueError("Vector embedding must contain exactly 1536 float dimensions.")
        return v

class ApprovalActionRequest(BaseModel):
    status: str = Field(..., description="The human approval verdict: APPROVED or REJECTED")
    reviewer_id: str = Field(..., min_length=1, max_length=100, description="Identifies the administrator performing the action")
    review_notes: Optional[str] = Field(None, description="Optional text justification or auditing notes for the decision")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        val = v.upper()
        if val not in ("APPROVED", "REJECTED"):
            raise ValueError("Status must be either APPROVED or REJECTED")
        return val
