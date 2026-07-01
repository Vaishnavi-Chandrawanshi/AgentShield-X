from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
import uuid
import datetime

class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: uuid.UUID
    log_id: uuid.UUID
    timestamp: datetime.datetime
    agent_source: str
    trigger_type: str
    severity_level: str
    details: Optional[Dict[str, Any]] = None

class HumanApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    approval_id: uuid.UUID
    log_id: uuid.UUID
    status: str
    reviewer_id: Optional[str] = None
    review_notes: Optional[str] = None
    created_at: datetime.datetime
    reviewed_at: Optional[datetime.datetime] = None

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    log_id: uuid.UUID
    session_id: str
    timestamp: datetime.datetime
    raw_input: str  # Decrypted on response construction
    sanitized_input: Optional[str] = None
    overall_risk_score: float
    policy_action: str
    events: List[SecurityEventResponse] = []
    approvals: List[HumanApprovalResponse] = []

class GatewayResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    log_id: uuid.UUID
    session_id: str
    sanitized_prompt: Optional[str] = None
    overall_risk_score: float
    policy_action: str
    message: str

    # Make event structure flexible
    events_triggered: List[Dict[str, Any]] = []
    all_detector_details: List[Dict[str, Any]] = []

class ExploitSignatureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    signature_id: uuid.UUID
    exploit_pattern: str
    added_at: datetime.datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    scopes: List[str] = []
