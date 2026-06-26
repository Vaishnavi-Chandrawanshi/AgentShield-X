import datetime
import uuid
from typing import List, Optional
from sqlalchemy import String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.core.database import Base, SafeVector

class AuditLog(Base):
    """
    AuditLog holds the record of a client transaction proxy request.
    It tracks the input payload sanitization state, raw logs (encrypted), 
    and policy evaluation decisions.
    """
    __tablename__ = "audit_logs"

    log_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        primary_key=True, 
        default=uuid.uuid4, 
        comment="Unique identifier for the audit transaction log"
    )
    session_id: Mapped[str] = mapped_column(
        String(255), 
        index=True, 
        nullable=False, 
        comment="Tracks the specific client browser session or API call grouping"
    )
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, 
        default=datetime.datetime.utcnow, 
        index=True, 
        comment="The execution timestamp of the security transaction"
    )
    raw_input: Mapped[str] = mapped_column(
        String, 
        nullable=False, 
        comment="The original, unsanitized user query (stored encrypted via AES-GCM)"
    )
    sanitized_input: Mapped[Optional[str]] = mapped_column(
        String, 
        nullable=True, 
        comment="The parsed and clean user query after redacting PII or removing injections"
    )
    overall_risk_score: Mapped[float] = mapped_column(
        Float, 
        nullable=False, 
        default=0.0, 
        comment="Synthesized threat metric (0.0 = Safe, 1.0 = Critical)"
    )
    policy_action: Mapped[str] = mapped_column(
        String(50), 
        nullable=False, 
        comment="Decision outcome: ALLOW, BLOCK, REDACTED, or HUMAN_REVIEW"
    )
    
    # Relationships
    events: Mapped[List["SecurityEvent"]] = relationship(
        "SecurityEvent", 
        back_populates="audit_log", 
        cascade="all, delete-orphan"
    )
    approvals: Mapped[List["HumanApproval"]] = relationship(
        "HumanApproval", 
        back_populates="audit_log", 
        cascade="all, delete-orphan"
    )


class SecurityEvent(Base):
    """
    SecurityEvent tracks specific alerts triggered during payload screening.
    Every event is mapped to a parent AuditLog transaction.
    """
    __tablename__ = "security_events"

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        primary_key=True, 
        default=uuid.uuid4, 
        comment="Unique identifier for the security warning event"
    )
    log_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        ForeignKey("audit_logs.log_id", ondelete="CASCADE"), 
        index=True,  # Critical index added to speed up parent transaction joins
        nullable=False, 
        comment="Foreign key linking back to the primary parent AuditLog record"
    )
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, 
        default=datetime.datetime.utcnow, 
        comment="Timestamp of event trigger"
    )
    agent_source: Mapped[str] = mapped_column(
        String(50), 
        nullable=False, 
        comment="Name of the agent that triggered the warning: INJECTION, PII, FILE, ACTION_GUARD"
    )
    trigger_type: Mapped[str] = mapped_column(
        String(255), 
        nullable=False, 
        comment="Specific threat classification (e.g., Jailbreak Attempt, API Leak, SSN Masked)"
    )
    severity_level: Mapped[str] = mapped_column(
        String(20), 
        nullable=False, 
        comment="Level of severity: LOW, MEDIUM, HIGH, CRITICAL"
    )
    details: Mapped[Optional[dict]] = mapped_column(
        JSON, 
        nullable=True, 
        comment="Contextual telemetry metadata detailing target parameters or matching lines"
    )

    # Relationships
    audit_log: Mapped["AuditLog"] = relationship("AuditLog", back_populates="events")


class ExploitSignature(Base):
    """
    ExploitSignature holds vector embeddings of historically flagged prompt injections.
    The Injection Agent uses these for fast cosine similarity scanning.
    """
    __tablename__ = "exploit_signatures"

    signature_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        primary_key=True, 
        default=uuid.uuid4, 
        comment="Unique identifier for the signature exploit record"
    )
    exploit_pattern: Mapped[str] = mapped_column(
        String, 
        nullable=False, 
        comment="The text fragment representing the jailbreak template"
    )
    embedding: Mapped[List[float]] = mapped_column(
        SafeVector(1536), 
        nullable=False, 
        comment="Float vector representation (1536 dimensions) for similarity search"
    )
    added_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, 
        default=datetime.datetime.utcnow, 
        comment="Timestamp representing when this signature pattern was indexed"
    )
