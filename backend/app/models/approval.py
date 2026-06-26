import datetime
import uuid
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.core.database import Base

class HumanApproval(Base):
    """
    HumanApproval tracks requests forwarded to the manual verification queue.
    If the Risk Scoring Agent flag evaluates as HUMAN_REVIEW, the transaction is held
    until a reviewer marks it as APPROVED or REJECTED.
    """
    __tablename__ = "human_approvals"

    approval_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        primary_key=True, 
        default=uuid.uuid4, 
        comment="Unique identifier for the human review block task"
    )
    log_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        ForeignKey("audit_logs.log_id", ondelete="CASCADE"), 
        index=True,  # Critical index added to speed up parent transaction joins
        nullable=False, 
        comment="Links back to the target AuditLog transaction being reviewed"
    )
    status: Mapped[str] = mapped_column(
        String(20), 
        nullable=False, 
        default="PENDING", 
        comment="State of approval: PENDING, APPROVED, or REJECTED"
    )
    reviewer_id: Mapped[Optional[str]] = mapped_column(
        String(100), 
        nullable=True, 
        comment="Identifier for the administrator executing the review"
    )
    review_notes: Mapped[Optional[str]] = mapped_column(
        Text, 
        nullable=True, 
        comment="Notes supplied by the reviewer justifying the action decision"
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, 
        default=datetime.datetime.utcnow, 
        comment="Creation timestamp of the human approval ticket"
    )
    reviewed_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime, 
        nullable=True, 
        comment="Completion timestamp representing when the review decision was saved"
    )

    # Relationships
    audit_log: Mapped["AuditLog"] = relationship("AuditLog", back_populates="approvals")
