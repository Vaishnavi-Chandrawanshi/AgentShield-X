import datetime
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.api.dependencies import get_db, require_admin
from backend.app.schemas.request import ApprovalActionRequest
from backend.app.schemas.response import HumanApprovalResponse, TokenPayload
from backend.app.models.approval import HumanApproval
from backend.app.models.audit import AuditLog

router = APIRouter()

@router.get("/pending", response_model=List[HumanApprovalResponse], status_code=status.HTTP_200_OK)
def get_pending_approvals(
    db: Session = Depends(get_db),
    admin: TokenPayload = Depends(require_admin)
):
    """
    Retrieves all pending human verification tickets from the queue.
    Restricted to administrators.
    """
    tickets = db.query(HumanApproval).filter(HumanApproval.status == "PENDING").order_by(HumanApproval.created_at.asc()).all()
    return tickets

@router.post("/{approval_id}/action", response_model=HumanApprovalResponse, status_code=status.HTTP_200_OK)
def review_approval_ticket(
    approval_id: uuid.UUID,
    action: ApprovalActionRequest,
    db: Session = Depends(get_db),
    admin: TokenPayload = Depends(require_admin)
):
    """
    Submits a review verdict (APPROVED or REJECTED) for a held transaction.
    Updates the approval ticket and syncs the parent audit log outcome.
    Restricted to administrators.
    """
    ticket = db.query(HumanApproval).filter(HumanApproval.approval_id == approval_id).first()
    if not ticket:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Human approval ticket not found."
        )
    
    if ticket.status != "PENDING":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"This ticket has already been processed with verdict: {ticket.status}."
        )
        
    # Update verification ticket
    ticket.status = action.status
    ticket.reviewer_id = action.reviewer_id
    ticket.review_notes = action.review_notes
    ticket.reviewed_at = datetime.datetime.utcnow()
    
    # Update parent audit log policy action to apply final verdict
    parent_log = db.query(AuditLog).filter(AuditLog.log_id == ticket.log_id).first()
    if parent_log:
        if action.status == "APPROVED":
            parent_log.policy_action = "ALLOW"
        else:
            parent_log.policy_action = "BLOCK"
            
    db.commit()
    db.refresh(ticket)
    return ticket
