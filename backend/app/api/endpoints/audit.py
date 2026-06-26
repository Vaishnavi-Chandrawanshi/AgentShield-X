import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.api.dependencies import get_db, get_current_user
from backend.app.schemas.request import ExploitSignatureCreate
from backend.app.schemas.response import AuditLogResponse, ExploitSignatureResponse, TokenPayload
from backend.app.models.audit import AuditLog, ExploitSignature
from backend.app.core.security import decrypt_text

router = APIRouter()

@router.get("/logs", response_model=List[AuditLogResponse], status_code=status.HTTP_200_OK)
def search_audit_logs(
    session_id: Optional[str] = None,
    policy_action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: TokenPayload = Depends(get_current_user)
):
    """
    Queries historical security logs. Supports session ID and policy action filtering.
    Automatically decrypts raw user queries on-the-fly.
    """
    query = db.query(AuditLog)
    if session_id:
        query = query.filter(AuditLog.session_id == session_id)
    if policy_action:
        query = query.filter(AuditLog.policy_action == policy_action)
        
    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    # Decrypt encrypted raw input for response presentation
    for log in logs:
        try:
            log.raw_input = decrypt_text(log.raw_input)
        except Exception:
            log.raw_input = "[Decryption Failed]"
            
    return logs

@router.get("/logs/{log_id}", response_model=AuditLogResponse, status_code=status.HTTP_200_OK)
def get_audit_log(
    log_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: TokenPayload = Depends(get_current_user)
):
    """
    Retrieves detailed transaction metadata for a single request.
    Restricted to authorized users. Decrypts raw inputs on-the-fly.
    """
    log = db.query(AuditLog).filter(AuditLog.log_id == log_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requested audit transaction log does not exist."
        )
    try:
        log.raw_input = decrypt_text(log.raw_input)
    except Exception:
        log.raw_input = "[Decryption Failed]"
        
    return log

@router.post("/signatures", response_model=ExploitSignatureResponse, status_code=status.HTTP_201_CREATED)
def create_exploit_signature(
    request: ExploitSignatureCreate,
    db: Session = Depends(get_db),
    current_user: TokenPayload = Depends(get_current_user)
):
    """
    Registers a new exploit signature with vector embedding representation.
    Used by prompt injection similarity scanners.
    """
    sig = ExploitSignature(
        exploit_pattern=request.exploit_pattern,
        embedding=request.embedding
    )
    db.add(sig)
    db.commit()
    db.refresh(sig)
    return sig

@router.get("/signatures", response_model=List[ExploitSignatureResponse], status_code=status.HTTP_200_OK)
def list_exploit_signatures(
    db: Session = Depends(get_db),
    current_user: TokenPayload = Depends(get_current_user)
):
    """
    Returns list of all registered exploit signatures.
    """
    sigs = db.query(ExploitSignature).order_by(ExploitSignature.added_at.desc()).all()
    return sigs
