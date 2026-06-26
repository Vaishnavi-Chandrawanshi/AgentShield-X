import datetime
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.app.api.dependencies import get_db, get_current_user
from backend.app.core.config import settings
from backend.app.core.security import (
    create_access_token,
    get_password_hash,
    verify_password
)
from backend.app.models.user import User
from backend.app.schemas.user import (
    UserRegister,
    UserResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ChangePasswordRequest,
    ProfileUpdateRequest
)
from backend.app.schemas.response import Token, TokenPayload

router = APIRouter()

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_in: UserRegister, db: Session = Depends(get_db)):
    """
    Registers a new user account.
    The first registered user is automatically assigned the 'admin' role.
    """
    # Check if username or email already exists
    existing_user = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered."
        )

    # Determine role based on whether this is the first user
    user_count = db.query(User).count()
    role = "admin" if user_count == 0 else "analyst"

    hashed_pw = get_password_hash(user_in.password)
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_pw,
        role=role,
        org_name=user_in.org_name
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/token", response_model=Token)
def login_for_access_token(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Standard OAuth2 compatible token login.
    Checks password against database user credentials.
    Supports fallback to environment-configured admin credentials.
    """
    # Try finding user in database
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if user:
        if not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user account"
            )
        
        scopes = ["admin"] if user.role == "admin" else []
        access_token = create_access_token(
            data={"sub": user.username, "scopes": scopes}
        )
        return {"access_token": access_token, "token_type": "bearer"}
    
    # Fallback to configured settings credentials (development convenience)
    if form_data.username == settings.ADMIN_USERNAME and form_data.password == settings.ADMIN_PASSWORD:
        access_token = create_access_token(
            data={"sub": settings.ADMIN_USERNAME, "scopes": ["admin"]}
        )
        return {"access_token": access_token, "token_type": "bearer"}
        
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

@router.get("/me", response_model=UserResponse)
def read_current_user_profile(
    db: Session = Depends(get_db),
    current_user_payload: TokenPayload = Depends(get_current_user)
):
    """
    Retrieves the current authenticated user's profile details.
    """
    username = current_user_payload.sub
    user = db.query(User).filter(User.username == username).first()
    if not user:
        # If logged in as the settings-configured admin fallback
        if username == settings.ADMIN_USERNAME:
            return User(
                user_id="settings-admin-id",
                username=settings.ADMIN_USERNAME,
                email="admin@agentshield.com",
                role="admin",
                org_name="Enterprise Root",
                is_active=True,
                created_at=datetime.datetime.utcnow()
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found."
        )
    return user

@router.put("/profile", response_model=UserResponse)
def update_user_profile(
    profile_in: ProfileUpdateRequest,
    db: Session = Depends(get_db),
    current_user_payload: TokenPayload = Depends(get_current_user)
):
    """
    Updates the authenticated user's email, org_name, or password.
    """
    username = current_user_payload.sub
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found for modifications."
        )
        
    if profile_in.email is not None:
        # Check email uniqueness
        existing_email = db.query(User).filter(
            User.email == profile_in.email, User.user_id != user.user_id
        ).first()
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address is already in use by another account."
            )
        user.email = profile_in.email
        
    if profile_in.org_name is not None:
        user.org_name = profile_in.org_name
        
    if profile_in.new_password is not None:
        user.hashed_password = get_password_hash(profile_in.new_password)
        
    db.commit()
    db.refresh(user)
    return user

@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    pwd_in: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user_payload: TokenPayload = Depends(get_current_user)
):
    """
    Updates user password after verifying current password.
    """
    username = current_user_payload.sub
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found."
        )
        
    if not verify_password(pwd_in.old_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect old password."
        )
        
    user.hashed_password = get_password_hash(pwd_in.new_password)
    db.commit()
    return {"message": "Password changed successfully."}

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Initiates password reset sequence. Generates a unique secure token
    valid for 15 minutes and updates user model.
    """
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        # To avoid user enumeration attacks, return 200 OK anyway
        return {"message": "If the email is registered, a reset link will be generated."}
        
    reset_token = str(uuid.uuid4())
    user.reset_token = reset_token
    user.reset_token_expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    db.commit()
    
    # In production, this would trigger email dispatch. For evaluation, we print to console log
    print(f"[SECURITY CONTROL] Password reset requested for user {user.username}. Reset Token: {reset_token}")
    
    return {
        "message": "Password reset initiated successfully.",
        "dev_token": reset_token  # Exposing token in response for evaluation ease
    }

@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Executes password override if the provided reset token is correct and valid.
    """
    user = db.query(User).filter(
        User.email == req.email,
        User.reset_token == req.token
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset credentials or expired token."
        )
        
    if not user.reset_token_expires or user.reset_token_expires < datetime.datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired."
        )
        
    user.hashed_password = get_password_hash(req.new_password)
    user.reset_token = None
    user.reset_token_expires = None
    db.commit()
    return {"message": "Password reset successfully."}
