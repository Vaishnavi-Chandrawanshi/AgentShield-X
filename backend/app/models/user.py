import uuid
import datetime
from sqlalchemy import Column, String, Boolean, DateTime
from backend.app.core.database import Base

class User(Base):
    """
    User model for authentication, role-based access control,
    and enterprise multi-tenancy mappings.
    """
    __tablename__ = "users"

    user_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst", nullable=False)  # admin, analyst, viewer
    org_name = Column(String, default="Enterprise Org", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    reset_token = Column(String, nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
