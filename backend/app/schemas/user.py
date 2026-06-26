from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional
import datetime
import re

def validate_email_str(email: str) -> str:
    # Basic email regex validation
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(regex, email):
        raise ValueError("Invalid email format.")
    return email

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    password: str = Field(..., min_length=6, max_length=100)
    org_name: str = Field("Enterprise Org", max_length=100)

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_str(v)

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    username: str
    email: str
    role: str
    org_name: str
    is_active: bool
    created_at: datetime.datetime

class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_str(v)

class ResetPasswordRequest(BaseModel):
    email: str
    token: str
    new_password: str = Field(..., min_length=6, max_length=100)

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_str(v)

class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=6, max_length=100)

class ProfileUpdateRequest(BaseModel):
    email: Optional[str] = None
    org_name: Optional[str] = Field(None, max_length=100)
    new_password: Optional[str] = Field(None, min_length=6, max_length=100)

    @field_validator("email")
    @classmethod
    def check_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_email_str(v)
        return v
