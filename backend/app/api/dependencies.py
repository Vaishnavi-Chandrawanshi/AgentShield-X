from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.security import verify_access_token
from backend.app.schemas.response import TokenPayload

# OAuth2 / JWT Authorization Header parser
reusable_oauth2 = HTTPBearer(auto_error=True)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(reusable_oauth2)) -> TokenPayload:
    """
    FastAPI dependency that extracts and validates the JWT authorization token.
    Raises 401 Unauthorized if the token is invalid or expired.
    """
    token = credentials.credentials
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid security token or token expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenPayload(
        sub=payload.get("sub"),
        scopes=payload.get("scopes", [])
    )

def require_admin(current_user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
    """
    FastAPI dependency that restricts route access to administrative tokens containing the 'admin' scope.
    """
    if "admin" not in current_user.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to access this resource."
        )
    return current_user
