from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import create_access_token
from backend.app.schemas.response import Token
from backend.app.api.endpoints import gateway, approval, audit, auth

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits direct streamlit integrations
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include endpoint routers
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["User Authentication"])
app.include_router(gateway.router, prefix=f"{settings.API_V1_STR}/gateway", tags=["Gateway Interceptor"])
app.include_router(approval.router, prefix=f"{settings.API_V1_STR}/approval", tags=["Admin Approval Queue"])
app.include_router(audit.router, prefix=f"{settings.API_V1_STR}/audit", tags=["Compliance & Audits"])

@app.on_event("startup")
def seed_admin_user():
    """
    Seeds the default administrative user from configured settings on startup
    if the users database is currently empty.
    """
    from backend.app.core.database import SessionLocal
    from backend.app.models.user import User
    from backend.app.core.security import get_password_hash
    
    db = SessionLocal()
    try:
        user_count = db.query(User).count()
        if user_count == 0:
            hashed_pw = get_password_hash(settings.ADMIN_PASSWORD)
            default_admin = User(
                username=settings.ADMIN_USERNAME,
                email="admin@agentshield.com",
                hashed_password=hashed_pw,
                role="admin",
                org_name="Enterprise Root"
            )
            db.add(default_admin)
            db.commit()
            print(f"[STARTUP SEED] Default administrator '{settings.ADMIN_USERNAME}' seeded successfully.")
    except Exception as e:
        print(f"[STARTUP SEED] Warning: Seeding failed ({e})")
    finally:
        db.close()

@app.get("/health", status_code=status.HTTP_200_OK, tags=["System Health"])
def health_check():
    """
    Returns system health status.
    """
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME
    }
