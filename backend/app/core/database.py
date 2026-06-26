import json
from sqlalchemy import create_engine, TypeDecorator, Text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from backend.app.core.config import settings

# Determine database type from URL setting
IS_SQLITE = settings.DATABASE_URL.startswith("sqlite")

# Configure connection pools. SQLite needs single-thread settings disabled for FastAPI compatibility
if IS_SQLITE:
    engine = create_engine(
        settings.DATABASE_URL, 
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        settings.DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=1800
    )

# Sessionmaker for transaction boundaries
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Modern SQLAlchemy 2.0 declarative base class
class Base(DeclarativeBase):
    pass

class SQLiteVector(TypeDecorator):
    """
    Fallback vector column wrapper for SQLite databases.
    Stores numerical embeddings as JSON-serialized text representation.
    """
    impl = Text
    cache_ok = True

    def __init__(self, dim):
        self.dim = dim
        super().__init__()

    def process_bind_param(self, value, dialect):
        if value is not None:
            if isinstance(value, list):
                return json.dumps(value)
            return value
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            try:
                return json.loads(value)
            except Exception:
                return value
        return None

def SafeVector(dim: int):
    """
    Returns a pgvector Vector type when running on PostgreSQL,
    or falls back to custom JSON-serialized SQLiteVector type on SQLite.
    """
    if IS_SQLITE:
        return SQLiteVector(dim)
    else:
        from pgvector.sqlalchemy import Vector
        return Vector(dim)

def get_db():
    """
    FastAPI dependency that yields database session boundaries
    and closes the connection upon completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
