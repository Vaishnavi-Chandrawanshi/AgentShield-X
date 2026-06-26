import time
import sys
from sqlalchemy import create_engine
from backend.app.core.config import settings

def wait_for_db():
    print("Checking database readiness...")
    db_url = settings.DATABASE_URL
    # For testing/dev SQLite, it is always available immediately
    if db_url.startswith("sqlite"):
        print("SQLite in use. Ready immediately.")
        return
        
    retries = 30
    while retries > 0:
        try:
            engine = create_engine(db_url)
            with engine.connect() as conn:
                print("Database is online and responding!")
                return
        except Exception as e:
            print(f"Database not ready yet ({e}). Waiting 1 second...")
            time.sleep(2)
            retries -= 1
    print("Database connection timed out. Exiting.")
    sys.exit(1)

if __name__ == "__main__":
    wait_for_db()
