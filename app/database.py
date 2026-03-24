from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

DATABASE_URL = settings.DATABASE_URL

if DATABASE_URL.startswith("postgresql+asyncpg"):
    sync_database_url = DATABASE_URL.replace("+asyncpg", "+psycopg2")
else:
    sync_database_url = DATABASE_URL

engine = create_engine(sync_database_url, echo=True, future=True)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()