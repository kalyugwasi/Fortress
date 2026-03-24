import asyncio
from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from contextlib import asynccontextmanager
from slowapi.errors import RateLimitExceeded
from app.database import Base,engine,SessionLocal
import app.models,app.schemas,app.crypto,app.services
from app.routers import auth,keys,messages,ws,safety
from app.services import ensure_bucket_exists,purge_expired_messages
from app.middleware import limiter,SecurityHeadersMiddleware

async def expired_message_cleanup():
    print("Background cleanup worker started.")
    while True:
        await asyncio.sleep(60)
        db = SessionLocal()
        try:
            # This calls message_repo.delete_expired_messages(db) via the service
            deleted_count = purge_expired_messages(db)
            if deleted_count > 0:
                print(f"Purged {deleted_count} expired messages.")
        except Exception as e:
            db.rollback()  # CRITICAL: Prevent PendingRollbackError for next cycles
            print(f"Cleanup error: {e}")
        finally:
            db.close()
@asynccontextmanager
async def lifespan(app: FastAPI):
    #Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    ensure_bucket_exists()
    cleanup_task = asyncio.create_task(expired_message_cleanup())
    yield
    cleanup_task.cancel()

app = FastAPI(title='Fortrx', lifespan=lifespan)
app.include_router(keys.router)
app.include_router(auth.router)
app.include_router(messages.router)
app.include_router(ws.router)
app.include_router(safety.router)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded,_rate_limit_exceeded_handler)
app.add_middleware(SecurityHeadersMiddleware)

@app.get('/')
async def health():
    return {"status":"Fortrx is running"}


# docker run -d --name localstack -p 4566:4566 localstack/localstac
# docker run -d --name minio -p 4566:4566 quay.io/minio/minio server /data --address ":4566"
# docker run -p 6379:6379 redis:alpine