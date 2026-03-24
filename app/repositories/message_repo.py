from datetime import datetime, UTC, timezone
from sqlalchemy.orm import Session
from app.models import Message

def save_message(db:Session,recipient_id,message_number,sealed_blob,expires_at=None):
    message = Message(
        recipient_id=recipient_id,
        sealed_blob=sealed_blob,
        message_number=message_number,
        expires_at = expires_at
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message

def get_message_for_user(db:Session,user_id:int):
    return (
        db.query(Message)
        .filter(Message.recipient_id==user_id)
        .order_by(Message.created_at.asc())
        .all()
    )

def delete_message(db:Session,message_id:int):
    message = db.query(Message).filter(Message.id == message_id).first()
    if message:
        db.delete(message)
        db.commit()
    return message

def get_expired_messages(db):
    now = datetime.now(timezone.utc).replace(tzinfo=None)  # strip tz for SQLite comparison
    return db.query(Message).filter(
        Message.expires_at != None,
        Message.expires_at < now
    ).all()