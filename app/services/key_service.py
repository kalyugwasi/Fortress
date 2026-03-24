from sqlalchemy.orm import Session
from fastapi import HTTPException,status
from app.models import User
from app.repositories import get_bundle_by_user_id,create_bundle,update_bundle,pop_one_time_prekey
from app.schemas import KeyBundleUpload,KeyBundleResponse
import json

def _deserialize_bundle_otpks(bundle):
    """Ensure bundle.one_time_prekeys is always a Python list, never a raw JSON string."""
    if isinstance(bundle.one_time_prekeys, str):
        keys = json.loads(bundle.one_time_prekeys)
    else:
        keys = bundle.one_time_prekeys or []
    # normalize back onto the instance so callers see a list
    bundle.one_time_prekeys = keys
    return bundle

def upload_key_bundle(db:Session,user_id:int,payload:KeyBundleUpload):
    # SQLite Text column cannot store a Python list — serialize to JSON string
    one_time_prekeys_json = json.dumps(payload.one_time_prekeys)
    bundle = get_bundle_by_user_id(db,user_id)
    if bundle:
        bundle = update_bundle(db,bundle,identity_key=payload.identity_key,signed_prekey=payload.signed_prekey,signed_prekey_signature=payload.signed_prekey_signature,prekey_id=payload.prekey_id,one_time_prekeys=one_time_prekeys_json)
    else:
        bundle = create_bundle(db,user_id=user_id,identity_key=payload.identity_key,signed_prekey=payload.signed_prekey,signed_prekey_signature=payload.signed_prekey_signature,prekey_id=payload.prekey_id,one_time_prekeys=one_time_prekeys_json)

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.identity_public_key = payload.identity_key
        db.commit()
    return bundle

def fetch_key_bundle(db:Session,user_id:int):
    bundle = get_bundle_by_user_id(db,user_id)
    if not bundle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="Key Bundle not found")
    # Deserialize stored JSON string back to list before repo operates on it
    _deserialize_bundle_otpks(bundle)
    otp = pop_one_time_prekey(db,bundle)
    return KeyBundleResponse(
        user_id=bundle.user_id,
        identity_key=bundle.identity_key,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_signature=bundle.signed_prekey_signature,
        prekey_id=bundle.prekey_id,
        one_time_prekey=otp
    )