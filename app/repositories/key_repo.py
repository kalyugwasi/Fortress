from sqlalchemy.orm import Session
import json
from app.models import KeyBundle
def get_bundle_by_user_id(db:Session,user_id:int):
    return db.query(KeyBundle).filter(KeyBundle.user_id==user_id).first()

def create_bundle(
    db:Session,
    user_id:int,
    identity_key:str,
    signed_prekey:str,
    signed_prekey_signature:str,
    prekey_id:int,
    one_time_prekeys:list[str]
    ):
    bundle = KeyBundle(
        user_id=user_id,
        identity_key=identity_key,
        signed_prekey=signed_prekey,
        signed_prekey_signature=signed_prekey_signature,
        prekey_id=prekey_id,
        one_time_prekeys=one_time_prekeys
    )
    db.add(bundle)
    db.commit()
    db.refresh(bundle)
    return bundle

def update_bundle(db:Session,bundle:KeyBundle,**fields):
    for key,value in fields.items():
        if key == "one_time_prekeys" and isinstance(value,list):
            value = json.dumps(value)
        setattr(bundle,key,value)
    db.commit()
    db.refresh(bundle)
    return bundle

def pop_one_time_prekey(db:Session,bundle:KeyBundle):
    keys = json.loads(bundle.one_time_prekeys or "[]")
    if not keys:
        return None
    popped = keys.pop()
    bundle.one_time_prekeys = json.dumps(keys)
    db.commit()
    return popped
