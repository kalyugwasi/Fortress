from passlib.context import CryptContext

pwd_context = CryptContext(schemes=['bcrypt_sha256','bcrypt'],deprecated='auto')

def hash_password(plain_password:str):
    return pwd_context.hash(plain_password)

def verify_password(plain_password:str,hashed_passwprd:str):
    return pwd_context.verify(plain_password,hashed_passwprd)