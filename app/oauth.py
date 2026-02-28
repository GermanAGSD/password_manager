
from jose import JWTError, jwt
from datetime import datetime, timedelta
from app.schemas import TokenData
from fastapi import Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Users
import secrets
import hashlib
from passlib.context import CryptContext

oauth_scheme = OAuth2PasswordBearer(tokenUrl='/login')

SECRET_KEY = "my_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
refresh_tokens = {}  # key = sha256(refresh), value = {user_id, expires, revoked}

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({'exp': expire})
    to_encode.update({'sub': str(data['user_id'])})  # sub всегда строка

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception

        # Можно хранить как int, если TokenData позволяет
        token_data = TokenData(id=str(user_id))
        return token_data

    except JWTError as e:
        print("❌ JWTError:", e)
        raise credentials_exception


def get_current_user(
        token: str = Depends(oauth_scheme),
        db: Session = Depends(get_db)
):
    cred_excp = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token_data = verify_access_token(token, cred_excp)

    # лучше привести к int явно
    try:
        user_id = int(token_data.id)
    except (TypeError, ValueError):
        raise cred_excp

    user = db.query(Users).filter(Users.id == user_id).first()
    if not user:
        raise cred_excp

    return user


def create_refresh_token():
    token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return token, token_hash, expires