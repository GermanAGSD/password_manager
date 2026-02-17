from jose import JWTError, jwt
from datetime import datetime, timedelta
from app.schemas import TokenData
from fastapi import Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
# import database
from sqlalchemy.orm import Session
# import models
from app.database import get_db
from app.models import Users
import secrets
import hashlib
from passlib.context import CryptContext
oauth_scheme = OAuth2PasswordBearer(tokenUrl='/login')


SECRET_KEY = "my_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 720
REFRESH_TOKEN_EXPIRE_DAYS = 7
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
refresh_tokens = {}

def create_token(data: dict):
    if not isinstance(data, dict):
        raise ValueError("Expected 'data' to be a dictionary")

    to_encode = data.copy()  # копируем данные для кодирования
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({'exp': expire})  # добавляем время истечения срока действия
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # создаём JWT токен
    return encode_jwt



def verify_access_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Используем 'sub' для идентификатора пользователя
        user_id = payload.get("sub")  # 'sub' это идентификатор пользователя

        if user_id is None:
            raise credentials_exception

        token_data = TokenData(id=user_id)
        return token_data
    except JWTError as e:
        print("❌ JWTError:", e)
        raise credentials_exception



def get_current_user(token: str = Depends(oauth_scheme), db: Session = Depends(get_db)):
    cred_excp = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Получаем данные токена
    token_data = verify_access_token(token, cred_excp)

    # Вместо поиска по users.id ищем по email или username
    user = db.query(Users).filter(Users.email == token_data.id).first()  # Ищем по email (или используйте username)

    if not user:
        raise cred_excp

    return user

def create_refresh_token():
    token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return token, token_hash, expires