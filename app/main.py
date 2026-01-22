import uvicorn
from fastapi.security import OAuth2PasswordBearer
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, Form, HTTPException, Response
from app import schemas, models
from app import database
from sqlalchemy.orm import Session
import secrets
import hashlib
from passlib.context import CryptContext
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
app = FastAPI()
# LDAP settings
LDAP_SERVER = 'ldap://172.30.30.3'
LDAP_BIND_DN = 'CN=my-service,CN=Users,DC=bull,DC=local'
LDAP_PASSWORD = ''
# JWT settings
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')
SECRET_KEY = "my_secret_key"  # Make sure this is kept safe and not exposed
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 1
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
refresh_tokens = {}
def create_access_token(user_id: str):
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_DAYS),
        "iat": datetime.utcnow(),
        "type": "access"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token():
    token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return token, token_hash, expires

def verify_access_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
        token_data = schemas.TokenData(id=user_id)
    except JWTError:
        raise credentials_exception
    return token_data

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    token = verify_access_token(token, credentials_exception)
    user = db.query(models.User).filter(models.User.id == token.id).first()
    return user

@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(
        response: Response,
        # user_credentials: OAuth2PasswordRequestForm = Depends(),
        username: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(database.get_db),


    ):

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, LDAP_BIND_DN, LDAP_PASSWORD, auto_bind=True)

    # Поиск пользователя по sAMAccountName
    search_filter = f"(sAMAccountName={username})"
    conn.search('DC=bull,DC=local', search_filter, SUBTREE, attributes=['cn', 'mail', 'memberOf'])

    if len(conn.entries) == 0:
        raise HTTPException(status_code=404, detail="User not found")

    user_dn = conn.entries[0].entry_dn
    user_conn = Connection(server, user_dn, password, authentication=SIMPLE)

    if not user_conn.bind():
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Проверяем наличие атрибута 'memberOf'
    if 'memberOf' in conn.entries[0]:
        groups = conn.entries[0].memberOf.values if hasattr(conn.entries[0].memberOf, 'values') else []
    else:
        groups = []  # Если атрибута нет, возвращаем пустой список или можно задать значение по умолчанию

    # Создание токена
    access_token = create_access_token(data={"user_id": user_dn})
    refresh_token, refresh_hash, expires = create_refresh_token()

    refresh_tokens[refresh_hash] = {
        "user_id": user_dn["id"],
        "expires": expires,
        "revoked": False
    }
    # print(groups)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "groups": groups,
    }

@app.post("/auth/refresh")
def refresh_token(
        response: Response,
        refresh_token: str = Cookie(None)
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    token_data = refresh_tokens.get(token_hash)

    if not token_data or token_data["revoked"]:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if token_data["expires"] < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh expired")

    # revoke old
    token_data["revoked"] = True

    # issue new
    new_access = create_access_token(token_data["user_id"])
    new_refresh, new_hash, new_expires = create_refresh_token()

    refresh_tokens[new_hash] = {
        "user_id": token_data["user_id"],
        "expires": new_expires,
        "revoked": False
    }

    response.set_cookie(
        key="refresh_token",
        value=new_refresh,
        httponly=True,
        secure=True,
        samesite="strict"
    )

    return {"access_token": new_access}


if __name__ == "__main__":
    uvicorn.run(app, host="192.168.3.2", port=8000)