import uvicorn
from fastapi.security import OAuth2PasswordBearer
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, Form, HTTPException
from app import schemas, models
from app import database
from sqlalchemy.orm import Session
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
ACCESS_TOKEN_EXPIRE_DAYS = 90


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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
        # user_credentials: OAuth2PasswordRequestForm = Depends(),
        username: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(database.get_db)):
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
    # print(groups)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "groups": groups,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="192.168.3.2", port=8000)