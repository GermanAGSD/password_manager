import uvicorn
from fastapi.security import OAuth2PasswordBearer
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, Form, HTTPException, Response, Cookie, APIRouter
from app import schemas, models
from app import database
from sqlalchemy.orm import Session
from app.models import Users
import secrets
import hashlib
from passlib.context import CryptContext

from app.settings import settings
from app.utils import hash_password, verify_password
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from app.oauth import create_token, verify_access_token,get_current_user, create_refresh_token
router = APIRouter(
    # prefix="/posts",
    # tags=['Posts']
)

# LDAP settings
LDAP_SERVER = 'ldap://172.30.30.3'
LDAP_BIND_DN = 'CN=my-service,CN=Users,DC=bull,DC=local'
LDAP_PASSWORD = settings.domain_password
refresh_tokens = {}

@router.post("/login", response_model=schemas.Token)
async def login_for_access_token(
        response: Response,
        username: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(database.get_db),
):
    # Подключение к LDAP серверу и проверка пользователя
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, LDAP_BIND_DN, LDAP_PASSWORD, auto_bind=True)

    search_filter = f"(sAMAccountName={username})"
    conn.search('DC=bull,DC=local', search_filter, SUBTREE, attributes=['cn', 'mail', 'memberOf'])

    if len(conn.entries) == 0:
        raise HTTPException(status_code=404, detail="User not found")

    user_dn = conn.entries[0].entry_dn
    user_conn = Connection(server, user_dn, password, authentication=SIMPLE)

    if not user_conn.bind():
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Получение групп
    groups = conn.entries[0].memberOf.values if hasattr(conn.entries[0].memberOf, 'values') else []

    # Создание токенов
    access_token = create_token({"sub": username})  # Передаем username или user_id
    refresh_token, refresh_hash, expires = create_refresh_token()

    # Используем 'Users' вместо 'User'
    user = db.query(models.Users).filter(models.Users.email == username).first()

    if not user:
        # Если пользователя нет в базе, создаем нового
        user = models.Users(name=username, email=username, domainpass=password)
        db.add(user)
        db.commit()

    # Добавляем группы пользователя в таблицу связи
    for group_dn in groups:
        group = db.query(models.Group).filter(models.Group.name == group_dn).first()
        if not group:
            # Если группы нет, создаем её
            group = models.Group(name=group_dn, created_by=user.id)
            db.add(group)
            db.commit()

        # Создаем ассоциацию пользователя с группой
        user_group_association = models.UserGroupAssociation(user_id=user.id, group_id=group.id)
        db.add(user_group_association)

    db.commit()

    # Сохранение refresh_token в куки
    refresh_tokens[refresh_hash] = {
        "user_id": user_dn,  # user_dn — строка DN
        "expires": expires,
        "revoked": False,
        "groups": groups
    }

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



@router.post("/auth/refresh")
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
    new_access = create_token(token_data["user_id"])
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

@router.post("/passwords", response_model=schemas.Password)
async def create_password(
        password_data: schemas.PasswordCreate,
        db: Session = Depends(database.get_db),
        current_user: Users = Depends(get_current_user)  # Получаем текущего пользователя
):
    # Проверяем, существует ли пользователь
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Создаем новый объект PasswordManager
    new_password = models.PasswordManager(
        password=password_data.password,
        login_password=password_data.login_password,
        description=password_data.description,
        about_password=password_data.about_password,
        created_by=current_user.id  # Указываем пользователя, который создает пароль
    )

    # Добавляем в базу данных
    db.add(new_password)
    db.commit()
    db.refresh(new_password)

    return new_password

@router.get("/passwords/{user_id}", response_model=list[schemas.Password], status_code=200)
async def get_passwords_by_user(user_id: int, db: Session = Depends(database.get_db), current_user: Users = Depends(get_current_user)):
    # Если текущий пользователь суперпользователь, он может получить пароли других пользователей
    if current_user.issuperuser:
        passwords = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == user_id).all()

        if not passwords:
            raise HTTPException(status_code=404, detail="No passwords found for this user")
        return passwords

    # Если текущий пользователь не суперпользователь, он может только получить свои пароли
    if current_user.id == user_id:
        passwords = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == current_user.id).all()

        if not passwords:
            raise HTTPException(status_code=404, detail="No passwords found for this user")
        return passwords

    # Если пользователь не суперпользователь и не запрашивает свои пароли, возвращаем ошибку доступа
    raise HTTPException(status_code=403, detail="Not authorized to access other user's passwords")

@router.get("/user/{user_id}/visible_groups", response_model=list[schemas.Group])
async def get_visible_groups_by_user(user_id: int, db: Session = Depends(database.get_db), current_user: Users = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access other user's groups")

    # Получаем все группы пользователя с visible = True
    groups = db.query(models.Group).join(models.UserGroupAssociation).filter(
        models.UserGroupAssociation.user_id == user_id,
        models.Group.visible == True
    ).all()

    if not groups:
        raise HTTPException(status_code=404, detail="No visible groups found for this user")

    return groups

@router.put("/groups/{group_id}/visibility", response_model=schemas.Group)
async def update_group_visibility(
        group_id: int,
        visibility: bool,
        db: Session = Depends(database.get_db),
        current_user: Users = Depends(get_current_user)
):
    # Находим группу по group_id
    group = db.query(models.Group).filter(models.Group.id == group_id).first()

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Проверяем, что текущий пользователь является создателем группы или суперпользователем
    if group.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to modify this group")

    # Обновляем поле visible
    group.visible = visibility
    db.commit()
    db.refresh(group)  # Обновляем объект группы, чтобы вернуть актуальные данные

    return group
