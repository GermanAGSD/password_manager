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
from typing import List
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
        login_data: schemas.LoginRequest,  # Используем модель LoginRequest
        db: Session = Depends(database.get_db),
):
    # Подключение к LDAP серверу и проверка пользователя
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, LDAP_BIND_DN, LDAP_PASSWORD, auto_bind=True)

    search_filter = f"(sAMAccountName={login_data.username})"
    conn.search('DC=bull,DC=local', search_filter, SUBTREE, attributes=['cn', 'mail', 'memberOf'])

    if len(conn.entries) == 0:
        raise HTTPException(status_code=404, detail="User not found")

    user_dn = conn.entries[0].entry_dn
    user_conn = Connection(server, user_dn, login_data.password, authentication=SIMPLE)

    if not user_conn.bind():
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Получение групп
    groups = conn.entries[0].memberOf.values if hasattr(conn.entries[0].memberOf, 'values') else []

    user = db.query(models.Users).filter(models.Users.email == login_data.username).first()

    if not user:
        # Если пользователя нет в базе, создаем нового
        user = models.Users(name=login_data.username, email=login_data.username, domainpass=login_data.password)
        db.add(user)
        db.commit()

    # Генерация токенов с использованием user.id
    # access_token = create_token({"sub": user.id})  # Здесь передаем user.id, а не username
    # access_token = create_token({"sub": user.id})  # Убедитесь, что sub - строка
    # access_token = create_token(data={"user_id": user.id})
    access_token = create_token(data={"user_id": user.id})

    refresh_token, refresh_hash, expires = create_refresh_token()

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

# # Получение групп из LDAP (список DN)
# ldap_group_dns = set(conn.entries[0].memberOf.values if hasattr(conn.entries[0].memberOf, 'values') else [])
#
# # Находим пользователя в БД (создаём при необходимости)
# user = db.query(models.Users).filter(models.Users.email == login_data.username).first()
# if not user:
#     user = models.Users(name=login_data.username, email=login_data.username, domainpass=login_data.password)
#     db.add(user)
#     db.commit()
#     db.refresh(user)
#
# # Получаем текущие связи пользователя с группами из БД
# current_associations = db.query(models.UserGroupAssociation).filter(
#     models.UserGroupAssociation.user_id == user.id
# ).all()
# current_group_ids = {a.group_id for a in current_associations}
#
# # Получаем группы из БД по их DN (чтобы можно было найти id)
# groups_in_db = db.query(models.Group).filter(models.Group.name.in_(ldap_group_dns)).all()
# group_name_to_id = {g.name: g.id for g in groups_in_db}
#
# # Множество id групп, которые уже есть в БД
# existing_group_ids = set(group_name_to_id.values())
#
# # Множество групп, которых нет в БД (их нужно создать)
# missing_groups = ldap_group_dns - set(group_name_to_id.keys())
#
# # Создаём недостающие группы
# for dn in missing_groups:
#     new_group = models.Group(name=dn, created_by=user.id)  # или None для created_by?
#     db.add(new_group)
#     db.flush()  # чтобы получить id
#     group_name_to_id[dn] = new_group.id
#     existing_group_ids.add(new_group.id)
#
# # Теперь у нас есть все id групп для всех DN из LDAP
# target_group_ids = set(group_name_to_id[dn] for dn in ldap_group_dns)
#
# # Определяем, какие связи нужно добавить (группы есть в LDAP, но нет связи в БД)
# to_add = target_group_ids - current_group_ids
# for group_id in to_add:
#     assoc = models.UserGroupAssociation(user_id=user.id, group_id=group_id)
#     db.add(assoc)
#
# # Определяем, какие связи нужно удалить (группы есть в БД, но нет в LDAP)
# to_remove = current_group_ids - target_group_ids
# if to_remove:
#     db.query(models.UserGroupAssociation).filter(
#         models.UserGroupAssociation.user_id == user.id,
#         models.UserGroupAssociation.group_id.in_(to_remove)
#     ).delete(synchronize_session=False)
#
# db.commit()

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
@router.get("/user/{user_id}/details", response_model=schemas.UserDetails)
async def get_user_details(
        user_id: int,
        db: Session = Depends(database.get_db),
        current_user: Users = Depends(get_current_user)
):
    # Проверяем, является ли текущий пользователь суперпользователем
    if not current_user.issuperuser and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access other user's details")

    # Получаем пользователя по user_id
    user = db.query(models.Users).filter(models.Users.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Получаем все пароли этого пользователя
    passwords = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == user_id).all()

    # Получаем все группы этого пользователя
    groups = db.query(models.Group).join(models.UserGroupAssociation).filter(
        models.UserGroupAssociation.user_id == user_id
    ).all()

    # Формируем данные для паролей
    password_data = [
        schemas.Password(
            id=password.id,
            password=password.password,
            login_password=password.login_password,
            description=password.description,
            about_password=password.about_password,
            created_by=password.created_by
        )
        for password in passwords
    ]

    # Формируем данные для групп
    group_names = [group.name for group in groups]

    # Возвращаем данные
    return {
        "user_id": user.id,
        "name": user.name,
        "email": user.email,
        "issuperuser": user.issuperuser,
        "created_at": user.created_at.isoformat(),
        "groups": group_names,
        "passwords": password_data  # Передаем список объектов паролей
    }
@router.get("/all_passwords", response_model=List[schemas.Password])
async def get_all_passwords(db: Session = Depends(database.get_db), current_user: Users = Depends(get_current_user)):
    # Проверка прав суперпользователя
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized to access all passwords")

    # Получаем все пароли из БД
    passwords = db.query(models.PasswordManager).all()

    if not passwords:
        raise HTTPException(status_code=404, detail="No passwords found")

    # FastAPI автоматически преобразует ORM-объекты в Pydantic схемы, если в схеме настроено orm_mode = True
    return passwords

@router.get("/users", response_model=List[schemas.UserDetails])
async def get_all_users(db: Session = Depends(database.get_db), current_user: Users = Depends(get_current_user)):
    # Проверка прав суперпользователя для получения всех пользователей
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized to access all users")

    # Получаем всех пользователей
    users = db.query(models.Users).all()

    # Если пользователей нет, возвращаем ошибку
    if not users:
        raise HTTPException(status_code=404, detail="No users found")

    # Формируем ответ для каждого пользователя
    user_data = []
    for user in users:
        # Получаем все пароли для каждого пользователя
        passwords = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == user.id).all()
        # Получаем все группы для каждого пользователя
        # groups = db.query(models.Group).join(models.UserGroupAssociation).filter(models.UserGroupAssociation.user_id == user.id).all()
        # Получаем ТОЛЬКО ВИДИМЫЕ группы для пользователя
        # groups = db.query(models.Group).join(models.UserGroupAssociation).filter(
        #     models.UserGroupAssociation.user_id == user.id,
        #     models.Group.visible == True   # добавляем условие видимости
        # ).all()
        groups = db.query(models.Group).join(models.UserGroupAssociation).filter(
            models.UserGroupAssociation.user_id == user.id
        ).all()
        # Формируем данные для паролей
        password_data = [
            schemas.Password(
                id=password.id,
                password=password.password,
                login_password=password.login_password,
                description=password.description,
                about_password=password.about_password,
                created_by=password.created_by
            )
            for password in passwords
        ]

        group_data = [
            schemas.Group(
                id=g.id,
                name=g.name,
                description=g.description,
                created_by=g.created_by,
                visible=g.visible
            ) for g in groups
        ]
        # group_names = [group.name for group in groups]

        # Добавляем пользователя в общий список
        user_data.append(schemas.UserDetails(
            user_id=user.id,
            name=user.name,
            email=user.email,
            issuperuser=user.issuperuser,
            created_at=user.created_at.isoformat(),
            groups=group_data,
            passwords=password_data
        ))

    return user_data

@router.get("/current_user", response_model=schemas.UserDetails)
async def get_current_user(current_user: Users = Depends(get_current_user)):
    return current_user


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

    # Разрешить, если пользователь создатель ИЛИ суперпользователь
    if group.created_by != current_user.id and not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized to modify this group")

    # Обновляем поле visible
    group.visible = visibility
    db.commit()
    db.refresh(group)  # Обновляем объект группы, чтобы вернуть актуальные данные

    return group

@router.get("/dashboard")
async def get_dashboard(current_user: models.Users = Depends(get_current_user), db: Session = Depends(database.get_db)):
    # Получаем группы текущего пользователя
    groups = db.query(models.Group).join(models.UserGroupAssociation).filter(models.UserGroupAssociation.user_id == current_user.id).all()
    return {"message": "Welcome to your dashboard", "groups": [group.name for group in groups]}

@router.post("/password_group", response_model=schemas.Password)
async def create_password(
        password_data: schemas.PasswordCreate,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    # Если указана группа, проверяем, что пользователь состоит в ней (или суперпользователь)
    if password_data.password_group is not None:
        group = db.query(models.Group).filter(models.Group.id == password_data.password_group).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        # Проверка членства (если не суперпользователь)
        if not current_user.issuperuser:
            membership = db.query(models.UserGroupAssociation).filter(
                models.UserGroupAssociation.user_id == current_user.id,
                models.UserGroupAssociation.group_id == group.id
            ).first()
            if not membership:
                raise HTTPException(status_code=403, detail="You are not a member of this group")

    new_password = models.PasswordManager(
        password=password_data.password,
        login_password=password_data.login_password,
        description=password_data.description,
        about_password=password_data.about_password,
        created_by=current_user.id,
        password_group=password_data.password_group
    )
    db.add(new_password)
    db.commit()
    db.refresh(new_password)
    return new_password

@router.put("/passwords/{password_id}/group", response_model=schemas.Password)
async def assign_password_to_group(
        password_id: int,
        assign_data: schemas.PasswordGroupAssign,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    password = db.query(models.PasswordManager).filter(models.PasswordManager.id == password_id).first()
    if not password:
        raise HTTPException(status_code=404, detail="Password not found")

    # Проверка прав: только создатель пароля или суперпользователь может менять группу
    if password.created_by != current_user.id and not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized to modify this password")

    group_id = assign_data.group_id
    if group_id is not None:
        group = db.query(models.Group).filter(models.Group.id == group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        # Если пользователь не суперпользователь, проверяем его членство в группе
        if not current_user.issuperuser:
            membership = db.query(models.UserGroupAssociation).filter(
                models.UserGroupAssociation.user_id == current_user.id,
                models.UserGroupAssociation.group_id == group.id
            ).first()
            if not membership:
                raise HTTPException(status_code=403, detail="You are not a member of this group")
    else:
        # Если group_id = None, разрешаем снять привязку к группе (только создатель или супер)
        pass

    password.password_group = group_id
    db.commit()
    db.refresh(password)
    return password

# Получить все пароли пользователя с информацией о группе
@router.get("/users/{user_id}/passwords", response_model=List[schemas.PasswordWithGroup])
async def get_user_passwords_with_groups(
        user_id: int,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    # Проверка прав: пользователь может смотреть свои пароли, суперпользователь — любые
    if current_user.id != user_id and not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized")

    passwords = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == user_id).all()
    result = []
    for pwd in passwords:
        group_info = None
        if pwd.password_group:
            group = db.query(models.Group).filter(models.Group.id == pwd.password_group).first()
            if group:
                group_info = schemas.GroupInfo(id=group.id, name=group.name)
        result.append(schemas.PasswordWithGroup(
            id=pwd.id,
            password=pwd.password,
            login_password=pwd.login_password,
            description=pwd.description,
            about_password=pwd.about_password,
            created_by=pwd.created_by,
            password_group=pwd.password_group,
            group_info=group_info
        ))
    return result