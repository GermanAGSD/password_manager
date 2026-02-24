from collections import defaultdict
from typing import Optional
from fastapi import Query
import uvicorn
from fastapi.security import OAuth2PasswordBearer
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, Form, HTTPException, Response, Cookie, APIRouter
from app import schemas, models
from app import database
from sqlalchemy.orm import Session
from app.models import Users
import secrets
import hashlib
from passlib.context import CryptContext
from sqlalchemy import delete, or_
from app.settings import settings
from app.utils import hash_password, verify_password
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from app.oauth import create_token, verify_access_token,get_current_user, create_refresh_token
from typing import List, Optional
from sqlalchemy import select, func
from app.utils_crypto import encrypt_secret, decrypt_secret
from ldap3.utils.conv import escape_filter_chars

router = APIRouter(
    # prefix="/posts",
    # tags=['Posts']
)

# LDAP settings
LDAP_SERVER = 'ldap://172.30.30.3'
LDAP_BIND_DN = 'CN=my-service,CN=Users,DC=bull,DC=local'
LDAP_PASSWORD = settings.domain_password


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def sync_ldap_groups_for_user(db: Session, user: models.Users) -> list[str]:
    """
    Синхронизирует LDAP memberOf -> таблицы Group и UserGroupAssociation для одного пользователя.
    Возвращает список group_dn из LDAP.
    """
    if not user or not user.email:
        return []

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, LDAP_BIND_DN, LDAP_PASSWORD, auto_bind=True)

    # ВАЖНО: экранируем логин для LDAP filter
    safe_username = escape_filter_chars(user.email)
    search_filter = f"(sAMAccountName={safe_username})"

    conn.search(
        "DC=bull,DC=local",
        search_filter,
        SUBTREE,
        attributes=["memberOf"]
    )

    if len(conn.entries) == 0:
        # Пользователь в LDAP не найден — ничего не делаем
        return []

    entry = conn.entries[0]
    groups = entry.memberOf.values if hasattr(entry.memberOf, "values") else []
    groups = list(groups or [])

    # 1) создаём/находим группы
    group_ids_from_ldap = set()

    for group_dn in groups:
        group = db.query(models.Group).filter(models.Group.name == group_dn).first()
        if not group:
            group = models.Group(
                name=group_dn,
                created_by=user.id,   # можно оставить так
            )
            db.add(group)
            db.flush()  # вместо commit внутри цикла

        group_ids_from_ldap.add(group.id)

        # 2) создаём связь user <-> group если её нет
        exists = db.query(models.UserGroupAssociation).filter(
            models.UserGroupAssociation.user_id == user.id,
            models.UserGroupAssociation.group_id == group.id
        ).first()

        if not exists:
            db.add(models.UserGroupAssociation(
                user_id=user.id,
                group_id=group.id
            ))

    # 3) (опционально) удаляем старые LDAP-связи, которых уже нет в LDAP
    # ВНИМАНИЕ: включай это только если в этой таблице Group у тебя действительно LDAP-группы,
    # а не пользовательские "локальные" группы.
    #
    # current_links = (
    #     db.query(models.UserGroupAssociation)
    #     .join(models.Group, models.Group.id == models.UserGroupAssociation.group_id)
    #     .filter(models.UserGroupAssociation.user_id == user.id)
    #     .all()
    # )
    #
    # for link in current_links:
    #     grp = db.query(models.Group).filter(models.Group.id == link.group_id).first()
    #     if grp and grp.name and "DC=" in grp.name and grp.id not in group_ids_from_ldap:
    #         db.delete(link)

    db.commit()
    return groups

def _safe_decrypt_password_value(value: Optional[str]) -> Optional[str]:
    """
    Расшифровывает пароль из БД.
    Если запись старая (лежит в открытом виде), возвращает как есть.
    """
    if value is None:
        return None

    try:
        return decrypt_secret(value)
    except Exception:
        # fallback для старых записей, если они еще plaintext
        return value


def to_password_schema(p: models.PasswordManager) -> schemas.Password:
    return schemas.Password(
        id=p.id,
        password=_safe_decrypt_password_value(p.password),  # <-- расшифровка
        login_password=p.login_password,
        description=p.description,
        about_password=p.about_password,
        created_by=p.created_by,
        password_group=p.password_group,
    )


def to_password_with_group_schema(
        p: models.PasswordManager,
        group_info: Optional[schemas.GroupInfo] = None
) -> schemas.PasswordWithGroup:
    return schemas.PasswordWithGroup(
        id=p.id,
        password=_safe_decrypt_password_value(p.password),  # <-- расшифровка
        login_password=p.login_password,
        description=p.description,
        about_password=p.about_password,
        created_by=p.created_by,
        password_group=p.password_group,
        group_info=group_info,
    )
@router.get("/users/{user_id}/visible_passwords", response_model=list[schemas.Password])
async def get_visible_passwords(
        user_id: int,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    if not current_user.issuperuser and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    rows = (
        db.query(models.PasswordManager)
        .outerjoin(
            models.UserPasswordShare,
            models.UserPasswordShare.password_id == models.PasswordManager.id
        )
        .filter(
            or_(
                models.PasswordManager.created_by == user_id,
                models.UserPasswordShare.user_id == user_id
            )
        )
        .distinct()
        .all()
    )

    return [to_password_schema(p) for p in rows]

# @router.get("/users/{user_id}/visible_passwords", response_model=list[schemas.Password])
# async def get_visible_passwords(
#         user_id: int,
#         db: Session = Depends(database.get_db),
#         current_user: models.Users = Depends(get_current_user)
# ):
#     # пользователь может смотреть только свои visible_passwords (superuser может любые)
#     if not current_user.issuperuser and current_user.id != user_id:
#         raise HTTPException(status_code=403, detail="Not authorized")
#
#     q = (
#         db.query(models.PasswordManager)
#         .outerjoin(
#             models.UserPasswordShare,
#             models.UserPasswordShare.password_id == models.PasswordManager.id
#         )
#         .filter(
#             or_(
#                 models.PasswordManager.created_by == user_id,
#                 models.UserPasswordShare.user_id == user_id
#             )
#         )
#         .distinct()
#     )
#
#     return q.all()

@router.post("/login", response_model=schemas.Token)
async def login_for_access_token(
        response: Response,
        login_data: schemas.LoginRequest,
        db: Session = Depends(database.get_db),
):
    # LDAP auth
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, LDAP_BIND_DN, LDAP_PASSWORD, auto_bind=True)

    search_filter = f"(sAMAccountName={login_data.username})"
    conn.search("DC=bull,DC=local", search_filter, SUBTREE, attributes=["cn", "mail", "memberOf"])

    if len(conn.entries) == 0:
        raise HTTPException(status_code=404, detail="User not found")

    user_dn = conn.entries[0].entry_dn
    user_conn = Connection(server, user_dn, login_data.password, authentication=SIMPLE)

    if not user_conn.bind():
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # groups = conn.entries[0].memberOf.values if hasattr(conn.entries[0].memberOf, "values") else []

    # DB user
    user = db.query(models.Users).filter(models.Users.email == login_data.username).first()

    # Хэшируем пароль для хранения
    hashed = hash_password(login_data.password)

    if not user:
        user = models.Users(
            name=login_data.username,
            email=login_data.username,
            domainpass=hashed,   # <-- ХЭШ вместо plain
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # (опционально) обновляем хэш только если пароль отличается
        # если domainpass может быть пустой/None - учти это
        try:
            needs_update = not verify_password(login_data.password, user.domainpass)
        except Exception:
            needs_update = True

        if needs_update:
            user.domainpass = hashed
            db.commit()
            db.refresh(user)

    # access/refresh токены
    access_token = create_token(data={"user_id": user.id, "issuperuser": user.issuperuser})
    refresh_token, refresh_hash, expires = create_refresh_token()

    # Группы/ассоциации — лучше без дублей
    # for group_dn in groups:
    #     group = db.query(models.Group).filter(models.Group.name == group_dn).first()
    #     if not group:
    #         group = models.Group(name=group_dn, created_by=user.id)
    #         db.add(group)
    #         db.flush()  # вместо commit внутри цикла
    #
    #     exists = db.query(models.UserGroupAssociation).filter(
    #         models.UserGroupAssociation.user_id == user.id,
    #         models.UserGroupAssociation.group_id == group.id
    #     ).first()
    #
    #     if not exists:
    #         db.add(models.UserGroupAssociation(user_id=user.id, group_id=group.id))

    # сохраняем refresh hash в БД
    db.add(models.RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=expires,
        revoked=False
    ))

    db.commit()

    return {
        "refresh_token": refresh_token,
        "access_token": access_token,
        "token_type": "bearer",
        "issuperuser": user.issuperuser,
        "user_id": user.id,
    }


@router.get("/user/{user_id}/groups", response_model=list[schemas.GroupWithCreator])
async def get_groups_by_user(
        user_id: int,
        db: Session = Depends(database.get_db),
        current_user: Users = Depends(get_current_user)
):
    if current_user.id != user_id and not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Находим пользователя в БД
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # ✅ Синхронизируем LDAP-группы ПЕРЕД чтением из БД
    # # Это решает проблему "админ не видит новую группу до перелогина пользователя"
    # try:
    #     # sync_ldap_groups_for_user(db, user)
    # except Exception as e:
    #     # Можно не падать полностью, а просто логировать и вернуть то, что есть в БД
    #     # raise HTTPException(status_code=500, detail=f"LDAP sync failed: {str(e)}")
    #     print(f"LDAP sync failed for user_id={user_id}: {e}")

    groups_with_creator = (
        db.query(models.Group, models.Users.name.label("creator_name"))
        .join(
            models.UserGroupAssociation,
            models.UserGroupAssociation.group_id == models.Group.id
        )
        .join(models.Users, models.Users.id == models.Group.created_by)
        .filter(
            models.UserGroupAssociation.user_id == user_id,
            models.Group.visible.is_(True)
        )
        .distinct()
        .all()
    )

    result = []
    for group, creator_name in groups_with_creator:
        result.append(
            schemas.GroupWithCreator(
                id=group.id,
                name=group.name,
                description=group.description,
                creator_name=creator_name,
                visible=group.visible,
            )
        )

    return result


@router.post("/auth/refresh")
def refresh_token_endpoint(
        payload: schemas.RefreshRequest,
        db: Session = Depends(database.get_db),
):
    refresh_token = payload.refresh_token
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    token_hash = hash_refresh_token(refresh_token)

    token_row = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.token_hash == token_hash)
        .first()
    )

    if not token_row:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if token_row.revoked:
        raise HTTPException(status_code=401, detail="Refresh token revoked")

    # timezone-aware сравнение (так как expires_at у тебя TIMESTAMP(timezone=True))
    now_utc = datetime.now(timezone.utc)
    if token_row.expires_at < now_utc:
        raise HTTPException(status_code=401, detail="Refresh expired")

    user = db.query(Users).filter(Users.id == token_row.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # ревокаем старый refresh
    token_row.revoked = True
    token_row.revoked_at = now_utc

    # выдаем новый access + refresh
    new_access = create_token({
        "user_id": user.id,
        "issuperuser": user.issuperuser
    })

    new_refresh, new_hash, new_expires = create_refresh_token()

    db.add(models.RefreshToken(
        user_id=user.id,
        token_hash=new_hash,
        expires_at=new_expires,
        revoked=False
    ))

    db.commit()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "issuperuser": user.issuperuser,
        "user_id": user.id,
    }
@router.post("/passwords", response_model=schemas.Password)
async def create_password(
        password_data: schemas.PasswordCreate,
        db: Session = Depends(database.get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    encrypted_password = encrypt_secret(password_data.password)

    new_password = models.PasswordManager(
        password=encrypted_password,  # <-- шифруем перед записью
        login_password=password_data.login_password,
        description=password_data.description,
        about_password=password_data.about_password,
        created_by=current_user.id
    )

    db.add(new_password)
    db.commit()
    db.refresh(new_password)

    return to_password_schema(new_password)  # <-- возвращаем расшифрованный
# @router.post("/passwords", response_model=schemas.Password)
# async def create_password(
#         password_data: schemas.PasswordCreate,
#         db: Session = Depends(database.get_db),
#         current_user: Users = Depends(get_current_user)  # Получаем текущего пользователя
# ):
#     # Проверяем, существует ли пользователь
#     if not current_user:
#         raise HTTPException(status_code=404, detail="User not found")
#
#     # Создаем новый объект PasswordManager
#     new_password = models.PasswordManager(
#         password=password_data.password,
#         login_password=password_data.login_password,
#         description=password_data.description,
#         about_password=password_data.about_password,
#         created_by=current_user.id  # Указываем пользователя, который создает пароль
#     )
#
#     # Добавляем в базу данных
#     db.add(new_password)
#     db.commit()
#     db.refresh(new_password)
#
#     return new_password

# @router.get("/passwords/{user_id}", response_model=list[schemas.Password], status_code=200)
# async def get_passwords_by_user(user_id: int, db: Session = Depends(database.get_db), current_user: Users = Depends(get_current_user)):
#     # Если текущий пользователь суперпользователь, он может получить пароли других пользователей
#     if current_user.issuperuser:
#         passwords = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == user_id).all()
#
#         if not passwords:
#             raise HTTPException(status_code=404, detail="No passwords found for this user")
#         return passwords
#
#     # Если текущий пользователь не суперпользователь, он может только получить свои пароли
#     if current_user.id == user_id:
#         passwords = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == current_user.id).all()
#
#         if not passwords:
#             raise HTTPException(status_code=404, detail="No passwords found for this user")
#         return passwords
#
#     # Если пользователь не суперпользователь и не запрашивает свои пароли, возвращаем ошибку доступа
#     raise HTTPException(status_code=403, detail="Not authorized to access other user's passwords")
@router.get("/passwords/{user_id}", response_model=list[schemas.Password], status_code=200)
async def get_passwords_by_user(
        user_id: int,
        db: Session = Depends(database.get_db),
        current_user: Users = Depends(get_current_user)
):
    if current_user.issuperuser:
        rows = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == user_id).all()
        return [to_password_schema(p) for p in rows]

    if current_user.id == user_id:
        rows = db.query(models.PasswordManager).filter(models.PasswordManager.created_by == current_user.id).all()
        return [to_password_schema(p) for p in rows]

    raise HTTPException(status_code=403, detail="Not authorized to access other user's passwords")

@router.get("/user/{user_id}/visible_groups", response_model=list[schemas.GroupWithCreator])
async def get_visible_groups_by_user(
        user_id: int,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access other user's groups")

    groups_with_creator = (
        db.query(
            models.Group,
            models.Users.name.label('creator_name')
        )
        .join(
            models.UserGroupAssociation,
            models.UserGroupAssociation.group_id == models.Group.id
        )
        .outerjoin(  # <-- лучше outerjoin, чтобы группа не пропала, если created_by пустой
            models.Users,
            models.Users.id == models.Group.created_by
        )
        .filter(
            models.UserGroupAssociation.user_id == user_id,
            models.Group.visible.is_(True)
        )
        .all()
    )

    # ✅ Это НЕ ошибка — просто нет групп
    if not groups_with_creator:
        return []

    result = []
    for group, creator_name in groups_with_creator:
        result.append(schemas.GroupWithCreator(
            id=group.id,
            name=group.name,
            description=group.description,
            creator_name=creator_name or "-",
            visible=group.visible
        ))

    return result

@router.get("/admin/users/visible_passwords_counts", response_model=list[schemas.UserPasswordCount])
async def visible_passwords_counts(
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized")

    # owned: (user_id, password_id)
    owned = select(
        models.PasswordManager.created_by.label("user_id"),
        models.PasswordManager.id.label("password_id"),
    )

    # shared: (user_id, password_id)
    shared = select(
        models.UserPasswordShare.user_id.label("user_id"),
        models.UserPasswordShare.password_id.label("password_id"),
    )

    u = owned.union_all(shared).subquery()

    q = select(
        u.c.user_id,
        func.count(func.distinct(u.c.password_id)).label("count")
    ).group_by(u.c.user_id)

    rows = db.execute(q).all()  # [(user_id, count), ...]

    # чтобы пользователи без паролей тоже вернулись с 0:
    all_users = db.query(models.Users.id).all()
    m = {uid: 0 for (uid,) in all_users}
    for user_id, cnt in rows:
        m[int(user_id)] = int(cnt)

    return [{"user_id": uid, "count": m[uid]} for uid in sorted(m.keys())]

@router.get("/users/details", response_model=list[schemas.UserDetails])
async def get_all_users_details(
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized")

    users = db.query(models.Users).order_by(models.Users.id).all()

    # 2) Все пароли (группируем по created_by)
    passwords = db.query(models.PasswordManager).all()
    pw_by_user = defaultdict(list)
    for p in passwords:
        pw_by_user[p.created_by].append(to_password_schema(p))

    # 3) Все группы по пользователям + DISTINCT
    rows = (
        db.query(models.UserGroupAssociation.user_id, models.Group.name)
        .join(models.Group, models.Group.id == models.UserGroupAssociation.group_id)
        .filter(models.Group.visible.is_(True))
        .distinct()
        .all()
    )

    groups_by_user = defaultdict(set)
    for user_id, group_name in rows:
        groups_by_user[user_id].add(group_name)

    result = []
    for u in users:
        result.append(
            schemas.UserDetails(
                user_id=u.id,
                name=u.name,
                email=u.email,
                issuperuser=u.issuperuser,
                created_at=u.created_at,
                groups=sorted(list(groups_by_user.get(u.id, set()))),
                passwords=pw_by_user.get(u.id, []),
            )
        )

    return result


@router.get("/all_passwords", response_model=List[schemas.Password])
async def get_all_passwords(
        db: Session = Depends(database.get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized to access all passwords")

    rows = db.query(models.PasswordManager).all()
    return [to_password_schema(p) for p in rows]

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
        # password_data = [
        #     schemas.Password(
        #         id=password.id,
        #         password=password.password,
        #         login_password=password.login_password,
        #         description=password.description,
        #         about_password=password.about_password,
        #         created_by=password.created_by
        #     )
        #     for password in passwords
        # ]
        password_data = [to_password_schema(password) for password in passwords]
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
async def get_current_user_back(current_user: Users = Depends(get_current_user)):
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
async def create_password_group(
        password_data: schemas.PasswordCreate,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    if password_data.password_group is not None:
        group = db.query(models.Group).filter(models.Group.id == password_data.password_group).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        if not current_user.issuperuser:
            membership = db.query(models.UserGroupAssociation).filter(
                models.UserGroupAssociation.user_id == current_user.id,
                models.UserGroupAssociation.group_id == group.id
            ).first()
            if not membership:
                raise HTTPException(status_code=403, detail="You are not a member of this group")

    encrypted_password = encrypt_secret(password_data.password)

    new_password = models.PasswordManager(
        password=encrypted_password,  # <-- шифруем
        login_password=password_data.login_password,
        description=password_data.description,
        about_password=password_data.about_password,
        created_by=current_user.id,
        password_group=password_data.password_group
    )
    db.add(new_password)
    db.commit()
    db.refresh(new_password)
    return to_password_schema(new_password)
# @router.post("/password_group", response_model=schemas.Password)
# async def create_password_group(
#         password_data: schemas.PasswordCreate,
#         db: Session = Depends(database.get_db),
#         current_user: models.Users = Depends(get_current_user)
# ):
#     # Если указана группа, проверяем, что пользователь состоит в ней (или суперпользователь)
#     if password_data.password_group is not None:
#         group = db.query(models.Group).filter(models.Group.id == password_data.password_group).first()
#         if not group:
#             raise HTTPException(status_code=404, detail="Group not found")
#         # Проверка членства (если не суперпользователь)
#         if not current_user.issuperuser:
#             membership = db.query(models.UserGroupAssociation).filter(
#                 models.UserGroupAssociation.user_id == current_user.id,
#                 models.UserGroupAssociation.group_id == group.id
#             ).first()
#             if not membership:
#                 raise HTTPException(status_code=403, detail="You are not a member of this group")
#
#     new_password = models.PasswordManager(
#         password=password_data.password,
#         login_password=password_data.login_password,
#         description=password_data.description,
#         about_password=password_data.about_password,
#         created_by=current_user.id,
#         password_group=password_data.password_group
#     )
#     db.add(new_password)
#     db.commit()
#     db.refresh(new_password)
#     return new_password

@router.put("/passwords/{password_id}/group", response_model=schemas.Password)
async def update_password_group(
        password_id: int,
        group_id: Optional[int] = Query(default=0),   # <-- по умолчанию 0
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    pw = db.query(models.PasswordManager).filter(models.PasswordManager.id == password_id).first()
    if not pw:
        raise HTTPException(status_code=404, detail="Password not found")

    if pw.created_by != current_user.id and not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized to modify this password")

    # 0 => снять группу
    if group_id == 0:
        pw.password_group = None
        db.commit()
        db.refresh(pw)
        return pw

    # назначаем группу
    grp = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not grp:
        raise HTTPException(status_code=404, detail="Group not found")

    pw.password_group = group_id
    db.commit()
    db.refresh(pw)
    return to_password_schema(pw)

@router.get("/users/{user_id}/passwords", response_model=List[schemas.PasswordWithGroup])
async def get_user_passwords_with_groups(
        user_id: int,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    # Проверка прав: пользователь может смотреть свои пароли, суперпользователь — любые
    if current_user.id != user_id and not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized")

    passwords = (
        db.query(models.PasswordManager)
        .filter(models.PasswordManager.created_by == user_id)
        .all()
    )

    # Чтобы не делать N+1 запросов по группам, можно заранее собрать группы в map
    group_ids = {p.password_group for p in passwords if p.password_group}
    group_map = {}

    if group_ids:
        groups = db.query(models.Group).filter(models.Group.id.in_(group_ids)).all()
        group_map = {
            g.id: schemas.GroupInfo(id=g.id, name=g.name)
            for g in groups
        }

    result = []
    for pwd in passwords:
        group_info = group_map.get(pwd.password_group) if pwd.password_group else None
        result.append(to_password_with_group_schema(pwd, group_info))

    return result
# Получить все пароли пользователя с информацией о группе

@router.get("/admin/passwords/pick", response_model=list[schemas.PasswordPickItem])
async def passwords_pick(
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized")

    rows = (
        db.query(models.PasswordManager, models.Users.email)   # или models.Users.name
        .join(models.Users, models.Users.id == models.PasswordManager.created_by)
        .order_by(models.PasswordManager.id.desc())
        .all()
    )

    result = []
    for p, user_email in rows:
        result.append({
            "id": p.id,
            "description": p.description,
            "login_password": p.login_password,
            "about_password": p.about_password,
            "created_by": p.created_by,
            "creator_login": user_email,   # <-- вот логин
        })

    return result

@router.get("/users/{user_id}/shared_password_ids", response_model=list[int])
async def get_shared_password_ids(
        user_id: int,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized")

    rows = db.query(models.UserPasswordShare.password_id).filter(
        models.UserPasswordShare.user_id == user_id
    ).all()

    return [r[0] for r in rows]

@router.put("/users/{user_id}/shared_passwords", response_model=schemas.SharePasswordsResult)
async def set_shared_passwords(
        user_id: int,
        payload: schemas.SharePasswordsUpdate,
        db: Session = Depends(database.get_db),
        current_user: models.Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not authorized")

    # проверим, что user существует
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # проверим, что пароли существуют
    ids = list(set(payload.password_ids or []))
    if ids:
        existing = db.query(models.PasswordManager.id).filter(models.PasswordManager.id.in_(ids)).all()
        existing_ids = {x[0] for x in existing}
        missing = [x for x in ids if x not in existing_ids]
        if missing:
            raise HTTPException(status_code=404, detail=f"Passwords not found: {missing}")

    # удаляем старые связи
    db.execute(delete(models.UserPasswordShare).where(models.UserPasswordShare.user_id == user_id))

    # добавляем новые
    for pid in ids:
        db.add(models.UserPasswordShare(
            user_id=user_id,
            password_id=pid,
            granted_by=current_user.id
        ))

    db.commit()
    return {"user_id": user_id, "password_ids": ids}


