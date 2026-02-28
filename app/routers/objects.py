from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import DirectoryObject, Users, ObjectUserAssignment, UserGroupAssociation, PasswordManager, \
    UserPasswordShare
from pydantic import BaseModel
from typing import List
from app.oauth import get_current_user
from app.schemas import DirectoryObjectCreateRequest, DirectoryObjectPickResponse, DirectoryObjectResponse, \
    ObjectUserResponse, UserWithCountsResponse
from sqlalchemy import func
router = APIRouter(prefix="/objects", tags=["objects"])
@router.get("/{object_id}/users_with_counts", response_model=List[UserWithCountsResponse])
def get_object_users_with_counts(
        object_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """
    Возвращает пользователей, назначенных на объект, с подсчётом их групп,
    видимых паролей и объектов, на которые они назначены.
    Доступно только суперпользователю.
    """
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Проверяем существование объекта (опционально)
    obj = db.get(DirectoryObject, object_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")

    # Получаем всех пользователей, назначенных на этот объект
    assignments = db.query(ObjectUserAssignment).filter(ObjectUserAssignment.object_id == object_id).all()
    user_ids = [a.user_id for a in assignments]
    if not user_ids:
        return []

    # Загружаем пользователей
    users = db.query(Users).filter(Users.id.in_(user_ids)).all()

    # Подсчёт групп для каждого пользователя
    group_counts = dict(
        db.query(UserGroupAssociation.user_id, func.count(UserGroupAssociation.group_id))
        .filter(UserGroupAssociation.user_id.in_(user_ids))
        .group_by(UserGroupAssociation.user_id)
        .all()
    )

    # Подсчёт собственных паролей (созданных пользователем)
    own_passwords = dict(
        db.query(PasswordManager.created_by, func.count(PasswordManager.id))
        .filter(PasswordManager.created_by.in_(user_ids))
        .group_by(PasswordManager.created_by)
        .all()
    )

    # Подсчёт расшаренных паролей (пароли, доступные пользователю через shares)
    shared_passwords = dict(
        db.query(UserPasswordShare.user_id, func.count(UserPasswordShare.password_id))
        .filter(UserPasswordShare.user_id.in_(user_ids))
        .group_by(UserPasswordShare.user_id)
        .all()
    )

    # Общее количество паролей (свои + расшаренные)
    passwords_count = {}
    for uid in user_ids:
        passwords_count[uid] = own_passwords.get(uid, 0) + shared_passwords.get(uid, 0)

    # Подсчёт объектов, на которые назначен пользователь (включая текущий)
    objects_counts = dict(
        db.query(ObjectUserAssignment.user_id, func.count(ObjectUserAssignment.object_id))
        .filter(ObjectUserAssignment.user_id.in_(user_ids))
        .group_by(ObjectUserAssignment.user_id)
        .all()
    )

    # Формируем ответ
    result = []
    for user in users:
        result.append(UserWithCountsResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            issuperuser=user.issuperuser,
            groups_count=group_counts.get(user.id, 0),
            passwords_count=passwords_count.get(user.id, 0),
            objects_count=objects_counts.get(user.id, 0)
        ))
    return result
@router.get("/{object_id}/users", response_model=List[ObjectUserResponse])
def get_object_users(
        object_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """
    Возвращает список пользователей, назначенных на объект.
    Доступно всем аутентифицированным пользователям (можно ограничить по правам).
    """

    # Проверяем существование объекта (опционально)
    obj = db.get(DirectoryObject, object_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")

    # Получаем все назначения для этого объекта
    assignments = db.query(ObjectUserAssignment).filter(
        ObjectUserAssignment.object_id == object_id
    ).all()

    # Собираем ID пользователей
    user_ids = [a.user_id for a in assignments]
    if not user_ids:
        return []

    # Загружаем пользователей
    users = db.query(Users).filter(Users.id.in_(user_ids)).all()

    # Создаём словарь ролей для быстрого доступа
    roles = {a.user_id: a.role for a in assignments}

    # Формируем ответ
    result = []
    for u in users:
        result.append({
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "role": roles.get(u.id)
        })
    return result

@router.get("/objects_tree", response_model=List[DirectoryObjectResponse])
async def get_objects(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):

    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    objects = db.query(DirectoryObject).all()
    return objects

@router.get("/pick_object", response_model=List[DirectoryObjectPickResponse])
async def get_objects_for_pick(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """
    Возвращает список всех объектов для выбора родительского объекта.
    Доступно только суперпользователям (или всем аутентифицированным пользователям, в зависимости от требований).
    """
    # Если доступ разрешён только суперпользователям:
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    objects = db.query(DirectoryObject).all()
    return objects

# app/routers/objects.py (или там, где у вас роутер объектов)
@router.get("/pick", response_model=List[DirectoryObjectPickResponse])
async def get_objects_for_pick(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    objects = db.query(DirectoryObject).all()
    return objects
@router.post("/createObj", response_model=DirectoryObjectCreateRequest)
async def create_object(
        object: DirectoryObjectCreateRequest,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)

        ):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not issuperuser")
    try:
        # Проверка на уникальность названия объекта в родительской группе
        existing_object = db.query(DirectoryObject).filter(
            DirectoryObject.name == object.name,
            DirectoryObject.parent_id == object.parent_id
        ).first()

        if existing_object:
            raise HTTPException(status_code=400, detail="Объект с таким названием уже существует в этой группе")

        if object.parent_id is None:
            # если родителя нет, передаем None в запрос
            parent_object = None
        else:
            # иначе проверяем, существует ли родительский объект
            parent_object = db.query(DirectoryObject).filter(DirectoryObject.id == object.parent_id).first()
            if not parent_object:
                raise HTTPException(status_code=400, detail="Родительский объект не существует")

        db_object = DirectoryObject(
            name=object.name,
            description=object.description,
            object_type=object.object_type,
            visible=object.visible,
            parent_id=object.parent_id if parent_object else None  # если родитель существует, передаем его id
        )

        db.add(db_object)
        db.commit()
        db.refresh(db_object)

        return db_object

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/all_object/{object_id}", response_model=DirectoryObjectResponse)
async def get_object(
        object_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not superuser")
    obj = db.query(DirectoryObject).filter(DirectoryObject.id == object_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")
    return obj

