from app.schemas import AddUserToGroupRequest, AddUserToGroupResponse, DeleteResponse, UserObjectResponse, \
    ObjectsCountResponse, UserResponse, LocalUserResponse, LocalUserCreate
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.models import Users, ObjectUserAssignment, DirectoryObject
from app.oauth import get_current_user
from typing import List
from sqlalchemy import func
from app.utils import hash_password
router = APIRouter(
    prefix="/users",
    tags=["users"]
)

@router.post("/local_user/create_local_user", response_model=LocalUserResponse, status_code=status.HTTP_201_CREATED)
def create_local_user(
        user_data: LocalUserCreate,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """
    Создаёт нового локального пользователя.
    Доступно только суперпользователям.
    """
    # Проверка прав
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Проверка уникальности email
    existing = db.query(Users).filter(Users.email == user_data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    # Хэширование пароля
    hashed_password = hash_password(user_data.password)

    # Создание пользователя
    new_user = Users(
        name=user_data.name,
        email=user_data.email,
        domainpass=hashed_password,
        issuperuser=user_data.issuperuser
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

@router.get("/{user_id}", response_model=UserResponse)
def get_user(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Возвращает информацию о пользователе по ID. Доступно суперпользователю или самому пользователю."""
    if not current_user.issuperuser and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    user = db.get(Users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user
# ---------- Получить список объектов, назначенных пользователю ----------
@router.get("/{user_id}/objects", response_model=List[UserObjectResponse])
def get_user_objects(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Возвращает все объекты, назначенные пользователю. Доступно суперпользователю или самому пользователю."""
    if not current_user.issuperuser and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    assignments = db.query(ObjectUserAssignment).filter(ObjectUserAssignment.user_id == user_id).all()
    object_ids = [a.object_id for a in assignments]
    objects = db.query(DirectoryObject).filter(DirectoryObject.id.in_(object_ids)).all()
    return objects

# ---------- Назначить объект пользователю ----------
@router.post("/{user_id}/objects/{object_id}", status_code=status.HTTP_201_CREATED)
def assign_object_to_user(
        user_id: int,
        object_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Назначает объект пользователю. Только для суперпользователя."""
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    user = db.get(Users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    obj = db.get(DirectoryObject, object_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")

    existing = db.query(ObjectUserAssignment).filter(
        ObjectUserAssignment.user_id == user_id,
        ObjectUserAssignment.object_id == object_id
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Object already assigned to this user")

    assignment = ObjectUserAssignment(
        user_id=user_id,
        object_id=object_id,
        created_by=current_user.id
    )
    db.add(assignment)
    db.commit()
    return {"message": "Object assigned successfully"}

# ---------- Удалить назначение объекта у пользователя ----------
@router.delete("/{user_id}/objects/{object_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_object_from_user(
        user_id: int,
        object_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Удаляет назначение объекта у пользователя. Только для суперпользователя."""
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    assignment = db.query(ObjectUserAssignment).filter(
        ObjectUserAssignment.user_id == user_id,
        ObjectUserAssignment.object_id == object_id
    ).first()
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    db.delete(assignment)
    db.commit()
    # 204 No Content
@router.post("/{user_id}/groups/{group_id}", response_model=AddUserToGroupResponse)
def add_user_to_group(
        user_id: int,
        group_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not issuperuser")

    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Группа не найдена")

    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    exists = (
        db.query(models.UserGroupAssociation.id)
        .filter(
            models.UserGroupAssociation.user_id == user_id,
            models.UserGroupAssociation.group_id == group_id,
            )
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="Пользователь уже состоит в этой группе")

    db.add(models.UserGroupAssociation(user_id=user_id, group_id=group_id))
    db.commit()

    return AddUserToGroupResponse(
        success=True,
        message="Пользователь добавлен в группу",
        group_id=group_id,
        user_id=user_id,
    )

@router.delete("/{user_id}/groups/{group_id}", response_model=DeleteResponse)
def remove_user_from_group(
        user_id: int,
        group_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not issuperuser")

    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Группа не найдена")

    link = (
        db.query(models.UserGroupAssociation)
        .filter(
            models.UserGroupAssociation.user_id == user_id,
            models.UserGroupAssociation.group_id == group_id,
            )
        .first()
    )

    if not link:
        raise HTTPException(status_code=404, detail="Пользователь не состоит в этой группе")

    db.delete(link)
    db.commit()

    return DeleteResponse(
        success=True,
        message="Пользователь удалён из группы",
        deleted_group_id=group_id,  # поле можно оставить, но по смыслу это group_id связи
    )



# ---------- Получить список объектов, назначенных пользователю ----------
@router.get("/{user_id}/objects", response_model=List[UserObjectResponse])
def get_user_objects(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """
    Возвращает все объекты, назначенные пользователю.
    Доступно суперпользователю или самому пользователю.
    """
    if not current_user.issuperuser and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    assignments = db.query(ObjectUserAssignment).filter(ObjectUserAssignment.user_id == user_id).all()
    object_ids = [a.object_id for a in assignments]
    objects = db.query(DirectoryObject).filter(DirectoryObject.id.in_(object_ids)).all()
    return objects


# ---------- Назначить объект пользователю ----------
@router.post("/{user_id}/objects/{object_id}", status_code=status.HTTP_201_CREATED)
def assign_object_to_user(
        user_id: int,
        object_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """
    Назначает объект пользователю. Только для суперпользователя.
    Возвращает 409, если объект уже назначен.
    """
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Проверка существования пользователя
    user = db.get(Users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Проверка существования объекта
    obj = db.get(DirectoryObject, object_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")

    # Проверка дубликата
    existing = db.query(ObjectUserAssignment).filter(
        ObjectUserAssignment.user_id == user_id,
        ObjectUserAssignment.object_id == object_id
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Object already assigned to this user")

    assignment = ObjectUserAssignment(
        user_id=user_id,
        object_id=object_id,
        created_by=current_user.id
    )
    db.add(assignment)
    db.commit()
    return {"message": "Object assigned successfully"}


# ---------- Удалить назначение объекта у пользователя ----------
@router.delete("/{user_id}/objects/{object_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_object_from_user(
        user_id: int,
        object_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """
    Удаляет назначение объекта у пользователя. Только для суперпользователя.
    """
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    assignment = db.query(ObjectUserAssignment).filter(
        ObjectUserAssignment.user_id == user_id,
        ObjectUserAssignment.object_id == object_id
    ).first()
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    db.delete(assignment)
    db.commit()
    # 204 No Content — ничего не возвращаем


# ---------- (Опционально) Получить количество объектов для всех пользователей ----------
@router.get("/admin/objects_counts", response_model=List[ObjectsCountResponse])
def get_objects_counts(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """
    Возвращает для каждого пользователя количество назначенных объектов.
    Используется для отображения в таблице "Все пользователи и группы".
    Только для суперпользователя.
    """
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    counts = db.query(
        ObjectUserAssignment.user_id,
        func.count(ObjectUserAssignment.object_id).label("count")
    ).group_by(ObjectUserAssignment.user_id).all()

    return [{"user_id": row[0], "count": row[1]} for row in counts]

