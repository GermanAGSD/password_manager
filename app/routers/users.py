from app.schemas import AddUserToGroupRequest, AddUserToGroupResponse, DeleteResponse
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.models import Users
from app.oauth import get_current_user

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

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