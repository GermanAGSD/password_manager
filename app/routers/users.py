from app.schemas import AddUserToGroupRequest, AddUserToGroupResponse
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.database import get_db
from app import models
from app.models import Users
from app.oauth import get_current_user
from app.schemas import GroupCreate, GroupOut, DeleteResponse

router = APIRouter(
    tags=["users"]
)


@router.post("/{group_id}/users", response_model=AddUserToGroupResponse)
def add_user_to_group(
        group_id: int,
        payload: AddUserToGroupRequest,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not issuperuser")

    group = db.query(models.Group).filter(models.Group.id == group_id).first()

    if not group:
        raise HTTPException(status_code=404, detail="Группа не найдена")

    user = db.query(models.Users).filter(models.Users.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    exists = (
        db.query(models.UserGroupAssociation.id)
        .filter(
            models.UserGroupAssociation.user_id == payload.user_id,
            models.UserGroupAssociation.group_id == group_id,
            )
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="Пользователь уже состоит в этой группе")

    row = models.UserGroupAssociation(user_id=payload.user_id, group_id=group_id)
    db.add(row)
    db.commit()

    return AddUserToGroupResponse(
        success=True,
        message="Пользователь добавлен в группу",
        group_id=group_id,
        user_id=payload.user_id,
    )