from fastapi import Depends, HTTPException, status, APIRouter
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.models import Users
from app.oauth import get_current_user

router = APIRouter(tags=["Groups"])


def is_superuser(db: Session, user_id: int) -> bool:
    role = (
        db.query(models.AdminRoleAssignment.id)
        .filter(
            models.AdminRoleAssignment.user_id == user_id,
            models.AdminRoleAssignment.role == "superuser",
            models.AdminRoleAssignment.is_active.is_(True),
            )
        .first()
    )
    return role is not None


def is_any_admin(db: Session, user_id: int) -> bool:
    role = (
        db.query(models.AdminRoleAssignment.id)
        .filter(
            models.AdminRoleAssignment.user_id == user_id,
            models.AdminRoleAssignment.is_active.is_(True),
            )
        .first()
    )
    return role is not None


def require_superuser(
        db: Session = Depends(get_db),
        current_user:Users = Depends(get_current_user),  # <-- замени на get_current_user
):
    if not is_superuser(db, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Только суперпользователь может выполнять это действие",
        )
    return current_user


def require_admin_any(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user),  # <-- замени на get_current_user
):
    if not is_any_admin(db, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Требуются права администратора",
        )
    return current_user