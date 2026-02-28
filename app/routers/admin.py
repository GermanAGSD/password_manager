# app/routers/admin.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List

from app.database import get_db
from app.models import Users, ObjectUserAssignment, DirectoryObject, ObjectGroupAssignment
from app.oauth import get_current_user
from pydantic import BaseModel

from app.schemas import ObjectAdminResponse, ObjectsCountResponse

router = APIRouter(prefix="/admin", tags=["admin"])



@router.get("/objects", response_model=List[ObjectAdminResponse])
def get_objects_admin(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    objects = db.query(DirectoryObject).all()
    result = []
    for obj in objects:
        user_count = db.query(ObjectUserAssignment).filter(ObjectUserAssignment.object_id == obj.id).count()
        group_count = db.query(ObjectGroupAssignment).filter(ObjectGroupAssignment.object_id == obj.id).count()
        child_count = db.query(DirectoryObject).filter(DirectoryObject.parent_id == obj.id).count()
        result.append({
            "id": obj.id,
            "name": obj.name,
            "object_type": obj.object_type,
            "visible": obj.visible,
            "user_count": user_count,
            "group_count": group_count,
            "child_count": child_count
        })
    return result

@router.get("/users/objects_counts", response_model=List[ObjectsCountResponse])
def get_objects_counts(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Возвращает количество объектов, назначенных каждому пользователю. Только для суперпользователя."""
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    counts = db.query(
        ObjectUserAssignment.user_id,
        func.count(ObjectUserAssignment.object_id).label("count")
    ).group_by(ObjectUserAssignment.user_id).all()

    return [{"user_id": row[0], "count": row[1]} for row in counts]