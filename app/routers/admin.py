# app/routers/admin.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List

from app.database import get_db
from app.models import Users, ObjectUserAssignment
from app.oauth import get_current_user
from pydantic import BaseModel

router = APIRouter(prefix="/admin", tags=["admin"])

class ObjectsCountResponse(BaseModel):
    user_id: int
    count: int

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