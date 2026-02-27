from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import Users, DirectoryObject, ObjectUserAssignment
from app.oauth import get_current_user
from pydantic import BaseModel
from datetime import datetime

router = APIRouter(prefix="/object-user-assignments", tags=["object-user-assignments"])

# Схемы Pydantic
class ObjectUserAssignmentCreate(BaseModel):
    user_id: int
    object_id: int
    role: str | None = None

class ObjectUserAssignmentResponse(BaseModel):
    id: int
    user_id: int
    object_id: int
    role: str | None
    created_by: int | None
    created_at: datetime

    class Config:
        from_attributes = True

class UserPickResponse(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True

class ObjectPickResponse(BaseModel):
    id: int
    name: str
    object_type: str

    class Config:
        from_attributes = True

@router.get("/users/pick", response_model=List[UserPickResponse])
async def get_users_for_pick(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Список пользователей для выпадающего списка (только суперпользователь)"""
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    users = db.query(Users).all()
    return users

@router.get("/objects/pick", response_model=List[ObjectPickResponse])
async def get_objects_for_pick(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Список объектов для выпадающего списка (только суперпользователь)"""
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    objects = db.query(DirectoryObject).all()
    return objects

@router.post("/", response_model=ObjectUserAssignmentResponse, status_code=status.HTTP_201_CREATED)
async def create_object_user_assignment(
        assignment: ObjectUserAssignmentCreate,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Создать привязку пользователя к объекту"""
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Проверка существования пользователя и объекта
    user = db.get(Users, assignment.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    obj = db.get(DirectoryObject, assignment.object_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")

    # Проверка на дубликат
    existing = db.query(ObjectUserAssignment).filter(
        ObjectUserAssignment.user_id == assignment.user_id,
        ObjectUserAssignment.object_id == assignment.object_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Assignment already exists")

    new_assignment = ObjectUserAssignment(
        user_id=assignment.user_id,
        object_id=assignment.object_id,
        role=assignment.role,
        created_by=current_user.id
    )
    db.add(new_assignment)
    db.commit()
    db.refresh(new_assignment)
    return new_assignment

@router.delete("/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_object_user_assignment(
        assignment_id: int,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    """Удалить привязку пользователя к объекту"""
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    assignment = db.get(ObjectUserAssignment, assignment_id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    db.delete(assignment)
    db.commit()