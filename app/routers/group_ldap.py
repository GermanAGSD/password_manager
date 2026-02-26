from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.database import get_db
from app import models
from app.models import Users
from app.oauth import get_current_user
from app.schemas import GroupCreate, GroupOut, DeleteResponse, GroupPickItem
from app.deps.admin_access import require_superuser

router = APIRouter(prefix="/groups", tags=["Groups"])


@router.post("/", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
def create_group(
        # user_id: int,
        payload: GroupCreate,
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not issuperuser")

    name = payload.name.strip()

    if not name:
        raise HTTPException(status_code=400, detail="Название группы не может быть пустым")

    node_type = payload.node_type.strip()
    if not node_type:
        raise HTTPException(status_code=400, detail="Тип группы (node_type) не может быть пустым")

    # ✅ Только проверяем, что родитель существует (если указан)
    if payload.parent_id is not None:
        parent = db.query(models.Group).filter(models.Group.id == payload.parent_id).first()
        if not parent:
            raise HTTPException(status_code=404, detail="Родительская группа не найдена")

    # ✅ Проверка дубля имени только в пределах одного parent_id
    dup_query = db.query(models.Group).filter(models.Group.name == name)
    if payload.parent_id is None:
        dup_query = dup_query.filter(models.Group.parent_id.is_(None))
    else:
        dup_query = dup_query.filter(models.Group.parent_id == payload.parent_id)

    if dup_query.first():
        raise HTTPException(
            status_code=409,
            detail="Группа с таким именем уже существует в этом разделе"
        )

    new_group = models.Group(
        name=name,
        description=payload.description,
        parent_id=payload.parent_id,
        visible=payload.visible,
        node_type=node_type,
        created_by=current_user.id,
    )

    db.add(new_group)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Не удалось создать группу: конфликт уникальности"
        )

    db.refresh(new_group)
    return new_group


@router.delete("/{group_id}", response_model=DeleteResponse)
def delete_group(
        group_id: int,
        recursive: bool = Query(False, description="Удалить вместе с подгруппами"),
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not issuperuser")

    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Группа не найдена")

    has_children = (
            db.query(models.Group.id)
            .filter(models.Group.parent_id == group.id)
            .first()
            is not None
    )

    if has_children and not recursive:
        raise HTTPException(
            status_code=400,
            detail="У группы есть подгруппы. Передай ?recursive=true для удаления вместе с подгруппами"
        )

    db.delete(group)
    db.commit()

    return DeleteResponse(
        success=True,
        message="Группа удалена",
        deleted_group_id=group_id,
    )

@router.get("/pick", response_model=list[GroupPickItem])
def get_groups_pick(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user)
):
    if not current_user.issuperuser:
        raise HTTPException(status_code=403, detail="Not issuperuser")

    rows = db.query(models.Group).order_by(models.Group.name.asc()).all()

    return [
        GroupPickItem(
            id=g.id,
            name=g.name,
            description=g.description,
            visible=g.visible,
        )
        for g in rows
    ]