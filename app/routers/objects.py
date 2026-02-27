from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import DirectoryObject, Users
from pydantic import BaseModel
from typing import List
from app.oauth import get_current_user
from app.schemas import DirectoryObjectCreateRequest, DirectoryObjectPickResponse, DirectoryObjectResponse

router = APIRouter(prefix="/objects", tags=["objects"])


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
