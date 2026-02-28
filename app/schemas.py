from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import datetime
from typing import Optional, List, Literal

from pydantic.types import conint

class LdapUsers(BaseModel):
    username: str
    password: str

    class Config:
        orm_mode: True

class TokenData(BaseModel):
    id: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    # groups: List[str]
    refresh_token: str
    issuperuser: bool

class RefreshRequest(BaseModel):
    refresh_token: str




class PasswordCreate(BaseModel):
    password: str
    login_password: str
    description: Optional[str] = None
    about_password: Optional[str] = None
    password_group: Optional[int] = None

    class Config:
        orm_mode = True

class UserPasswordCount(BaseModel):
    user_id: int
    count: int

class PasswordPickItem(BaseModel):
    id: int
    description: str | None = None
    login_password: str | None = None
    about_password: str | None = None
    created_by: int
    creator_login: str | None = None

    class Config:
        from_attributes = True

class SharePasswordsUpdate(BaseModel):
    password_ids: List[int]

class SharePasswordsResult(BaseModel):
    user_id: int
    password_ids: List[int]

class Password(BaseModel):
    id: int
    password: str
    login_password: str
    description: Optional[str] = None
    about_password: Optional[str] = None
    created_by: int
    password_group: Optional[int] = None  # добавить поле

    class Config:
        orm_mode = True

class UserDetails(BaseModel):
    user_id: int
    name: str
    email: str
    issuperuser: bool
    created_at: datetime
    groups: List[str]
    passwords: List[Password]

    class Config:
        orm_mode = True

class PasswordWithCreator(Password):
    created_by_name: str

class GroupWithCreator(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    creator_name: str   # новое поле – имя создателя
    visible: bool

    class Config:
        orm_mode = True

# Схема для Group, которая будет использоваться для ответа
class Group(BaseModel):
    id: int
    name: str
    description: str | None = None
    visible: bool
    created_by: int | None = None

    class Config:
        orm_mode = True

class LoginRequest(BaseModel):
    username: str
    password: str

# class UserDetails(BaseModel):
#     user_id: int
#     name: str
#     email: str
#     issuperuser: bool
#     created_at: str
#     groups: List[Group]  # Список строк для групп
#     passwords: List[Password]  # Список строк для паролей
#
#     class Config:
#         orm_mode = True

class GroupAll(BaseModel):
    groups: List[Group]

# Схема для создания пароля (уже может быть)
class PasswordCreate(BaseModel):
    login_password: str
    password: str
    description: Optional[str] = None
    about_password: Optional[str] = None
    password_group: Optional[int] = None  # добавить опциональное поле

class GroupInfo(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True

class PasswordWithGroup(Password):
    group_info: Optional[GroupInfo] = None

# Схема для назначения группы паролю
class PasswordGroupAssign(BaseModel):
    group_id: int

class PasswordListItem(BaseModel):
    id: int
    description: Optional[str] = None
    login_password: Optional[str] = None
    about_password: Optional[str] = None
    created_by: int
    password_group: Optional[int] = None
    group_info: Optional[GroupInfo] = None

    # NEW: вместо открытого пароля
    has_password: bool = True
    password_masked: str = "••••••••"

    class Config:
        orm_mode = True


class PasswordRevealResponse(BaseModel):
    id: int
    password: str  # plaintext только по отдельному запросу

class GroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    parent_id: Optional[int] = None
    visible: bool = True
    # ✅ Любой node_type
    node_type: str = Field(default="group", min_length=1, max_length=64)

class AddUserToGroupRequest(BaseModel):
    user_id: int


class AddUserToGroupResponse(BaseModel):
    success: bool
    message: str
    group_id: int
    user_id: int

class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: Optional[str]
    parent_id: Optional[int]
    visible: bool
    node_type: str
    created_by: Optional[int]
    created_at: datetime


class DeleteResponse(BaseModel):
    success: bool
    message: str
    deleted_group_id: int

class GroupPickItem(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    visible: bool

class DirectoryObjectCreateRequest(BaseModel):
    name: str
    description: str = None
    object_type: str = "object"
    visible: bool = True
    parent_id: Optional[int] = None  # ID родительского объекта (если есть)

class DirectoryObjectPickResponse(BaseModel):
    id: int
    name: str
    description: str | None = None
    object_type: str
    visible: bool

    class Config:
        from_attributes = True

class DirectoryObjectResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    object_type: str
    visible: bool
    parent_id: Optional[int] = None

    class Config:
        from_attributes = True  # orm_mode = True для Pydantic v1

# Pydantic схемы для ответов
class UserObjectResponse(BaseModel):
    id: int
    name: str
    object_type: str
    visible: bool

    class Config:
        from_attributes = True

class ObjectsCountResponse(BaseModel):
    user_id: int
    count: int

# Схемы для ответов
class UserObjectResponse(BaseModel):
    id: int
    name: str
    object_type: str
    visible: bool

    class Config:
        from_attributes = True

# Схема для ответа с данными пользователя
class UserResponse(BaseModel):
    id: int
    name: str
    email: Optional[str] = None
    # добавьте другие поля, если нужно (например, issuperuser, created_at)

    class Config:
        from_attributes = True

# Схема для ответа (можно вынести в schemas.py)
class ObjectUserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: Optional[str] = None

    class Config:
        from_attributes = True

class ObjectsCountResponse(BaseModel):
    user_id: int
    count: int

class ObjectAdminResponse(BaseModel):
    id: int
    name: str
    object_type: str
    visible: bool
    user_count: int
    group_count: int
    child_count: int

    class Config:
        from_attributes = True

class UserWithCountsResponse(BaseModel):
    id: int
    name: str
    email: str
    issuperuser: bool
    groups_count: int
    passwords_count: int
    objects_count: int

    class Config:
        from_attributes = True

# Схема для запроса создания локального пользователя
class LocalUserCreate(BaseModel):
    name: str
    email: str
    password: str
    issuperuser: Optional[bool] = False

# Схема для ответа (без пароля)
class LocalUserResponse(BaseModel):
    id: int
    name: str
    email: str
    issuperuser: bool
    created_at: datetime  # используем datetime, а не str

    class Config:
        from_attributes = True

class LocalLoginRequest(BaseModel):
    username: str
    password: str
