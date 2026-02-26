# app/models.py  (финальная схема: Users / Groups + Objects как в AD)

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
    Index,
    text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import TIMESTAMP

from app.database import Base


# ----------------------------
# USERS
# ----------------------------
# --- Users (фрагмент) ---
class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True)
    history = Column(String, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    primary_group_id = Column(Integer, ForeignKey("groups.id", ondelete="SET NULL"), nullable=True, index=True)

    issuperuser = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    domainpass = Column(String, nullable=False)

    # --- existing relationships in your project ---
    passwords = relationship("PasswordManager", back_populates="creator")
    primary_group = relationship("Group", foreign_keys=[primary_group_id])

    group_memberships = relationship(
        "UserGroupAssociation",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    groups = relationship(
        "Group",
        secondary="user_group_association",
        back_populates="users",
        overlaps="group_memberships,user_memberships,user,group",
    )

    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    password_shares = relationship(
        "UserPasswordShare",
        foreign_keys="UserPasswordShare.user_id",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    granted_password_shares = relationship(
        "UserPasswordShare",
        foreign_keys="UserPasswordShare.granted_by",
        back_populates="granted_by_user",
    )

    admin_roles = relationship(
        "AdminRoleAssignment",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="AdminRoleAssignment.user_id",
    )

    created_admin_roles = relationship(
        "AdminRoleAssignment",
        back_populates="creator",
        foreign_keys="AdminRoleAssignment.created_by",
    )

    # ✅ object_user_assignments: назначен на объект
    object_assignments = relationship(
        "ObjectUserAssignment",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="ObjectUserAssignment.user_id",
    )

    # ✅ object_user_assignments: кто создал назначение
    created_object_assignments = relationship(
        "ObjectUserAssignment",
        back_populates="created_by_user",
        foreign_keys="ObjectUserAssignment.created_by",
    )
# ----------------------------
# GROUPS (tree)
# ----------------------------
class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)

    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    visible = Column(Boolean, nullable=False, default=True, server_default=text("true"))

    # any type for your logic (restaurant/city/team/etc.)
    node_type = Column(String(64), nullable=False, default="group", server_default=text("'group'"), index=True)

    parent_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    parent = relationship("Group", remote_side=[id], back_populates="children")
    children = relationship("Group", back_populates="parent", cascade="all, delete-orphan")

    # direct user membership
    user_memberships = relationship(
        "UserGroupAssociation",
        back_populates="group",
        cascade="all, delete-orphan",
        overlaps="groups,users",
    )

    users = relationship(
        "Users",
        secondary="user_group_association",
        back_populates="groups",
        overlaps="group_memberships,user_memberships,user,group",
    )

    # passwords linked to group
    passwords = relationship("PasswordManager", back_populates="group")

    admin_role_assignments = relationship(
        "AdminRoleAssignment",
        back_populates="scope_group",
        foreign_keys="AdminRoleAssignment.scope_group_id",
    )

    # object assignments (group -> object)
    object_assignments = relationship(
        "ObjectGroupAssignment",
        back_populates="group",
        cascade="all, delete-orphan",
        foreign_keys="ObjectGroupAssignment.group_id",
    )

    __table_args__ = (
        UniqueConstraint("parent_id", "name", name="uq_group_parent_name"),
        CheckConstraint("parent_id IS NULL OR parent_id <> id", name="ck_group_not_self_parent"),
    )


class UserGroupAssociation(Base):
    __tablename__ = "user_group_association"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "group_id", name="uq_user_group"),
        Index("ix_user_group_user_id", "user_id"),
        Index("ix_user_group_group_id", "group_id"),
    )

    user = relationship("Users", back_populates="group_memberships", overlaps="groups,users")
    group = relationship("Group", back_populates="user_memberships", overlaps="groups,users")


# ----------------------------
# OBJECTS (как "объекты" в AD) + иерархия объектов
# ----------------------------
# --- DirectoryObject (полностью, ключевая правка в users relationship) ---
class DirectoryObject(Base):
    __tablename__ = "directory_objects"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)

    object_type = Column(String(64), nullable=False, default="object", server_default=text("'object'"), index=True)
    visible = Column(Boolean, nullable=False, default=True, server_default=text("true"))

    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    parent_id = Column(Integer, ForeignKey("directory_objects.id", ondelete="CASCADE"), nullable=True, index=True)

    parent = relationship("DirectoryObject", remote_side=[id], back_populates="children")
    children = relationship("DirectoryObject", back_populates="parent", cascade="all, delete-orphan")

    user_assignments = relationship(
        "ObjectUserAssignment",
        back_populates="obj",
        cascade="all, delete-orphan",
        foreign_keys="ObjectUserAssignment.object_id",
    )

    group_assignments = relationship(
        "ObjectGroupAssignment",
        back_populates="obj",
        cascade="all, delete-orphan",
        foreign_keys="ObjectGroupAssignment.object_id",
    )

    # ✅ ВАЖНО: явный join, чтобы не путаться между user_id и created_by
    users = relationship(
        "Users",
        secondary="object_user_assignments",
        primaryjoin="DirectoryObject.id == ObjectUserAssignment.object_id",
        secondaryjoin="Users.id == ObjectUserAssignment.user_id",
        foreign_keys="ObjectUserAssignment.object_id, ObjectUserAssignment.user_id",
        viewonly=True,
    )

    groups = relationship(
        "Group",
        secondary="object_group_assignments",
        primaryjoin="DirectoryObject.id == ObjectGroupAssignment.object_id",
        secondaryjoin="Group.id == ObjectGroupAssignment.group_id",
        foreign_keys="ObjectGroupAssignment.object_id, ObjectGroupAssignment.group_id",
        viewonly=True,
    )

    __table_args__ = (
        UniqueConstraint("parent_id", "name", name="uq_object_parent_name"),
        CheckConstraint("parent_id IS NULL OR parent_id <> id", name="ck_object_not_self_parent"),
    )

class ObjectUserAssignment(Base):
    __tablename__ = "object_user_assignments"

    id = Column(Integer, primary_key=True, index=True)

    object_id = Column(Integer, ForeignKey("directory_objects.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    role = Column(String(64), nullable=True)

    # ⚠️ ВТОРАЯ FK на users (создатель назначения)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    obj = relationship("DirectoryObject", back_populates="user_assignments", foreign_keys=[object_id])

    # ✅ назначенный пользователь
    user = relationship("Users", back_populates="object_assignments", foreign_keys=[user_id])

    # ✅ создатель назначения (ВАЖНО: имя relationship должно быть created_by_user)
    created_by_user = relationship(
        "Users",
        back_populates="created_object_assignments",
        foreign_keys=[created_by],
    )

    __table_args__ = (
        UniqueConstraint("object_id", "user_id", name="uq_object_user"),
        Index("ix_object_user_object_id", "object_id"),
        Index("ix_object_user_user_id", "user_id"),
    )


class ObjectGroupAssignment(Base):
    """
    Привязка группы к объекту.
    Пример:
      объект "Москва/Вернадского" <- group_id="Kitchen"
    """
    __tablename__ = "object_group_assignments"

    id = Column(Integer, primary_key=True, index=True)

    object_id = Column(Integer, ForeignKey("directory_objects.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)

    # опционально тип привязки (например "access", "staff", "security")
    binding_type = Column(String(64), nullable=True)

    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    obj = relationship("DirectoryObject", back_populates="group_assignments", foreign_keys=[object_id])
    group = relationship("Group", back_populates="object_assignments", foreign_keys=[group_id])

    __table_args__ = (
        UniqueConstraint("object_id", "group_id", name="uq_object_group"),
        Index("ix_object_group_object_id", "object_id"),
        Index("ix_object_group_group_id", "group_id"),
    )


# ----------------------------
# ADMIN ROLES
# ----------------------------
class AdminRoleAssignment(Base):
    """
    - superuser   : global (scope_group_id = NULL)
    - local_admin : scoped to a group (scope_group_id != NULL)
    """
    __tablename__ = "admin_role_assignments"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(32), nullable=False, index=True)  # 'superuser' | 'local_admin'

    scope_group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)

    is_active = Column(Boolean, nullable=False, default=True, server_default=text("true"))

    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    user = relationship("Users", foreign_keys=[user_id], back_populates="admin_roles")
    creator = relationship("Users", foreign_keys=[created_by], back_populates="created_admin_roles")
    scope_group = relationship("Group", foreign_keys=[scope_group_id], back_populates="admin_role_assignments")

    __table_args__ = (
        UniqueConstraint("user_id", "role", "scope_group_id", name="uq_admin_role_assignment"),
        CheckConstraint("role IN ('superuser', 'local_admin')", name="ck_admin_role_type"),
        CheckConstraint(
            "(role = 'superuser' AND scope_group_id IS NULL) OR "
            "(role = 'local_admin' AND scope_group_id IS NOT NULL)",
            name="ck_admin_role_scope",
        ),
    )


# ----------------------------
# PASSWORDS
# ----------------------------
class PasswordManager(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True, index=True)
    password = Column(String, nullable=False)
    login_password = Column(String, nullable=False)
    description = Column(String, nullable=True)
    about_password = Column(String, nullable=True)

    created_by = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    password_group = Column(Integer, ForeignKey("groups.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    creator = relationship("Users", back_populates="passwords")
    group = relationship("Group", foreign_keys=[password_group], back_populates="passwords")
    shares = relationship("UserPasswordShare", back_populates="password_obj", cascade="all, delete-orphan")


class UserPasswordShare(Base):
    __tablename__ = "user_password_share"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    password_id = Column(Integer, ForeignKey("passwords.id", ondelete="CASCADE"), nullable=False, index=True)
    granted_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    __table_args__ = (
        UniqueConstraint("user_id", "password_id", name="uq_user_password_share"),
    )

    user = relationship("Users", foreign_keys=[user_id], back_populates="password_shares")
    granted_by_user = relationship("Users", foreign_keys=[granted_by], back_populates="granted_password_shares")
    password_obj = relationship("PasswordManager", back_populates="shares")


# ----------------------------
# REFRESH TOKENS
# ----------------------------
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)

    revoked = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)

    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    revoked_at = Column(TIMESTAMP(timezone=True), nullable=True)

    user_agent = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)

    user = relationship("Users", back_populates="refresh_tokens")