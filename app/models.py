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


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True)
    history = Column(String, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    primary_group_id = Column(Integer, ForeignKey("groups.id", ondelete="SET NULL"), nullable=True, index=True)

    # ⚠️ legacy поле (можно оставить временно, но не использовать в новой логике)
    issuperuser = Column(Boolean, nullable=False, default=False, server_default=text("false"))

    domainpass = Column(String, nullable=False)

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

    refresh_tokens = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )

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

    # ✅ Новая отдельная модель ролей админов
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


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)

    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    visible = Column(Boolean, nullable=False, default=True, server_default=text("true"))

    # folder / restaurant / group
    node_type = Column(String(32), nullable=False, default="group", server_default=text("'group'"), index=True)

    parent_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    parent = relationship("Group", remote_side=[id], back_populates="children")
    children = relationship("Group", back_populates="parent", cascade="all, delete-orphan")

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

    passwords = relationship("PasswordManager", back_populates="group")

    # локальные админы, привязанные к этой группе (обычно restaurant)
    admin_role_assignments = relationship(
        "AdminRoleAssignment",
        back_populates="scope_group",
        foreign_keys="AdminRoleAssignment.scope_group_id",
    )

    __table_args__ = (
        UniqueConstraint("parent_id", "name", name="uq_group_parent_name"),
        CheckConstraint("parent_id IS NULL OR parent_id <> id", name="ck_group_not_self_parent"),
        CheckConstraint("node_type IN ('folder', 'restaurant', 'group')", name="ck_group_node_type"),
    )


class AdminRoleAssignment(Base):
    """
    Отдельная модель ролей администраторов:
    - superuser   : глобальный суперпользователь (scope_group_id = NULL)
    - local_admin : локальный админ (scope_group_id = группа/ресторан)
    """
    __tablename__ = "admin_role_assignments"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(32), nullable=False, index=True)  # 'superuser' | 'local_admin'

    # Для local_admin — на какой ресторан/группу распространяются права
    # Для superuser должно быть NULL
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
        # superuser -> scope_group_id IS NULL, local_admin -> scope_group_id IS NOT NULL
        CheckConstraint(
            "(role = 'superuser' AND scope_group_id IS NULL) OR "
            "(role = 'local_admin' AND scope_group_id IS NOT NULL)",
            name="ck_admin_role_scope",
        ),
    )


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