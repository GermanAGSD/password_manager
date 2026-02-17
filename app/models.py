from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import text
from sqlalchemy.sql.sqltypes import TIMESTAMP
from app.database import Base

class Users(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    history = Column(String, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text('now()'))
    # Внешний ключ, ссылающийся на id таблицы Type
    grouptype_id = Column(Integer, ForeignKey('groups.id'), nullable=True)
    issuperuser = Column(Boolean, default=False)
    domainpass = Column(String, nullable=False)
    passwords = relationship("PasswordManager", back_populates="creator")
    # Связь с группами
    groups = relationship("Group", secondary="user_group_association", back_populates="users")

class UserGroupAssociation(Base):
    __tablename__ = "user_group_association"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    group_id = Column(Integer, ForeignKey("groups.id"))

class Group(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    users = relationship("Users", secondary="user_group_association", back_populates="groups")
    visible = Column(Boolean, nullable=True, default=True)

class PasswordManager(Base):
    __tablename__ = "passwords"
    id = Column(Integer, primary_key=True, index=True)
    password = Column(String, nullable=False)
    login_password = Column(String, nullable=False)
    description = Column(String, nullable=True)
    about_password = Column(String, nullable=True)
    # Внешний ключ на пользователя, создавшего запись
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Обратная связь
    creator = relationship("Users", back_populates="passwords")
