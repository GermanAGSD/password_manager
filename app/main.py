import uvicorn
from fastapi.security import OAuth2PasswordBearer
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, Form, HTTPException, Response, Cookie, status
from app import schemas, models
from app import database
from sqlalchemy.orm import Session
import secrets
import hashlib
from passlib.context import CryptContext
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from app.routers import ldap_auth
from app.database import engine
models.Base.metadata.create_all(bind=engine)
app = FastAPI()

# Для zabbix отслеживать жив ли сервер
@app.get("/health",status_code=status.HTTP_200_OK)
async def check_server():
    return {"message": "its work"}

app.include_router(ldap_auth.router)

if __name__ == "__main__":
    uvicorn.run(app, host="192.168.0.25", port=8000)