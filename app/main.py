import uvicorn
from fastapi import FastAPI, status
from app import schemas, models
from app.routers import ldap_auth, group_ldap, users, objects, object_assignments, admin
from app.database import engine
from fastapi.middleware.cors import CORSMiddleware

models.Base.metadata.create_all(bind=engine)
app = FastAPI()
# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Укажите домены, которым разрешено отправлять запросы
    allow_credentials=True,
    allow_methods=["*"],  # Разрешить все методы
    allow_headers=["*"],  # Разрешить все заголовки
)

# Для zabbix отслеживать жив ли сервер
@app.get("/health",status_code=status.HTTP_200_OK)
async def check_server():
    return {"message": "its work"}

app.include_router(ldap_auth.router)
app.include_router(group_ldap.router)
app.include_router(users.router)
app.include_router(objects.router)
app.include_router(object_assignments.router)
app.include_router(admin.router)
if __name__ == "__main__":
    uvicorn.run(app, host="192.168.0.25", port=8000)