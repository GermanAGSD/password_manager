# from pydantic_settings import BaseSettings
#
# class Settings(BaseSettings):
#     database_hostname: str
#     database_port: str
#     database_password: str
#     database_name: str
#     database_username: str
#     secret_key: str
#     algorithm: str
#     access_token_expire_minutes: int
#     domain_password: str
#     passwords_encryption_key: str
#
#     class Config:
#         env_file = "../.env"
#
#
# settings = Settings()
# app/settings.py
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent  # корень проекта (где app/)
ENV_PATH = BASE_DIR / ".env"

class Settings(BaseSettings):
    database_hostname: str
    database_port: str
    database_password: str
    database_name: str
    database_username: str
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    domain_password: str
    passwords_encryption_key: str

    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH),        # или просто ".env", если файл в WORKDIR
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

settings = Settings()