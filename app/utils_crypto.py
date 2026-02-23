from cryptography.fernet import Fernet, InvalidToken
from app.settings import settings

# В .env:
# PASSWORDS_ENCRYPTION_KEY=... (ключ Fernet)
fernet = Fernet(settings.passwords_encryption_key.encode("utf-8"))


def encrypt_secret(value: str) -> str:
    if value is None:
        return None
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    if value is None:
        return None
    try:
        return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        # Если в БД еще есть старые plaintext записи (до миграции), можно временно вернуть как есть:
        # return value
        raise ValueError("Decrypt failed")