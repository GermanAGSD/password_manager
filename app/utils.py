from passlib.context import CryptContext

# Инициализация CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Функция для хэширования пароля
def hash_password(password: str):
    # Обрезаем пароль до 72 символов, если он длиннее
    if len(password) > 72:
        password = password[:72]
    return pwd_context.hash(password)

# Функция для проверки пароля
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)