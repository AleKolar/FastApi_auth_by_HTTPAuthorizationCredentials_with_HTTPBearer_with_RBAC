import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext

# Настройки JWT
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "fallback-refresh-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет соответствие пароля и хеша"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Создает хеш пароля"""
    return pwd_context.hash(password)

def _create_token(
    data: dict,
    secret: str,
    expires_delta: timedelta,
    token_type: str
) -> str:
    """Внутренняя функция для создания токена"""
    to_encode = data.copy()
    expire = datetime.now() + expires_delta
    to_encode.update({"exp": expire, "type": token_type})
    return jwt.encode(to_encode, secret, algorithm=ALGORITHM)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Создает access token"""
    delta = expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return _create_token(data, SECRET_KEY, delta, "access")

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Создает refresh token"""
    delta = expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return _create_token(data, REFRESH_SECRET_KEY, delta, "refresh")

def verify_access_token(token: str) -> Optional[dict]:
    """Проверяет и декодирует access token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload if payload.get("type") == "access" else None
    except JWTError:
        return None

def verify_refresh_token(token: str) -> Optional[dict]:
    """Проверяет и декодирует refresh token"""
    try:
        payload = jwt.decode(token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        return payload if payload.get("type") == "refresh" else None
    except JWTError:
        return None

def create_token_pair(username: str) -> dict:
    """Создает пару access и refresh токенов"""
    return {
        "access_token": create_access_token(data={"sub": username}),
        "refresh_token": create_refresh_token(data={"sub": username}),
        "token_type": "bearer"
    }

