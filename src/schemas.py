import re
import uuid
from typing import List

from pydantic import BaseModel, Field, ConfigDict, field_validator, computed_field
from datetime import datetime

# Будем возвращать валидированный объект Pydantic CommonHeaders
# с заголовками + message + timestamp
class CommonHeaders(BaseModel):
    model_config = ConfigDict(extra='allow')

    user_agent: str | None = Field(None, alias="User-Agent")
    accept_language: str | None = Field(None, alias="Accept-Language")
    x_server_time: datetime = Field(default_factory=datetime.now)
    message: str = "Добро пожаловать! Ваши заголовки успешно обработаны."

    @field_validator('accept_language')
    def validate_pattern(cls, v: str) -> str:
        pattern = "en-US,ru-RU,en;q=0.9,es;q=0.8"
        if v != pattern:
            raise ValueError(f"Accept-Language does not match pattern: {pattern}")
        return v


LOGIN_PATTERN = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d_]{4,}$"
VALID_ROLES = {"user", "admin"}

class UserBase(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    email: str = Field(..., min_length=1, max_length=255)
    age: int = Field(..., ge=0, le=150)
    login: str = Field(..., min_length=4, max_length=11)
    roles: List[str] = Field(default=["user"])

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @field_validator("login")
    def login_pattern(cls, v):
        if not re.match(LOGIN_PATTERN, v):
            raise ValueError(
                "Login must contain at least one lowercase letter, "
                "one uppercase letter, and one digit; "
                "length >= 4; ASCII letters and digits only."
            )
        return v

    @field_validator("password")
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(char.isdigit() for char in v):
            raise ValueError("Password must contain at least one digit")
        if not any(char.isupper() for char in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(char.islower() for char in v):
            raise ValueError("Password must contain at least one lowercase letter")
        return v

    @computed_field
    @property
    def is_adult(self) -> bool:
        return self.age >= 18

class UserLogin(BaseModel):
    login: str
    password: str

class UserResponse(UserBase):
    id: uuid.UUID
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Token
class TokenRefresh(BaseModel):
    refresh_token: str

class Token(TokenRefresh):
    access_token: str
    token_type: str = "bearer"

# Для данных в токене (опционально)
class TokenData(BaseModel):
    username: str | None = None
    roles: List[str] = []
    exp: datetime | None = None
    type: str | None = None  # "access" или "refresh"