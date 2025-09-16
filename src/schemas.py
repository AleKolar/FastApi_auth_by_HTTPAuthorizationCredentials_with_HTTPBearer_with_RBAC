import re
import uuid
from pydantic import BaseModel, Field, ConfigDict, field_validator, computed_field
from datetime import datetime

LOGIN_PATTERN = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d_]{4,}$"

class UserBase(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    email: str = Field(..., min_length=1, max_length=255)
    age: int = Field(..., ge=0, le=150)
    login: str = Field(..., min_length=4, max_length=11)

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

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None