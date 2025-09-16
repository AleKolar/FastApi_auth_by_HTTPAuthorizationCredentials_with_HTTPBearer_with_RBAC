from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.DB.models import UserOrm
from src.security import get_password_hash

from typing import Optional




async def get_user_by_email(db: AsyncSession, email: str) -> Optional[UserOrm]:
    result = await db.execute(select(UserOrm).where(UserOrm.email == email))
    return result.scalar_one_or_none()

async def get_user_by_username(db: AsyncSession, username: str) -> Optional[UserOrm]:
    result = await db.execute(select(UserOrm).where(UserOrm.username == username))
    return result.scalar_one_or_none()

async def get_user_by_login(db: AsyncSession, login: str) -> Optional[UserOrm]:
    result = await db.execute(select(UserOrm).where(UserOrm.login == login))
    return result.scalar_one_or_none()

async def create_user(db: AsyncSession, user_data) -> UserOrm:
    hashed_password = get_password_hash(user_data.password)
    db_user = UserOrm(
        username=user_data.username,
        email=user_data.email,
        age=user_data.age,
        login=user_data.login,
        hashed_password=hashed_password
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

async def authenticate_user(db: AsyncSession, login: str, password: str) -> Optional[UserOrm]:
    user = await get_user_by_login(db, login)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user