import uuid
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from typing import Optional, Dict

from src.DB.models import UserOrm, RefreshTokenOrm
from src.security import get_password_hash, verify_password, get_refresh_token_hash, verify_refresh_token_hash


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[UserOrm]:
    result = await db.execute(select(UserOrm).where(UserOrm.email == email))
    return result.scalar_one_or_none()

async def get_user_by_username(db: AsyncSession, username: str): # -> Optional[UserOrm]:
    result = await db.execute(select(UserOrm).where(UserOrm.username == username))
    return result.scalar_one_or_none()

async def get_user_by_login(db: AsyncSession, login: str) -> Optional[UserOrm]:
    result = await db.execute(select(UserOrm).where(UserOrm.login == login))
    return result.scalar_one_or_none()

async def create_user(db: AsyncSession, user_data) -> dict[str, str | UserOrm]:
    hashed_password = get_password_hash(user_data.password)
    db_user = UserOrm(
        username=user_data.username,
        email=user_data.email,
        age=user_data.age,
        login=user_data.login,
        hashed_password=hashed_password,
        roles=user_data.roles
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


# 🔄 Новые функции для работы с refresh токенами, после того, как в БД стали хранить token_hash
async def save_refresh_token(db: AsyncSession, refresh_token: str, username: str):
    """Сохраняет refresh токен в БД"""
    user = await get_user_by_login(db, username)
    if not user:
        raise ValueError(f"User {username} not found")

    # Сначала удаляем старые токены пользователя
    user_id: uuid.UUID = user.id
    await delete_user_refresh_tokens(db, user_id)

    # Создаем новый токен
    token_hash = get_refresh_token_hash(refresh_token)
    expires_at = datetime.now() + timedelta(days=7)  # 7 дней

    db_token = RefreshTokenOrm(
        token_hash=token_hash,
        user_id=user.id,
        expires_at=expires_at
    )
    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)
    return db_token


async def verify_refresh_token_in_db(db: AsyncSession, refresh_token: str, username: str) -> bool:
    """Проверяет существование refresh токена в БД"""
    user = await get_user_by_login(db, username)
    if not user:
        return False

    result = await db.execute(
        select(RefreshTokenOrm).where(
            RefreshTokenOrm.user_id == user.id,
            RefreshTokenOrm.expires_at > datetime.now()
        )
    )
    db_tokens = result.scalars().all()

    for db_token in db_tokens:
        if verify_refresh_token_hash(refresh_token, db_token.token_hash):
            return True

    return False


async def delete_refresh_token(db: AsyncSession, refresh_token: str, username: str):
    """Удаляет refresh токен из БД"""
    user = await get_user_by_login(db, username)
    if not user:
        return

    result = await db.execute(
        select(RefreshTokenOrm).where(
            RefreshTokenOrm.user_id == user.id
        )
    )
    db_tokens = result.scalars().all()

    for db_token in db_tokens:
        if verify_refresh_token_hash(refresh_token, db_token.token_hash):
            await db.delete(db_token)
            await db.commit()
            return


async def delete_user_refresh_tokens(db: AsyncSession, user_id: int):
    """Удаляет все refresh токены пользователя"""
    await db.execute(
        delete(RefreshTokenOrm).where(RefreshTokenOrm.user_id == user_id)
    )
    await db.commit()



