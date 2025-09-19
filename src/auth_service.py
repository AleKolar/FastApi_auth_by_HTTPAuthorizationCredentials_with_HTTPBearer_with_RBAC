from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from src.repository import save_refresh_token, get_user_by_login
from src.security import create_access_token, create_refresh_token


async def create_token_pair_service(username: str, db: AsyncSession) -> dict:
    """Сервис для создания пары токенов"""
    user = await get_user_by_login(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(data={"sub": username})

    await save_refresh_token(db, refresh_token, username)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }