from sqlalchemy.ext.asyncio import AsyncSession

from src.repository import save_refresh_token
from src.security import create_access_token, create_refresh_token


async def create_token_pair_service(username: str, db: AsyncSession) -> dict:
    """Сервис для создания пары токенов"""
    access_token = create_access_token(data={"sub": username})
    refresh_token = create_refresh_token(data={"sub": username})

    await save_refresh_token(db, refresh_token, username)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }