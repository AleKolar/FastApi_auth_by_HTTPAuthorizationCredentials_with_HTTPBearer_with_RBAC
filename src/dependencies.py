import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import ExpiredSignatureError
from sqlalchemy.ext.asyncio import AsyncSession

from src import schemas
from src.DB.database import get_db
from src.DB.models import UserOrm
from src.repository import get_user_by_login
from src.schemas import UserResponse
from src.security import verify_access_token, verify_refresh_token

http_bearer = HTTPBearer(auto_error=False)

logger = logging.getLogger(__name__)

async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
        db: AsyncSession = Depends(get_db)
) -> UserResponse:
    logger.debug(f"Credentials object: {credentials}")
    logger.debug(f"Credentials type: {type(credentials)}")
    if credentials is None:
        logger.debug("No credentials provided - check Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    logger.debug(f"Token received: {token}")
    try:
        payload = verify_access_token(token)
        logger.debug(f"Token payload: {payload}")
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        username: str = payload.get("sub")
        logger.debug(f"Username from token: '{username}'")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = await get_user_by_login(db, login=username)
        if user is None:
            logger.debug(f"User not found for username: '{username}'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        logger.debug(f"User found: {user.username}")
        return schemas.UserResponse.model_validate(user)

    except ExpiredSignatureError:
        logger.debug("Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token", error_description="The access token expired"'},
        )

async def get_refresh_token_user(
        refresh_token: str,
        db: AsyncSession = Depends(get_db)
) -> UserOrm:
    payload = verify_refresh_token(refresh_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload",
        )

    user = await get_user_by_login(db, login=username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user

