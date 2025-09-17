import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, APIRouter, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from src import schemas
from src.DB.database import create_tables, get_db
from src.DB.models import UserOrm
from src.auth_service import create_token_pair_service
from src.dependencies import get_current_user, http_bearer
from src.repository import get_user_by_login, create_user, authenticate_user, get_user_by_email, \
    verify_refresh_token_in_db, delete_refresh_token

from src.schemas import UserResponse, UserCreate, Token, UserLogin
from src.security import verify_refresh_token, verify_access_token
from starlette.responses import FileResponse

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("ENVIRONMENT") == "development":
        await create_tables()
        print("✅ Таблицы созданы (development mode)")
    yield
    print("🛑 Приложение завершает работу")
app = FastAPI(
    title="JWT Auth API",
    lifespan=lifespan,
    swagger_ui_parameters={
        "persistAuthorization": True,  # Сохраняет авторизацию между перезагрузками
        "tryItOutEnabled": True,       # Включает кнопку "Try it out" по умолчанию
        "displayRequestDuration": True, # Показывает время выполнения запросов
        # "docExpansion": "none",           # Сворачивает документацию по умолчанию
        # "filter": True,                   # Включает поиск по API
        # "showExtensions": True,           # Показывает расширения
        # "showCommonExtensions": True,     # Показывает common extensions
    }
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # expose_headers=["*"], # какие заголовки exposed to browser
    # max_age=600,          # кеширование preflight requests (в секундах)
)

main_router = APIRouter(tags=["main"])
header_router = APIRouter(tags=["headers"], prefix="/headers")
user_router = APIRouter(tags=["users"], prefix="/users")

# Main routers
@main_router.get("/health")
async def health():
    return {"status": "ok"}


@main_router.get("/")
async def root():
    return FileResponse("static/index.html")

# !!! Header !!!
# Возвращает произвольный JSON dict , без валидации, без message, без timestamp
@header_router.get("/headers/v1")
async def get_headers(
        user_agent: str | None = Header(None, alias="User-Agent"),
        accept_language: str | None = Header(None, alias="Accept-Language")
):
    # Проверяем, что заголовки присутствуют
    if user_agent is None:
        raise HTTPException(
            status_code=400,
            detail="User-Agent header is required"
        )

    if accept_language is None:
        raise HTTPException(
            status_code=400,
            detail="Accept-Language header is required"
        )

    # Возвращаем заголовки в формате JSON
    return {
        "User-Agent": user_agent,
        "Accept-Language": accept_language
    }

# Возвращает валидированный объект Pydantic CommonHeaders
# с заголовками + message + timestamp
@header_router.get("/headers", response_model=schemas.CommonHeaders)
async def get_headers(
    user_agent: str | None = Header(None, alias="User-Agent"),
    accept_language: str | None = Header(None, alias="Accept-Language")
):
    # 1. Проверяем обязательные заголовки
    if user_agent is None:
        raise HTTPException(
            status_code=400,
            detail="User-Agent header is required"
        )

    if accept_language is None:
        raise HTTPException(
            status_code=400,
            detail="Accept-Language header is required"
        )

    # 2. Устанавливаем сообщение (правильное обращение)
    final_message = "Добро пожаловать! Ваши заголовки успешно обработаны."

    # 3. Создаем объект модели со ВСЕМИ полями
    headers = schemas.CommonHeaders(
        user_agent=user_agent,
        accept_language=accept_language,
        message=final_message,
        x_server_time=datetime.now()  # ← Добавляем timestamp
    )

    # 4. Проверяем паттерн (используем значение)
    try:
        is_valid = headers.validate_pattern  # ← Присваиваем значение!
        if is_valid:
            logger.info("Accept-Language соответствует паттерну")
        else:
            logger.warning("Accept-Language не соответствует паттерну")
    except ValueError as e:
        logger.warning(f"Accept-Language не соответствует паттерну: {e}")

    # 5. Возвращаем объект модели
    return headers

# Users routers
@user_router.post("/auth/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    if await get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if await get_user_by_login(db, user.login):
        raise HTTPException(status_code=400, detail="Login already taken")

    user_db = await create_user(db, user)
    return {
        "message": "New user created",
        "user": UserResponse.model_validate(user_db)
    }

@user_router.post("/auth/login", response_model=Token)
async def login_user(user_data: UserLogin, db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, user_data.login, user_data.password)
    if not user:
        logger.warning(f"Failed login attempt for: {user_data.login}")
        raise HTTPException(status_code=401, detail="Incorrect login or password")

    logger.info(f"Successful login for: {user_data.login}")
    return await create_token_pair_service(user.login, db)

@user_router.post("/auth/refresh", response_model=Token)
async def refresh_token(
    token_data: schemas.TokenRefresh,  # Используем новую схему только с refresh_token
    db: AsyncSession = Depends(get_db)
):
    # Проверяем валидность refresh токена
    payload = verify_refresh_token(token_data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # Проверяем существование токена в БД
    if not await verify_refresh_token_in_db(db, token_data.refresh_token, username):
        raise HTTPException(status_code=401, detail="Refresh token not found or expired")

    # Удаляем использованный токен
    await delete_refresh_token(db, token_data.refresh_token, username)

    # Создаем новую пару токенов
    return await create_token_pair_service(username, db)


@user_router.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: UserResponse = Depends(get_current_user)):
    """
    Получение информации о текущем пользователе,
    требует валидный access token
    """
    return current_user

# !!! Если надо !!!
# Для access token = List["access", "refresh"],
# проверяет тип токена и валидность
@user_router.get("/protected_resource")
async def protected_resource(
        credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
        db: AsyncSession = Depends(get_db)
):
    """
    Защищенный маршрут - только с access token,
    проверяет тип токена и валидность
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # Проверяем, что токен является access token
    payload = verify_access_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    user = await get_user_by_login(db, login=username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return {
        "message": f"Access granted to protected resource for user: {user.username}",
        "user_id": user.id,
        "username": user.username
    }

@user_router.get("/protected")
async def protected_route(current_user: UserResponse = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}!", "user_id": current_user.id}

@user_router.get("/debug/users")
async def debug_users(db: AsyncSession = Depends(get_db)):
    users = await db.execute(select(UserOrm))
    return [
        {
            "id": u.id,
            "username": u.username,
            "login": u.login,
            "email": u.email
        } for u in users.scalars().all()
    ]

# Для middleware, для логирования запросов
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code}")
    return response
app.include_router(main_router)
app.include_router(user_router)
app.include_router(header_router)

# myvenv\Scripts\activate
#
# uvicorn main:app --reload

# {
#   "login": "AleKolar_33",
#   "password": "Mn1471979!_Mn"
# }