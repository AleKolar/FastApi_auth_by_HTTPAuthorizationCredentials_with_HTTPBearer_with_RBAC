import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.DB.database import create_tables, get_db
from src.DB.models import UserOrm
from src.dependencies import get_current_user, get_refresh_token_user
from src.repository import get_user_by_email, get_user_by_login, create_user, authenticate_user

from src.schemas import UserResponse, UserCreate, Token, UserLogin
from src.security import create_token_pair
from starlette.responses import FileResponse

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


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
)

main_router = APIRouter(tags=["main"])
user_router = APIRouter(tags=["users"], prefix="/users")

# Main routers
@main_router.get("/health")
async def health():
    return {"status": "ok"}


@main_router.get("/")
async def root():
    return FileResponse("static/index.html")

# Users routers
@user_router.post("/auth/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    # Проверка существования пользователя
    if await get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if await get_user_by_login(db, user.login):
        raise HTTPException(status_code=400, detail="Login already taken")

    user_db = await create_user(db, user)
    return {
        "message": "New user created",
        "user": UserResponse.model_validate(user_db)  # Опционально
    }


@user_router.post("/auth/login", response_model=Token)
async def login_user(user_data: UserLogin, db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, user_data.login, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect login or password",
        )

    return create_token_pair(user.login)


@user_router.post("/auth/refresh", response_model=Token)
async def refresh_token(token_data: Token, db: AsyncSession = Depends(get_db)):
    user = await get_refresh_token_user(token_data.refresh_token, db)
    return create_token_pair(user.username)


@user_router.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: UserResponse = Depends(get_current_user)):
    return current_user


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

app.include_router(main_router)
app.include_router(user_router)

# myvenv\Scripts\activate
#
# uvicorn main:app --reload

# {
#   "login": "AleKolar_33",
#   "password": "Mn1471979!_Mn"
# }