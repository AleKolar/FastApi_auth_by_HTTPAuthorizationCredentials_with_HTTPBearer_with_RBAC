import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

from src.DB.database import create_tables, get_db
from src.dependencies import get_current_user, get_refresh_token_user
from src.repository import get_user_by_email, get_user_by_login, create_user, authenticate_user

from src.schemas import UserResponse, UserCreate, Token, UserLogin
from src.security import create_token_pair
from starlette.responses import FileResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("ENVIRONMENT") == "development":
        await create_tables()
        print("✅ Таблицы созданы (development mode)")
    yield
    print("🛑 Приложение завершает работу")
app = FastAPI(
    title="JWT Auth API",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
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
@app.post("/auth/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    # Проверка существования пользователя
    if await get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if await get_user_by_login(db, user.login):
        raise HTTPException(status_code=400, detail="Login already taken")

    return await create_user(db, user)


@app.post("/auth/login", response_model=Token)
async def login_user(user_data: UserLogin, db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, user_data.login, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect login or password",
        )

    return create_token_pair(user.username)


@app.post("/auth/refresh", response_model=Token)
async def refresh_token(token_data: Token, db: AsyncSession = Depends(get_db)):
    user = await get_refresh_token_user(token_data.refresh_token, db)
    return create_token_pair(user.username)


@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: UserResponse = Depends(get_current_user)):
    return current_user


@app.get("/protected")
async def protected_route(current_user: UserResponse = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}!", "user_id": current_user.id}


app.include_router(main_router)
app.include_router(user_router)

# myvenv\Scripts\activate
#
# uvicorn main:app --reload
