from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from src.DB.config import db_config
from src.DB.models import Model

# Создаем асинхронный engine
engine = create_async_engine(
    db_config.DATABASE_URL,
    echo=db_config.DB_ECHO,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,
)

# Создаем фабрику сессий
SessionFactory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False
)

async def get_db() -> AsyncSession:
    """
    Dependency для получения асинхронной сессии БД
    """
    async with SessionFactory() as session:
        try:
            yield session
        finally:
            await session.close()

async def create_tables():
    """
    Создание всех таблиц
    """
    async with engine.begin() as conn:
        await conn.run_sync(Model.metadata.create_all, checkfirst=True)
    print("✅ Таблицы созданы")

async def delete_tables():
    """
    Удаление всех таблиц (только для тестов!)
    """
    async with engine.begin() as conn:
        await conn.run_sync(Model.metadata.drop_all)
    print("🗑️ Таблицы удалены")