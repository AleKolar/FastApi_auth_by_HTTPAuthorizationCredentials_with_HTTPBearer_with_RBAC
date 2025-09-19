from functools import wraps
from typing import List, Callable

from fastapi import HTTPException
from starlette import status


def permission(required_roles: List[str], allow_admin: bool = True):
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Требуется аутентификация"
                )
            user_roles = getattr(current_user, 'roles', [])
            if allow_admin and 'admin' in user_roles:
                return await func(*args, **kwargs)

                # Проверка требуемых ролей
            if not any(role in user_roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Недостаточно прав. Требуются роли: {required_roles}"
                )

            return await func(*args, **kwargs)
        return wrapper

    return decorator


