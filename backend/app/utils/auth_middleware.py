from functools import wraps
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Callable, List, Optional
from ..models.permission import PermissionType, UserRole
from ..models.user import User
from .permissions import PermissionManager
import jwt
import os

security = HTTPBearer()
security_optional = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """JWT 토큰에서 현재 사용자 정보 추출"""
    try:
        from ..core.database import db
        from ..core.config import settings

        token = credentials.credentials

        # JWT 토큰 디코딩
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        email = payload.get("email")

        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="토큰에서 사용자 정보를 찾을 수 없습니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 데이터베이스에서 사용자 정보 조회
        user_data = await db.users.find_one({"email": email})

        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="사용자를 찾을 수 없습니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user_data.get("is_active", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="비활성화된 계정입니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # User 모델로 변환
        user = User(
            id=str(user_data["_id"]),
            name=user_data["name"],
            student_number=user_data.get("student_number"),
            email=user_data["email"],
            password=user_data["password"],
            role=UserRole(user_data.get("role", "student")),
            permissions=user_data.get("permissions", []),
            is_active=user_data.get("is_active", False),
            is_admin=user_data.get("is_admin", False),
            created_at=user_data["created_at"],
            last_login=user_data.get("last_login")
        )

        return user

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="토큰이 만료되었습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 인증 토큰입니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="인증 처리 중 오류가 발생했습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_permission(required_permission: PermissionType):
    """특정 권한이 필요한 엔드포인트에 사용하는 데코레이터"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if not PermissionManager.has_permission(current_user, required_permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"이 작업을 수행할 권한이 없습니다. 필요한 권한: {required_permission.value}"
                )
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

def require_role(required_roles: List[UserRole]):
    """특정 역할이 필요한 엔드포인트에 사용하는 데코레이터"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if current_user.role not in required_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"이 작업을 수행할 권한이 없습니다. 필요한 역할: {[role.value for role in required_roles]}"
                )
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

def require_admin():
    """어드민 권한이 필요한 엔드포인트에 사용하는 데코레이터"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if not current_user.is_admin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="관리자 권한이 필요합니다."
                )
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional)) -> Optional[User]:
    """JWT 토큰에서 현재 사용자 정보 추출 (선택적 - 토큰이 없어도 None 반환)"""
    try:
        if not credentials:
            return None

        from ..core.database import db
        from ..core.config import settings

        token = credentials.credentials

        # JWT 토큰 디코딩
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        email = payload.get("email")

        if not email:
            return None

        # 데이터베이스에서 사용자 정보 조회
        user_data = await db.users.find_one({"email": email})

        if not user_data or not user_data.get("is_active", False):
            return None

        # User 모델로 변환
        user = User(
            id=str(user_data["_id"]),
            name=user_data["name"],
            student_number=user_data.get("student_number"),
            email=user_data["email"],
            password=user_data["password"],
            role=UserRole(user_data.get("role", "student")),
            permissions=user_data.get("permissions", []),
            is_active=user_data.get("is_active", False),
            is_admin=user_data.get("is_admin", False),
            created_at=user_data["created_at"],
            last_login=user_data.get("last_login")
        )

        return user

    except (jwt.ExpiredSignatureError, jwt.PyJWTError, Exception):
        return None

async def can_manage_user_check(target_user_id: str, current_user: User = Depends(get_current_user)):
    """사용자 관리 권한 체크"""
    try:
        from ..core.database import db
        from bson import ObjectId

        # 실제 데이터베이스에서 대상 사용자 정보 조회
        target_user_data = await db.users.find_one({"_id": ObjectId(target_user_id)})

        if not target_user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="대상 사용자를 찾을 수 없습니다."
            )

        # User 모델로 변환
        target_user = User(
            id=str(target_user_data["_id"]),
            name=target_user_data["name"],
            student_number=target_user_data.get("student_number"),
            email=target_user_data["email"],
            password=target_user_data["password"],
            role=UserRole(target_user_data.get("role", "student")),
            permissions=target_user_data.get("permissions", []),
            is_active=target_user_data.get("is_active", False),
            is_admin=target_user_data.get("is_admin", False),
            created_at=target_user_data["created_at"],
            last_login=target_user_data.get("last_login")
        )

        if not PermissionManager.can_manage_user(current_user, target_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="해당 사용자를 관리할 권한이 없습니다."
            )

        return target_user

    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="사용자 권한 확인 중 오류가 발생했습니다."
        )
