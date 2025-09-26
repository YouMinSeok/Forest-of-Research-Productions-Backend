from passlib.context import CryptContext
from fastapi import HTTPException, Cookie, Header, Depends
from typing import Optional
import jwt  # PyJWT 사용
from jwt import ExpiredSignatureError, InvalidTokenError
from app.core.config import settings
from app.models.user import User
from app.models.permission import UserRole
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.core.database import get_database
from bson import ObjectId
from datetime import datetime

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

async def get_current_user(access_token: str = Cookie(None), db: AsyncIOMotorDatabase = Depends(get_database)):
    """
    쿠키 "access_token"에서 JWT 토큰을 읽어 사용자 정보를 반환합니다.
    """
    if not access_token:
        raise HTTPException(status_code=401, detail="토큰이 제공되지 않았습니다.")
    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="토큰 정보가 부족합니다(sub).")
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

    # 데이터베이스에서 사용자 정보 조회
    try:
        user_doc = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user_doc:
            raise HTTPException(status_code=401, detail="사용자를 찾을 수 없습니다.")

        # User 객체 생성
        user = User(
            id=str(user_doc["_id"]),
            name=user_doc.get("name", "Unknown"),
            email=user_doc.get("email", "user@example.com"),
            password=user_doc.get("password", ""),
            role=UserRole(user_doc.get("role", "student")),
            permissions=user_doc.get("permissions", []),
            is_active=user_doc.get("is_active", True),
            is_admin=user_doc.get("is_admin", False),
            created_at=user_doc.get("created_at", datetime.utcnow()),
            last_login=user_doc.get("last_login"),
            student_number=user_doc.get("student_number")
        )
        return user

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"사용자 정보 조회 실패: {str(e)}")

def get_current_user_optional(access_token: str = Cookie(None)) -> Optional[dict]:
    """
    선택적 사용자 인증: 토큰이 유효하면 사용자 정보를 반환하고, 그렇지 않으면 None을 반환합니다.
    로그인하지 않은 사용자도 접근할 수 있는 API에서 사용합니다.
    """
    if not access_token:
        return None
    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        user_name: str = payload.get("name")
        if user_id is None or user_name is None:
            return None
        return {"id": user_id, "name": user_name}
    except (ExpiredSignatureError, InvalidTokenError):
        return None
