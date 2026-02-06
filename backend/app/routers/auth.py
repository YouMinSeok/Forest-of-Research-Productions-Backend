# app/routers/auth.py
import os
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks, status, Response, Cookie, Header
from bson import ObjectId
import jwt  # PyJWT

from app.schemas.user import UserCreate, UserLogin
from app.models.user import FindUsernameRequest, PasswordResetRequest, VerifyResetCodeRequest, NewPasswordRequest
from app.core.database import db
from app.core.config import settings
from app.utils.email import generate_verification_code, send_verification_email
from app.utils.security import get_password_hash, verify_password

router = APIRouter()
logger = logging.getLogger("auth_router")

# 환경 구분
is_local = settings.DEBUG


def get_cookie_options():
    # (프론트는 Authorization 헤더를 쓰지만, 여기 함수는 기존 흐름 호환용으로 남겨둠)
    if is_local:
        return {
            "httponly": True,
            "max_age": 2592000,  # 30일
            "secure": False,
            "samesite": "Lax",
            "path": "/"
        }
    else:
        return {
            "httponly": True,
            "max_age": 2592000,  # 30일
            "secure": True,
            "samesite": "None",
            "path": "/"
        }


def fix_mongo_object_ids(obj):
    if isinstance(obj, list):
        return [fix_mongo_object_ids(item) for item in obj]
    elif isinstance(obj, dict):
        new_obj = {}
        for key, value in obj.items():
            if isinstance(value, ObjectId):
                new_obj[key] = str(value)
            else:
                new_obj[key] = fix_mongo_object_ids(value)
        return new_obj
    return obj


def _extract_token_from_auth_header(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() == "bearer" and token:
            return token.strip()
    except ValueError:
        return None
    return None


# =========================
# 시간 유틸 (UTC 고정)
# =========================
def _utcnow() -> datetime:
    """timezone-aware UTC 현재 시각"""
    return datetime.now(timezone.utc)


def _ensure_aware_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    DB(Mongo)에서 꺼낸 datetime은 tzinfo 없는 naive로 오는 경우가 많습니다.
    이 경우 'UTC로 저장된 naive'라고 가정하고 UTC aware로 변환합니다.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_ts(dt: datetime) -> int:
    """UTC epoch seconds로 변환(초 단위)"""
    return int(_ensure_aware_utc(dt).timestamp())


# =========================
# AT/RT 유틸
# =========================
def _make_access_token(user, minutes: Optional[int] = None):
    # settings에 값이 아직 없다면 기본값 사용 (2시간)
    default_minutes = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 120)
    exp_minutes = minutes if minutes is not None else default_minutes

    current_time = _utcnow()
    expiry_time = current_time + timedelta(minutes=exp_minutes)

    payload = {
        "sub": str(user["_id"]),
        "name": user["name"],
        "email": user["email"],
        # exp는 반드시 UTC epoch seconds(초)로
        "exp": _to_ts(expiry_time)
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=getattr(settings, "ALGORITHM", "HS256"))
    return token, expiry_time


def _make_refresh_token() -> str:
    # 간단히 무작위 문자열 사용 (DB에 평문 저장). 필요 시 해시 저장으로 강화 가능.
    return secrets.token_urlsafe(64)


# =========================
# 회원가입 / 이메일 인증
# =========================
@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate, background_tasks: BackgroundTasks):
    existing_name = await db.users.find_one({"name": user.name})
    if existing_name:
        raise HTTPException(status_code=400, detail="이미 사용중인 이름입니다.")

    existing_email = await db.users.find_one({"email": user.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="이미 사용중인 이메일입니다.")

    existing_student_number = await db.users.find_one({"student_number": user.student_number})
    if existing_student_number:
        raise HTTPException(status_code=400, detail="이미 사용중인 학번입니다.")

    hashed_password = get_password_hash(user.password)
    user_data = user.dict()
    user_data["password"] = hashed_password
    user_data["is_active"] = False
    user_data["created_at"] = _utcnow()
    await db.users.insert_one(user_data)

    await db.user_verification.delete_many({"email": user.email, "role": user.role})

    code = generate_verification_code()
    expires_at = _utcnow() + timedelta(minutes=4)
    await db.user_verification.insert_one({
        "email": user.email,
        "role": user.role,
        "code": code,
        "expires_at": expires_at,
        "created_at": _utcnow()
    })

    logger.info(f"회원가입: {user.email} 에 인증 코드 {code} 발송 (만료: {expires_at})")
    background_tasks.add_task(send_verification_email, user.email, code)

    return {
        "message": "회원가입 요청 완료. 인증 코드가 전송되었습니다.",
        "email": user.email,
        "role": user.role
    }


@router.post("/verify", status_code=status.HTTP_200_OK)
async def verify_code(data: dict, response: Response):
    email = data.get("email")
    role = data.get("role")
    code = data.get("code")
    if not email or not role or not code:
        raise HTTPException(status_code=400, detail="필수 정보 누락")

    record = await db.user_verification.find_one({"email": email, "role": role})
    if not record:
        raise HTTPException(status_code=404, detail="인증 정보가 존재하지 않습니다.")

    current_time = _utcnow()
    expires_at = _ensure_aware_utc(record.get("expires_at"))
    if not expires_at:
        raise HTTPException(status_code=400, detail="인증 만료 정보가 없습니다.")

    if current_time > expires_at:
        raise HTTPException(status_code=400, detail="인증 코드가 만료되었습니다.")
    if record["code"] != code:
        raise HTTPException(status_code=400, detail="인증 코드가 일치하지 않습니다.")

    await db.users.update_one({"email": email}, {"$set": {"is_active": True}})
    await db.user_verification.delete_one({"email": email, "role": role})

    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="사용자 정보를 찾을 수 없습니다.")

    # (프론트는 헤더를 사용하므로 쿠키는 필수 아님. 기존 호환을 위해 남겨둠)
    # token, _ = _make_access_token(user)
    # response.set_cookie(key="access_token", value=token, **get_cookie_options())

    logger.info(f"{email} 인증 완료, 계정 활성화됨.")
    return {"message": "이메일 인증 완료. 계정이 활성화되었습니다."}


# =========================
# 로그인 / 로그아웃 / 내 정보
# =========================
@router.post("/login", status_code=status.HTTP_200_OK)
async def login(user: UserLogin, response: Response):
    existing = await db.users.find_one({"email": user.email})
    if not existing:
        raise HTTPException(status_code=400, detail="존재하지 않는 계정입니다.")
    if not verify_password(user.password, existing["password"]):
        raise HTTPException(status_code=400, detail="비밀번호가 일치하지 않습니다.")
    if not existing.get("is_active", False):
        raise HTTPException(status_code=400, detail="계정이 활성화되지 않았습니다. 이메일 인증을 진행해주세요.")

    current_time = _utcnow()

    # Access / Refresh 발급
    access_token, access_exp = _make_access_token(existing)
    refresh_token = _make_refresh_token()
    refresh_days = getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 30)
    refresh_exp = current_time + timedelta(days=refresh_days)

    # 마지막 로그인 & RT 저장 (단일 RT 정책)
    await db.users.update_one(
        {"_id": existing["_id"]},
        {"$set": {"last_login": current_time, "refresh_token": refresh_token, "refresh_exp": refresh_exp}}
    )

    logger.info(f"{existing['email']} 로그인 성공, AT/RT 발급.")

    # 프론트는 헤더 토큰 사용 → 쿠키 설정 불필요
    return {
        "message": "로그인 성공",
        "access_token": access_token,
        "access_exp": _to_ts(access_exp),
        "refresh_token": refresh_token,
        "refresh_exp": _to_ts(refresh_exp),
        "user": {
            "id": str(existing["_id"]),
            "name": existing["name"],
            "email": existing["email"],
            "role": existing.get("role", "user")
        }
    }


@router.put("/profile", status_code=status.HTTP_200_OK)
async def update_profile(
    profile_data: dict,
    access_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
):
    """사용자 프로필 업데이트 (이름만 가능)"""
    token = access_token or _extract_token_from_auth_header(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="토큰이 제공되지 않았습니다.")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[getattr(settings, "ALGORITHM", "HS256")])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

    user = await db.users.find_one({"email": payload["email"]})
    if not user:
        raise HTTPException(status_code=404, detail="사용자 정보를 찾을 수 없습니다.")

    allowed_fields = ["name"]
    update_data = {k: v for k, v in profile_data.items() if k in allowed_fields and v}

    if not update_data:
        raise HTTPException(status_code=400, detail="업데이트할 유효한 데이터가 없습니다.")

    if "name" in update_data:
        existing_name = await db.users.find_one({
            "name": update_data["name"],
            "_id": {"$ne": user["_id"]}
        })
        if existing_name:
            raise HTTPException(status_code=400, detail="이미 사용중인 이름입니다.")

    await db.users.update_one({"_id": user["_id"]}, {"$set": update_data})

    updated_user = await db.users.find_one({"_id": user["_id"]})
    updated_user["_id"] = str(updated_user["_id"])
    updated_user.pop("password", None)

    return {"message": "프로필이 업데이트되었습니다.", "user": updated_user}


@router.get("/me", status_code=status.HTTP_200_OK)
async def get_current_user_endpoint(
    access_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
):
    """현재 로그인 사용자 정보 (Authorization 헤더 우선, 쿠키는 보조)"""
    token = access_token or _extract_token_from_auth_header(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="토큰이 제공되지 않았습니다.")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[getattr(settings, "ALGORITHM", "HS256")])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

    user = await db.users.find_one({"email": payload["email"]})
    if not user:
        raise HTTPException(status_code=404, detail="사용자 정보를 찾을 수 없습니다.")

    user["_id"] = str(user["_id"])
    user.pop("password", None)
    return {"user": user}


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(response: Response, data: Optional[dict] = None):
    """로그아웃: 전달된 refresh_token을 폐기(권장)."""
    refresh_token = (data or {}).get("refresh_token") if isinstance(data, dict) else None
    if refresh_token:
        await db.users.update_one(
            {"refresh_token": refresh_token},
            {"$unset": {"refresh_token": "", "refresh_exp": ""}}
        )
    # (쿠키는 현재 사용하지 않지만 기존 호환)
    response.delete_cookie("access_token")
    return {"message": "로그아웃 성공"}


# =========================
# 리프레시 토큰 엔드포인트
# =========================
@router.post("/refresh", status_code=status.HTTP_200_OK)
async def refresh_token_endpoint(data: dict):
    """
    바디로 { "refresh_token": "..." }를 받아 Access Token 재발급.
    """
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token이 필요합니다.")

    user = await db.users.find_one({"refresh_token": refresh_token})
    if not user:
        raise HTTPException(status_code=401, detail="유효하지 않은 리프레시 토큰입니다.")

    refresh_exp = _ensure_aware_utc(user.get("refresh_exp"))
    if not refresh_exp:
        raise HTTPException(status_code=401, detail="리프레시 토큰 만료 정보가 없습니다.")

    if _utcnow() >= refresh_exp:
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$unset": {"refresh_token": "", "refresh_exp": ""}}
        )
        raise HTTPException(status_code=401, detail="리프레시 토큰이 만료되었습니다. 다시 로그인해주세요.")

    access_token, access_exp = _make_access_token(user)
    return {
        "access_token": access_token,
        "access_exp": _to_ts(access_exp)
    }


# =========================
# 아이디 / 비밀번호 찾기
# =========================
@router.post("/find-username", status_code=status.HTTP_200_OK)
async def find_username(request: FindUsernameRequest):
    user = await db.users.find_one({
        "name": request.name,
        "student_number": request.student_number
    })
    if not user:
        raise HTTPException(status_code=404, detail="일치하는 회원 정보를 찾을 수 없습니다.")

    email = user["email"]
    username, domain = email.split('@')
    if len(username) > 3:
        masked_username = username[:3] + '*' * (len(username) - 3)
    else:
        masked_username = username[0] + '*' * (len(username) - 1)
    masked_email = f"{masked_username}@{domain}"

    return {"message": f"해당회원님의 아이디는 {masked_email}입니다.", "username": masked_email}


@router.post("/request-password-reset", status_code=status.HTTP_200_OK)
async def request_password_reset(request: PasswordResetRequest, background_tasks: BackgroundTasks):
    user = await db.users.find_one({
        "name": request.name,
        "student_number": request.student_number,
        "email": request.email
    })
    if not user:
        raise HTTPException(status_code=404, detail="일치하는 회원 정보를 찾을 수 없습니다.")

    await db.password_reset.delete_many({"email": request.email})

    code = generate_verification_code()
    expires_at = _utcnow() + timedelta(minutes=10)

    await db.password_reset.insert_one({
        "email": request.email,
        "code": code,
        "expires_at": expires_at,
        "created_at": _utcnow()
    })

    logger.info(f"비밀번호 재설정: {request.email} 에 인증 코드 {code} 발송 (만료: {expires_at})")
    background_tasks.add_task(send_verification_email, request.email, code)

    return {"message": "회원정보가 확인되었습니다. 이메일로 인증번호가 발송되었습니다.", "email": request.email}


@router.post("/verify-reset-code", status_code=status.HTTP_200_OK)
async def verify_reset_code(request: VerifyResetCodeRequest):
    record = await db.password_reset.find_one({"email": request.email})
    if not record:
        raise HTTPException(status_code=404, detail="인증 정보가 존재하지 않습니다.")

    current_time = _utcnow()
    expires_at = _ensure_aware_utc(record.get("expires_at"))
    if not expires_at:
        raise HTTPException(status_code=400, detail="인증 만료 정보가 없습니다.")

    if current_time > expires_at:
        raise HTTPException(status_code=400, detail="인증 코드가 만료되었습니다.")
    if record["code"] != request.code:
        raise HTTPException(status_code=400, detail="인증 코드가 일치하지 않습니다.")

    return {"message": "인증번호가 확인되었습니다. 새 비밀번호를 설정해주세요.", "verified": True}


@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(request: NewPasswordRequest):
    record = await db.password_reset.find_one({"email": request.email})
    if not record:
        raise HTTPException(status_code=404, detail="인증 정보가 존재하지 않습니다.")

    current_time = _utcnow()
    expires_at = _ensure_aware_utc(record.get("expires_at"))
    if not expires_at:
        raise HTTPException(status_code=400, detail="인증 만료 정보가 없습니다.")

    if current_time > expires_at:
        raise HTTPException(status_code=400, detail="인증 코드가 만료되었습니다.")
    if record["code"] != request.code:
        raise HTTPException(status_code=400, detail="인증 코드가 일치하지 않습니다.")

    user = await db.users.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="사용자 정보를 찾을 수 없습니다.")

    hashed_password = get_password_hash(request.new_password)
    await db.users.update_one({"email": request.email}, {"$set": {"password": hashed_password}})
    await db.password_reset.delete_one({"email": request.email})

    logger.info(f"비밀번호 재설정 완료: {request.email}")
    return {"message": "비밀번호가 성공적으로 변경되었습니다."}


@router.post("/check-duplicate")
async def check_duplicate(request: dict):
    field = request.get("field")
    value = request.get("value")

    if not field or not value:
        raise HTTPException(status_code=400, detail="field와 value가 필요합니다.")

    query = {}
    if field == "email":
        query = {"email": value}
    elif field == "name":
        query = {"name": value}
    elif field == "student_number":
        query = {"student_number": value}
    else:
        raise HTTPException(status_code=400, detail="유효하지 않은 필드입니다.")

    existing_user = await db.users.find_one(query)
    if existing_user:
        if field == "email":
            raise HTTPException(status_code=400, detail="이미 사용중인 이메일입니다.")
        elif field == "name":
            raise HTTPException(status_code=400, detail="이미 사용중인 이름입니다.")
        elif field == "student_number":
            raise HTTPException(status_code=400, detail="이미 사용중인 학번입니다.")

    return {"message": "사용 가능합니다."}
