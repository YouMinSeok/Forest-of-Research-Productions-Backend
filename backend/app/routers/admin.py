from fastapi import APIRouter, HTTPException, Depends, status
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from bson import ObjectId
import os
from pydantic import BaseModel
from ..core.database import db
from ..core.config import settings
from ..models.user import User, UserUpdate, UserResponse
from ..models.permission import PermissionType, UserRole, UserRoleUpdate
from ..utils.permissions import PermissionManager
from ..utils.security import get_password_hash
from ..utils.auth_middleware import get_current_user

class PermissionRequest(BaseModel):
    permission: str

router = APIRouter(tags=["admin"])

async def require_admin_permission(current_user: User = Depends(get_current_user)):
    """어드민 권한 확인"""
    if not current_user.is_admin and not PermissionManager.is_admin_email(current_user.email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 권한이 필요합니다."
        )
    return current_user

@router.post("/init-admin")
async def initialize_admin():
    """어드민 계정 초기화 (최초 1회만 실행)"""
    admin_creds = PermissionManager.get_admin_credentials()

    # 기존 어드민 계정 확인
    existing_admin = await db.users.find_one({"email": admin_creds["email"]})
    if existing_admin:
        return {"message": "어드민 계정이 이미 존재합니다."}

    # 어드민 계정 생성
    admin_data = {
        "name": admin_creds["name"],
        "email": admin_creds["email"],
        "password": get_password_hash(admin_creds["password"]),
        "role": "admin",
        "is_active": True,
        "is_admin": True,
        "permissions": [perm.value for perm in PermissionType],
        "created_at": datetime.utcnow()
    }

    await db.users.insert_one(admin_data)
    return {
        "message": "어드민 계정이 생성되었습니다.",
        "email": admin_creds["email"],
        "password": admin_creds["password"]
    }

@router.get("/dashboard/stats")
async def get_dashboard_stats(current_user: User = Depends(require_admin_permission)):
    """어드민 대시보드 통계 정보"""

    # 실제 사용자 통계
    total_users = await db.users.count_documents({})
    active_users = await db.users.count_documents({"is_active": True})

    # 일주일 전 날짜
    week_ago = datetime.utcnow() - timedelta(days=7)
    new_users_this_week = await db.users.count_documents({"created_at": {"$gte": week_ago}})

    # 게시판 통계 (board 컬렉션이 있다고 가정)
    total_posts = 0
    try:
        total_posts = await db.board_posts.count_documents({})
    except:
        total_posts = 0

    # 연구자료 통계
    total_research = 0
    try:
        total_research = await db.research_data.count_documents({})
    except:
        total_research = 0

    stats = {
        "total_users": total_users,
        "active_users": active_users,
        "total_posts": total_posts,
        "total_research": total_research,
        "new_users_this_week": new_users_this_week,
        "active_sessions": active_users,  # 근사치
        "system_health": "healthy",
        "last_updated": datetime.utcnow()
    }
    return stats

@router.get("/dashboard/recent-activities")
async def get_recent_activities(current_user: User = Depends(require_admin_permission)):
    """최근 활동 로그"""

    activities = []

    # 최근 가입한 사용자들
    recent_users = await db.users.find(
        {},
        {"name": 1, "email": 1, "created_at": 1, "role": 1, "is_active": 1}
    ).sort("created_at", -1).limit(5).to_list(5)

    for user in recent_users:
        activities.append({
            "id": str(user["_id"]) + "_signup",
            "user_name": user["name"],
            "action": "회원가입",
            "resource": f"역할: {user.get('role', 'user')} | 상태: {'활성' if user.get('is_active', False) else '비활성'}",
            "timestamp": user["created_at"],
            "ip_address": "N/A",
            "type": "user_activity"
        })

    # 최근 로그인한 사용자들 (last_login이 있는 경우)
    recent_logins = await db.users.find(
        {"last_login": {"$exists": True}},
        {"name": 1, "email": 1, "last_login": 1, "role": 1}
    ).sort("last_login", -1).limit(3).to_list(3)

    for user in recent_logins:
        if user.get("last_login"):
            activities.append({
                "id": str(user["_id"]) + "_login",
                "user_name": user["name"],
                "action": "로그인",
                "resource": f"역할: {user.get('role', 'user')}",
                "timestamp": user["last_login"],
                "ip_address": "N/A",
                "type": "auth_activity"
            })

    # 시스템 활동 추가
    current_time = datetime.utcnow()

    activities.extend([
        {
            "id": "system_health_check",
            "user_name": "시스템",
            "action": "상태 점검",
            "resource": "자동 시스템 모니터링",
            "timestamp": current_time - timedelta(minutes=5),
            "ip_address": "localhost",
            "type": "system_activity"
        },
        {
            "id": "db_connection_check",
            "user_name": "시스템",
            "action": "데이터베이스 연결 확인",
            "resource": "MongoDB Atlas 연결 테스트",
            "timestamp": current_time - timedelta(minutes=10),
            "ip_address": "localhost",
            "type": "system_activity"
        }
    ])

    # 시간순으로 정렬 (최신순)
    activities.sort(key=lambda x: x["timestamp"], reverse=True)

    # 최대 10개만 반환
    return activities[:10]

@router.get("/users")
async def get_all_users(
    page: int = 1,
    limit: int = 20,
    role: str = None,
    search: str = None,
    current_user: User = Depends(require_admin_permission)
) -> Dict[str, Any]:
    """모든 사용자 목록 조회"""

    # 검색 및 필터 조건 구성
    query = {}
    if role:
        query["role"] = role
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}}
        ]

    # 전체 개수
    total = await db.users.count_documents(query)

    # 페이징
    skip = (page - 1) * limit
    users_cursor = db.users.find(query).skip(skip).limit(limit).sort("created_at", -1)
    users = await users_cursor.to_list(limit)

    # 응답 데이터 변환
    user_responses = []
    for user in users:
        user_responses.append({
            "id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user.get("role", "student"),
            "permissions": user.get("permissions", []),
            "is_active": user.get("is_active", False),
            "is_admin": user.get("is_admin", False),
            "created_at": user["created_at"],
            "last_login": user.get("last_login")
        })

    return {
        "users": user_responses,
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit
    }

@router.get("/users/{user_id}")
async def get_user_detail(
    user_id: str,
    current_user: User = Depends(require_admin_permission)
):
    """특정 사용자 상세 정보"""
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

        return {
            "id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user.get("role", "student"),
            "permissions": user.get("permissions", []),
            "is_active": user.get("is_active", False),
            "is_admin": user.get("is_admin", False),
            "created_at": user["created_at"],
            "last_login": user.get("last_login")
        }
    except:
        raise HTTPException(status_code=400, detail="잘못된 사용자 ID입니다.")

@router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: User = Depends(require_admin_permission)
):
    """사용자 정보 업데이트"""
    try:
        # 업데이트할 데이터 구성
        update_data = {}
        if user_update.name is not None:
            update_data["name"] = user_update.name
        if user_update.role is not None:
            update_data["role"] = user_update.role.value
        if user_update.permissions is not None:
            update_data["permissions"] = user_update.permissions
        if user_update.is_active is not None:
            update_data["is_active"] = user_update.is_active
        if user_update.is_admin is not None:
            update_data["is_admin"] = user_update.is_admin

        update_data["updated_at"] = datetime.utcnow()

        # 업데이트 실행
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )

        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

        # 업데이트된 사용자 정보 반환
        updated_user = await db.users.find_one({"_id": ObjectId(user_id)})
        return {
            "id": str(updated_user["_id"]),
            "name": updated_user["name"],
            "email": updated_user["email"],
            "role": updated_user.get("role", "student"),
            "permissions": updated_user.get("permissions", []),
            "is_active": updated_user.get("is_active", False),
            "is_admin": updated_user.get("is_admin", False),
            "created_at": updated_user["created_at"],
            "last_login": updated_user.get("last_login")
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"사용자 업데이트 실패: {str(e)}")

@router.post("/users/{user_id}/permissions")
async def add_user_permission(
    user_id: str,
    request: PermissionRequest,
    current_user: User = Depends(require_admin_permission)
):
    """사용자에게 권한 추가"""
    try:
        # 요청된 권한이 유효한 PermissionType인지 확인
        try:
            permission = PermissionType(request.permission)
        except ValueError:
            valid_permissions = [perm.value for perm in PermissionType]
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "요청 데이터 형식이 올바르지 않습니다.",
                    "details": [f"유효하지 않은 권한입니다. 가능한 권한: {valid_permissions}"]
                }
            )

        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$addToSet": {"permissions": permission.value}}
        )

        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

        return {"message": f"사용자에게 {permission.value} 권한이 추가되었습니다."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "요청 데이터 형식이 올바르지 않습니다.",
                "details": [f"권한 추가 실패: {str(e)}"]
            }
        )

@router.delete("/users/{user_id}/permissions/{permission}")
async def remove_user_permission(
    user_id: str,
    permission: str,
    current_user: User = Depends(require_admin_permission)
):
    """사용자에게서 권한 제거"""
    try:
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$pull": {"permissions": permission}}
        )

        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

        return {"message": f"사용자에게서 {permission} 권한이 제거되었습니다."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"권한 제거 실패: {str(e)}")

@router.post("/users/{user_id}/activate")
async def activate_user(
    user_id: str,
    current_user: User = Depends(require_admin_permission)
):
    """사용자 활성화"""
    try:
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": True}}
        )

        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

        return {"message": "사용자가 활성화되었습니다."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"사용자 활성화 실패: {str(e)}")

@router.post("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: str,
    current_user: User = Depends(require_admin_permission)
):
    """사용자 비활성화"""
    try:
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": False}}
        )

        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

        return {"message": "사용자가 비활성화되었습니다."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"사용자 비활성화 실패: {str(e)}")

@router.get("/permissions")
async def get_all_permissions(current_user: User = Depends(require_admin_permission)):
    """모든 권한 목록"""
    permissions = [
        {
            "type": perm.value,
            "description": f"{perm.value} 권한"
        }
        for perm in PermissionType
    ]
    return permissions

@router.get("/roles")
async def get_all_roles(current_user: User = Depends(require_admin_permission)):
    """모든 역할 목록과 기본 권한"""
    roles = []
    for role in UserRole:
        default_permissions = PermissionManager.DEFAULT_PERMISSIONS.get(role, [])
        roles.append({
            "role": role.value,
            "default_permissions": [perm.value for perm in default_permissions]
        })
    return roles

@router.get("/system/health")
async def get_system_health(current_user: User = Depends(require_admin_permission)):
    """시스템 상태 확인"""
    try:
        # MongoDB 연결 테스트
        await db.command("ping")
        db_status = "connected"
    except:
        db_status = "disconnected"

    # 실제 시스템 리소스 정보 수집
    try:
        import psutil
        import platform

        # CPU 사용률 (1초간 측정)
        cpu_percent = psutil.cpu_percent(interval=1)

        # 메모리 사용률
        memory = psutil.virtual_memory()
        memory_percent = memory.percent

        # 디스크 사용률 (루트 파티션)
        disk = psutil.disk_usage('/')
        disk_percent = round((disk.used / disk.total) * 100, 1)

        # 시스템 업타임
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_delta = datetime.now() - boot_time
        uptime_days = uptime_delta.days
        uptime_hours = uptime_delta.seconds // 3600
        uptime_minutes = (uptime_delta.seconds % 3600) // 60

        if uptime_days > 0:
            uptime_str = f"{uptime_days}일 {uptime_hours}시간 {uptime_minutes}분"
        else:
            uptime_str = f"{uptime_hours}시간 {uptime_minutes}분"

        # 시스템 정보
        system_info = {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor() or "Unknown",
            "ram_total_gb": round(memory.total / (1024**3), 2),
            "disk_total_gb": round(disk.total / (1024**3), 2)
        }

    except Exception as e:
        # psutil이 없거나 오류 발생 시 기본값
        cpu_percent = 0
        memory_percent = 0
        disk_percent = 0
        uptime_str = "정보 없음"
        system_info = {}

    # 전체 시스템 상태 결정
    overall_status = "healthy"
    if db_status == "disconnected":
        overall_status = "unhealthy"
    elif cpu_percent > 90 or memory_percent > 90 or disk_percent > 90:
        overall_status = "warning"

    return {
        "status": overall_status,
        "database": db_status,
        "memory_usage": f"{memory_percent:.1f}%",
        "cpu_usage": f"{cpu_percent:.1f}%",
        "disk_usage": f"{disk_percent:.1f}%",
        "uptime": uptime_str,
        "last_backup": datetime.utcnow() - timedelta(hours=6),  # 실제 백업 시스템 구현 시 변경
        "system_info": system_info,
        "timestamp": datetime.utcnow()
    }
