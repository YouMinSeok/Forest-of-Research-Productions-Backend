"""
게시판 임시저장 (Draft) 라우터
- 엔터프라이즈 파일 시스템 연동
- 자동저장 기능
- 7일 TTL 자동 정리
- 첨부파일 안전 관리
"""

import os
import logging
from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Request, Query, BackgroundTasks
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
import pytz

from app.core.database import get_database
from app.utils.security import get_current_user
from app.utils.enterprise_file_manager import create_enterprise_file_manager
from app.models.draft import (
    DraftCreate, DraftUpdate, DraftResponse, DraftListResponse,
    DraftPublishRequest, AutoSaveRequest, DraftStats
)
from app.utils.permissions import PermissionManager
from app.models.permission import PermissionType

logger = logging.getLogger(__name__)
router = APIRouter()

# 엔터프라이즈 파일 매니저 초기화
enterprise_config = {
    "upload_dir": "uploads",
    "log_dir": "logs",
    "secret_key": os.getenv("FILE_SECRET_KEY", "enterprise-secret-key-2025"),
    "prevent_duplicates": True,
    "max_file_size": 50 * 1024 * 1024,  # 50MB
    "security_level": "high"
}

file_manager = create_enterprise_file_manager(enterprise_config)
seoul_tz = pytz.timezone('Asia/Seoul')

@router.post("/save", response_model=DraftResponse)
async def create_or_update_draft(
    draft_data: DraftCreate,
    db: AsyncIOMotorDatabase = Depends(get_database),
    user = Depends(get_current_user),
    request: Request = None
):
    """
    임시저장 생성 또는 업데이트
    - 동일 게시판의 기존 임시저장이 있으면 업데이트
    - 없으면 새로 생성
    """
    client_ip = request.client.host if request else "unknown"

    try:
        # 권한 확인
        if not PermissionManager.has_permission(user, PermissionType.WRITE):
            raise HTTPException(
                status_code=403,
                detail="임시저장 권한이 없습니다."
            )

        current_time = datetime.now(seoul_tz)
        user_id = str(user.id)

        # 같은 게시판의 기존 임시저장 확인
        existing_draft = await db.drafts.find_one({
            "writer_id": user_id,
            "board": draft_data.board,
            "status": "draft"
        })

        if existing_draft:
            # 기존 임시저장 업데이트
            update_data = {
                "title": draft_data.title,
                "content": draft_data.content,
                "category": draft_data.category,
                "tags": draft_data.tags,
                "is_private": draft_data.is_private,
                "metadata": draft_data.metadata,
                "updated_at": current_time,
                "last_save_ip": client_ip
            }

            result = await db.drafts.update_one(
                {"_id": existing_draft["_id"]},
                {"$set": update_data}
            )

            if result.modified_count == 0:
                raise HTTPException(status_code=500, detail="임시저장 업데이트 실패")

            draft_id = str(existing_draft["_id"])
            logger.info(f"임시저장 업데이트: {draft_id} by {user.name}")

        else:
            # 새 임시저장 생성
            draft_doc = {
                "board": draft_data.board,
                "title": draft_data.title,
                "content": draft_data.content,
                "category": draft_data.category,
                "tags": draft_data.tags,
                "is_private": draft_data.is_private,
                "writer_id": user_id,
                "writer_name": user.name,
                "status": "draft",
                "created_at": current_time,
                "updated_at": current_time,
                "expires_at": current_time + timedelta(days=7),  # 7일 TTL
                "auto_save_count": 0,
                "last_save_ip": client_ip,
                "metadata": draft_data.metadata or {}
            }

            result = await db.drafts.insert_one(draft_doc)
            draft_id = str(result.inserted_id)
            logger.info(f"새 임시저장 생성: {draft_id} by {user.name}")

        # 첨부파일 개수 조회
        attachment_count = await db.attachments.count_documents({"post_id": draft_id})

        # 응답 데이터 생성
        draft = await db.drafts.find_one({"_id": ObjectId(draft_id)})
        return DraftResponse(
            id=draft_id,
            board=draft["board"],
            title=draft["title"],
            content=draft["content"],
            category=draft.get("category"),
            tags=draft.get("tags", []),
            is_private=draft.get("is_private", False),
            writer_id=draft["writer_id"],
            writer_name=draft["writer_name"],
            created_at=draft["created_at"],
            updated_at=draft["updated_at"],
            attachment_count=attachment_count,
            auto_save_enabled=True,
            metadata=draft.get("metadata")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"임시저장 실패: {e}")
        raise HTTPException(status_code=500, detail="임시저장 중 오류가 발생했습니다.")

@router.post("/auto-save")
async def auto_save_draft(
    auto_save_data: AutoSaveRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
    user = Depends(get_current_user),
    request: Request = None
):
    """자동 저장 (1분마다 클라이언트에서 호출)"""
    client_ip = request.client.host if request else "unknown"

    try:
        draft_id = auto_save_data.draft_id

        # 임시저장 존재 및 권한 확인
        draft = await db.drafts.find_one({
            "_id": ObjectId(draft_id),
            "writer_id": str(user.id),
            "status": "draft"
        })

        if not draft:
            raise HTTPException(status_code=404, detail="임시저장을 찾을 수 없습니다.")

        current_time = datetime.now(seoul_tz)

        # 자동저장 업데이트
        update_data = {
            "title": auto_save_data.title,
            "content": auto_save_data.content,
            "updated_at": current_time,
            "last_save_ip": client_ip,
            "$inc": {"auto_save_count": 1}
        }

        result = await db.drafts.update_one(
            {"_id": ObjectId(draft_id)},
            {"$set": {k: v for k, v in update_data.items() if k != "$inc"},
             "$inc": update_data["$inc"]}
        )

        if result.modified_count == 0:
            raise HTTPException(status_code=500, detail="자동저장 실패")

        return {"success": True, "saved_at": current_time.isoformat()}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"자동저장 실패: {e}")
        return {"success": False, "error": str(e)}

@router.get("/list", response_model=DraftListResponse)
async def get_user_drafts(
    board: Optional[str] = Query(None, description="특정 게시판 필터링"),
    limit: int = Query(20, le=100, description="조회 개수"),
    offset: int = Query(0, description="오프셋"),
    db: AsyncIOMotorDatabase = Depends(get_database),
    user = Depends(get_current_user)
):
    """사용자 임시저장 목록 조회"""
    try:
        # 쿼리 조건 구성
        query = {
            "writer_id": str(user.id),
            "status": "draft"
        }

        if board:
            query["board"] = board

        # 총 개수 조회
        total_count = await db.drafts.count_documents(query)

        # 임시저장 목록 조회 (최신순)
        drafts_cursor = db.drafts.find(query).sort("updated_at", -1).skip(offset).limit(limit)
        drafts = await drafts_cursor.to_list(length=limit)

        # 각 임시저장의 첨부파일 개수 조회
        draft_responses = []
        for draft in drafts:
            draft_id = str(draft["_id"])
            attachment_count = await db.attachments.count_documents({"post_id": draft_id})

            draft_responses.append(DraftResponse(
                id=draft_id,
                board=draft["board"],
                title=draft["title"],
                content=draft["content"],
                category=draft.get("category"),
                tags=draft.get("tags", []),
                is_private=draft.get("is_private", False),
                writer_id=draft["writer_id"],
                writer_name=draft["writer_name"],
                created_at=draft["created_at"],
                updated_at=draft["updated_at"],
                attachment_count=attachment_count,
                auto_save_enabled=True,
                metadata=draft.get("metadata")
            ))

        return DraftListResponse(
            drafts=draft_responses,
            total_count=total_count,
            has_more=(offset + limit < total_count)
        )

    except Exception as e:
        logger.error(f"임시저장 목록 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="목록 조회 중 오류가 발생했습니다.")

@router.get("/{draft_id}", response_model=DraftResponse)
async def get_draft(
    draft_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    user = Depends(get_current_user)
):
    """특정 임시저장 조회"""
    try:
        draft = await db.drafts.find_one({
            "_id": ObjectId(draft_id),
            "writer_id": str(user.id),
            "status": "draft"
        })

        if not draft:
            raise HTTPException(status_code=404, detail="임시저장을 찾을 수 없습니다.")

        # 첨부파일 개수 조회
        attachment_count = await db.attachments.count_documents({"post_id": draft_id})

        return DraftResponse(
            id=draft_id,
            board=draft["board"],
            title=draft["title"],
            content=draft["content"],
            category=draft.get("category"),
            tags=draft.get("tags", []),
            is_private=draft.get("is_private", False),
            writer_id=draft["writer_id"],
            writer_name=draft["writer_name"],
            created_at=draft["created_at"],
            updated_at=draft["updated_at"],
            attachment_count=attachment_count,
            auto_save_enabled=True,
            metadata=draft.get("metadata")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"임시저장 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="조회 중 오류가 발생했습니다.")

@router.post("/{draft_id}/upload-file")
async def upload_file_to_draft(
    draft_id: str,
    file: UploadFile = File(...),
    db: AsyncIOMotorDatabase = Depends(get_database),
    user = Depends(get_current_user),
    request: Request = None
):
    """
    임시저장에 파일 업로드 (엔터프라이즈 파일 시스템 사용)
    """
    client_ip = request.client.host if request else "unknown"

    try:
        # 임시저장 존재 및 권한 확인
        draft = await db.drafts.find_one({
            "_id": ObjectId(draft_id),
            "writer_id": str(user.id),
            "status": "draft"
        })

        if not draft:
            raise HTTPException(status_code=404, detail="임시저장을 찾을 수 없습니다.")

        # 엔터프라이즈 파일 매니저로 업로드
        upload_result = await file_manager.upload_file_secure(
            file=file,
            post_id=draft_id,  # draft_id를 post_id로 사용
            user_id=str(user.id),
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent"),
            is_draft=True  # 드래프트 파일임을 명시
        )

        # DB에 첨부파일 정보 저장
        attachment_doc = {
            "post_id": draft_id,
            "filename": upload_result["secure_filename"],
            "original_filename": upload_result["original_filename"],
            "file_size": upload_result["file_size"],
            "file_type": upload_result["file_type"],
            "mime_type": upload_result["mime_type"],
            "file_path": upload_result["storage_path"],
            "file_hash": upload_result["file_hash"],
            "upload_date": datetime.now(seoul_tz),
            "uploader_id": str(user.id),
            "is_draft": True,  # 드래프트 첨부파일 플래그
            "security_verified": upload_result.get("security_verified", False)
        }

        result = await db.attachments.insert_one(attachment_doc)
        attachment_id = str(result.inserted_id)

        logger.info(f"드래프트 파일 업로드 성공: {draft_id} - {upload_result['original_filename']}")

        return {
            "attachment_id": attachment_id,
            "filename": upload_result["secure_filename"],
            "original_filename": upload_result["original_filename"],
            "file_size": upload_result["file_size"],
            "file_type": upload_result["file_type"],
            "upload_date": attachment_doc["upload_date"].isoformat(),
            "security_status": "verified" if upload_result.get("security_verified") else "pending"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"드래프트 파일 업로드 실패: {e}")
        raise HTTPException(status_code=500, detail="파일 업로드 중 오류가 발생했습니다.")

@router.delete("/{draft_id}")
async def delete_draft(
    draft_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncIOMotorDatabase = Depends(get_database),
    user = Depends(get_current_user)
):
    """임시저장 삭제 (첨부파일 포함)"""
    try:
        # 임시저장 존재 및 권한 확인
        draft = await db.drafts.find_one({
            "_id": ObjectId(draft_id),
            "writer_id": str(user.id),
            "status": "draft"
        })

        if not draft:
            raise HTTPException(status_code=404, detail="임시저장을 찾을 수 없습니다.")

        # 백그라운드에서 첨부파일 정리
        background_tasks.add_task(_cleanup_draft_files, draft_id)

        # 임시저장 삭제
        result = await db.drafts.delete_one({"_id": ObjectId(draft_id)})

        if result.deleted_count == 0:
            raise HTTPException(status_code=500, detail="임시저장 삭제 실패")

        logger.info(f"임시저장 삭제: {draft_id} by {user.name}")

        return {"success": True, "message": "임시저장이 삭제되었습니다."}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"임시저장 삭제 실패: {e}")
        raise HTTPException(status_code=500, detail="삭제 중 오류가 발생했습니다.")

@router.post("/{draft_id}/publish")
async def publish_draft(
    draft_id: str,
    publish_data: DraftPublishRequest,
    background_tasks: BackgroundTasks,
    db: AsyncIOMotorDatabase = Depends(get_database),
    user = Depends(get_current_user),
    request: Request = None
):
    """
    임시저장을 정식 게시글로 발행
    - 첨부파일을 새 post_id로 마이그레이션
    - 임시저장 삭제
    """
    client_ip = request.client.host if request else "unknown"

    try:
        # 임시저장 존재 및 권한 확인
        draft = await db.drafts.find_one({
            "_id": ObjectId(draft_id),
            "writer_id": str(user.id),
            "status": "draft"
        })

        if not draft:
            raise HTTPException(status_code=404, detail="임시저장을 찾을 수 없습니다.")

        # 발행 권한 확인
        if not PermissionManager.has_permission(user, PermissionType.WRITE):
            raise HTTPException(
                status_code=403,
                detail="게시글 발행 권한이 없습니다."
            )

        current_time = datetime.now(seoul_tz)

        # 최종 데이터 결정 (요청 데이터가 있으면 사용, 없으면 draft 데이터 사용)
        final_title = publish_data.final_title or draft["title"]
        final_content = publish_data.final_content or draft["content"]
        final_category = publish_data.final_category or draft.get("category")
        final_tags = publish_data.final_tags or draft.get("tags", [])
        final_is_private = publish_data.final_is_private if publish_data.final_is_private is not None else draft.get("is_private", False)

        # 유효성 검사
        if not final_title.strip():
            raise HTTPException(status_code=400, detail="제목은 필수입니다.")
        if not final_content.strip():
            raise HTTPException(status_code=400, detail="내용은 필수입니다.")

        # 게시글 번호 생성 (카운터 시스템)
        from pymongo import ReturnDocument
        counter_key = f"{draft['board']}_post_number"
        counter = await db["counters"].find_one_and_update(
            {"_id": counter_key},
            {"$inc": {"seq": 1}},
            upsert=True,
            return_document=ReturnDocument.AFTER
        )
        post_number = counter["seq"] if counter else 1

        # 새 게시글 생성
        user_dict = {
            "id": str(user.id),
            "name": user.name,
            "email": user.email,
            "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
            "permissions": user.permissions,
            "is_admin": user.is_admin
        }

        post_doc = {
            "board": draft["board"],
            "title": final_title,
            "content": final_content,
            "category": final_category,
            "tags": final_tags,
            "is_private": final_is_private,
            "writer": user.name,
            "writer_id": str(user.id),
            "user_info": user_dict,
            "date": current_time.strftime("%Y-%m-%d %H:%M:%S"),  # 날짜 포맷 추가
            "created_at": current_time,
            "updated_at": current_time,
            "views": 0,
            "likes": 0,
            "comments_count": 0,
            "post_number": post_number,  # 게시글 번호 추가
            "published_from_draft": True,
            "original_draft_id": draft_id,
            "client_ip": client_ip
        }

        # 게시글 등록
        post_result = await db.board.insert_one(post_doc)
        new_post_id = str(post_result.inserted_id)

        # 백그라운드에서 첨부파일 마이그레이션
        background_tasks.add_task(_migrate_draft_attachments, draft_id, new_post_id)

        # 임시저장 상태 변경 (삭제하지 않고 발행됨으로 표시)
        await db.drafts.update_one(
            {"_id": ObjectId(draft_id)},
            {"$set": {
                "status": "published",
                "published_at": current_time,
                "published_post_id": new_post_id
            }}
        )

        logger.info(f"임시저장 발행 완료: {draft_id} -> {new_post_id} by {user.name}")

        return {
            "success": True,
            "post_id": new_post_id,
            "message": "게시글이 성공적으로 발행되었습니다.",
            "redirect_url": f"/board/{new_post_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"임시저장 발행 실패: {e}")
        raise HTTPException(status_code=500, detail="발행 중 오류가 발생했습니다.")

@router.get("/stats/summary", response_model=DraftStats)
async def get_draft_stats(
    db: AsyncIOMotorDatabase = Depends(get_database),
    user = Depends(get_current_user)
):
    """사용자 임시저장 통계"""
    try:
        user_id = str(user.id)
        current_time = datetime.now(seoul_tz)
        week_ago = current_time - timedelta(days=7)

        # 총 임시저장 수
        total_drafts = await db.drafts.count_documents({
            "writer_id": user_id,
            "status": "draft"
        })

        # 최근 7일 임시저장 수
        recent_drafts = await db.drafts.count_documents({
            "writer_id": user_id,
            "status": "draft",
            "created_at": {"$gte": week_ago}
        })

        # 총 첨부파일 수 (임시저장용)
        draft_cursor = db.drafts.find(
            {"writer_id": user_id, "status": "draft"},
            {"_id": 1}
        )
        draft_docs = await draft_cursor.to_list(length=None)
        draft_ids = [str(d["_id"]) for d in draft_docs]

        total_attachments = 0
        storage_used_bytes = 0

        if draft_ids:
            attachments_cursor = db.attachments.find({"post_id": {"$in": draft_ids}})
            async for attachment in attachments_cursor:
                total_attachments += 1
                storage_used_bytes += attachment.get("file_size", 0)

        # 가장 오래된 임시저장
        oldest_draft = await db.drafts.find_one(
            {"writer_id": user_id, "status": "draft"},
            sort=[("created_at", 1)]
        )

        oldest_draft_days = 0
        if oldest_draft:
            oldest_draft_days = (current_time - oldest_draft["created_at"]).days

        return DraftStats(
            total_drafts=total_drafts,
            recent_drafts=recent_drafts,
            total_attachments=total_attachments,
            storage_used_mb=round(storage_used_bytes / (1024 * 1024), 2),
            oldest_draft_days=oldest_draft_days
        )

    except Exception as e:
        logger.error(f"임시저장 통계 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="통계 조회 중 오류가 발생했습니다.")

# 백그라운드 작업 함수들
async def _cleanup_draft_files(draft_id: str):
    """임시저장 첨부파일 정리"""
    try:
        db = await get_database()
        attachments_cursor = db.attachments.find({"post_id": draft_id})
        attachments = await attachments_cursor.to_list(length=None)

        for attachment in attachments:
            try:
                # 물리적 파일 삭제
                file_path = attachment.get("file_path")
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)

                # DB에서 첨부파일 삭제
                await db.attachments.delete_one({"_id": attachment["_id"]})

            except Exception as e:
                logger.error(f"첨부파일 삭제 실패 {attachment.get('_id')}: {e}")

        logger.info(f"드래프트 첨부파일 정리 완료: {draft_id}")

    except Exception as e:
        logger.error(f"드래프트 파일 정리 실패: {e}")

async def _migrate_draft_attachments(draft_id: str, new_post_id: str):
    """드래프트 첨부파일을 새 게시글로 마이그레이션"""
    try:
        db = await get_database()
        # 첨부파일의 post_id 업데이트
        result = await db.attachments.update_many(
            {"post_id": draft_id},
            {"$set": {
                "post_id": new_post_id,
                "is_draft": False,
                "migrated_at": datetime.now(seoul_tz)
            }}
        )

        logger.info(f"첨부파일 마이그레이션 완료: {draft_id} -> {new_post_id} ({result.modified_count}개)")

    except Exception as e:
        logger.error(f"첨부파일 마이그레이션 실패: {e}")
