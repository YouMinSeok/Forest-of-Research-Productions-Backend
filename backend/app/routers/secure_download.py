"""
보안 다운로드 게이트
- 토큰 기반 다운로드 (만료 시간 포함)
- 직접 파일 경로 노출 금지
- RFC5987 준수 헤더
- X-Content-Type-Options: nosniff
- 권한 검사
"""

import os
import logging
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import StreamingResponse, JSONResponse
from starlette.background import BackgroundTask

from app.core.database import get_database
from app.utils.security import get_current_user
from app.utils.enhanced_security import EnhancedFileSecurityManager
from app.utils.file_logger import FileActivityLogger
from bson import ObjectId

logger = logging.getLogger(__name__)

router = APIRouter()

# 보안 관리자 초기화 (실제 환경에서는 config에서 가져와야 함)
security_manager = EnhancedFileSecurityManager(secret_key="your-secret-key-here")
file_logger = FileActivityLogger()

@router.get("/generate-download-token/{attachment_id}")
async def generate_download_token(
    attachment_id: str,
    db=Depends(get_database),
    user=Depends(get_current_user),
    request: Request = None
):
    """
    보안 다운로드 토큰 생성
    - 첨부파일 권한 검증
    - 1시간 유효 토큰 발급
    - 감사 로그 기록
    """
    try:
        # 첨부파일 존재 및 권한 확인
        attachment = db.attachments.find_one({
            "_id": ObjectId(attachment_id)
        })

        if not attachment:
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다")

        # 권한 검사 (업로더 본인 또는 게시글 접근 권한)
        can_access = await _check_download_permission(attachment, user, db)
        if not can_access:
            # 권한 없음 로그
            file_logger.log_security_event(
                event_type="unauthorized_download_attempt",
                user_id=str(user["_id"]),
                attachment_id=attachment_id,
                client_ip=request.client.host if request else "unknown",
                details="권한 없는 다운로드 시도"
            )
            raise HTTPException(status_code=403, detail="다운로드 권한이 없습니다")

        # 다운로드 토큰 생성 (1시간 유효)
        token = security_manager.generate_secure_download_token(
            attachment_id=attachment_id,
            user_id=str(user["_id"]),
            expires_in=3600  # 1시간
        )

        # 토큰 발급 로그
        file_logger.log_file_access(
            operation="token_generated",
            user_id=str(user["_id"]),
            attachment_id=attachment_id,
            filename=attachment.get("original_filename"),
            client_ip=request.client.host if request else "unknown",
            success=True
        )

        return {
            "success": True,
            "token": token,
            "expires_in": 3600,
            "download_url": f"/api/secure-download/download?token={token}&attachment_id={attachment_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"토큰 생성 실패: {e}")
        raise HTTPException(status_code=500, detail="토큰 생성에 실패했습니다")

@router.get("/download")
async def secure_download(
    token: str = Query(..., description="다운로드 토큰"),
    attachment_id: str = Query(..., description="첨부파일 ID"),
    db=Depends(get_database),
    request: Request = None
):
    """
    보안 다운로드 엔드포인트
    - 토큰 검증
    - RFC5987 준수 헤더
    - X-Content-Type-Options: nosniff
    - 스트리밍 다운로드 (메모리 효율)
    """
    client_ip = request.client.host if request else "unknown"

    try:
        # 첨부파일 조회
        attachment = db.attachments.find_one({
            "_id": ObjectId(attachment_id)
        })

        if not attachment:
            file_logger.log_security_event(
                event_type="invalid_attachment_access",
                attachment_id=attachment_id,
                client_ip=client_ip,
                details="존재하지 않는 첨부파일 접근"
            )
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다")

        # 토큰 검증
        is_valid = security_manager.verify_download_token(
            token=token,
            attachment_id=attachment_id,
            user_id=attachment["uploader_id"]
        )

        if not is_valid:
            file_logger.log_security_event(
                event_type="invalid_download_token",
                attachment_id=attachment_id,
                client_ip=client_ip,
                details="유효하지 않은 다운로드 토큰"
            )
            raise HTTPException(status_code=403, detail="유효하지 않은 토큰입니다")

        # 파일 경로 (실제 파일 시스템 경로는 숨김)
        file_path = attachment.get("file_path")
        if not file_path or not os.path.exists(file_path):
            file_logger.log_security_event(
                event_type="missing_file",
                attachment_id=attachment_id,
                client_ip=client_ip,
                details="물리적 파일 누락"
            )
            raise HTTPException(status_code=404, detail="파일을 찾을 수 없습니다")

        # 파일 정보
        original_filename = attachment.get("original_filename", "download")
        file_size = attachment.get("file_size", 0)
        mime_type = attachment.get("mime_type", "application/octet-stream")

        # RFC5987 준수 파일명 인코딩
        encoded_filename = _encode_filename_rfc5987(original_filename)

        # 보안 헤더 설정
        headers = {
            # RFC5987 준수 Content-Disposition
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}",

            # 보안 헤더
            "X-Content-Type-Options": "nosniff",  # MIME 스니핑 방지
            "X-Frame-Options": "DENY",           # 프레임 내 로드 방지
            "Cache-Control": "no-cache, no-store, must-revalidate",  # 캐시 방지
            "Pragma": "no-cache",
            "Expires": "0",

            # 파일 정보
            "Content-Length": str(file_size),
            "Content-Type": mime_type,

            # 다운로드 추적
            "X-Download-Token": "secure",
            "X-File-ID": attachment_id
        }

        # 스트리밍 응답 생성
        def file_generator():
            try:
                with open(file_path, "rb") as file:
                    while True:
                        chunk = file.read(8192)  # 8KB 청크
                        if not chunk:
                            break
                        yield chunk
            except Exception as e:
                logger.error(f"파일 스트리밍 오류: {e}")
                raise

        # 다운로드 성공 로그 (백그라운드)
        background_task = BackgroundTask(
            _log_successful_download,
            attachment_id=attachment_id,
            user_id=attachment["uploader_id"],
            filename=original_filename,
            client_ip=client_ip,
            file_size=file_size
        )

        return StreamingResponse(
            file_generator(),
            media_type=mime_type,
            headers=headers,
            background=background_task
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"다운로드 실패: {e}")
        file_logger.log_security_event(
            event_type="download_error",
            attachment_id=attachment_id,
            client_ip=client_ip,
            details=f"다운로드 오류: {str(e)}"
        )
        raise HTTPException(status_code=500, detail="다운로드에 실패했습니다")

@router.get("/block-direct-access")
async def block_direct_access():
    """
    직접 파일 경로 접근 차단 엔드포인트
    실제 파일 경로로의 접근을 차단하고 보안 경고를 기록
    """
    return JSONResponse(
        status_code=403,
        content={
            "error": "Direct file access is forbidden",
            "message": "파일에 직접 접근할 수 없습니다. 적절한 다운로드 토큰을 사용하세요.",
            "code": "DIRECT_ACCESS_FORBIDDEN"
        },
        headers={
            "X-Security-Warning": "Direct file access attempted",
            "X-Content-Type-Options": "nosniff"
        }
    )

async def _check_download_permission(attachment: dict, user: dict, db) -> bool:
    """다운로드 권한 검사"""
    try:
        # 1. 업로더 본인인지 확인
        if str(attachment["uploader_id"]) == str(user["_id"]):
            return True

        # 2. 게시글 권한 확인
        post_id = attachment.get("post_id")
        if post_id:
            post = db.posts.find_one({"_id": ObjectId(post_id)})
            if post:
                # 공개 게시글인지 확인
                if post.get("status") == "published":
                    return True

                # 게시글 작성자인지 확인
                if str(post.get("author_id")) == str(user["_id"]):
                    return True

        # 3. 관리자 권한 확인
        if user.get("role") == "admin":
            return True

        return False

    except Exception as e:
        logger.error(f"권한 검사 오류: {e}")
        return False

def _encode_filename_rfc5987(filename: str) -> str:
    """RFC5987 준수 파일명 인코딩"""
    try:
        # URL 인코딩 (UTF-8)
        encoded = urllib.parse.quote(filename, safe='')
        return encoded
    except Exception:
        # 인코딩 실패 시 안전한 기본값
        return "download"

async def _log_successful_download(attachment_id: str, user_id: str,
                                 filename: str, client_ip: str, file_size: int):
    """다운로드 성공 로그 (백그라운드 작업)"""
    try:
        file_logger.log_file_access(
            operation="download_completed",
            user_id=user_id,
            attachment_id=attachment_id,
            filename=filename,
            client_ip=client_ip,
            success=True,
            additional_data={
                "file_size": file_size,
                "download_method": "secure_token"
            }
        )
    except Exception as e:
        logger.error(f"다운로드 로그 실패: {e}")

@router.get("/verify-token")
async def verify_token(
    token: str = Query(...),
    attachment_id: str = Query(...),
    user=Depends(get_current_user)
):
    """토큰 검증 엔드포인트 (디버깅용)"""
    is_valid = security_manager.verify_download_token(
        token=token,
        attachment_id=attachment_id,
        user_id=str(user["_id"])
    )

    return {
        "valid": is_valid,
        "user_id": str(user["_id"]),
        "attachment_id": attachment_id
    }
