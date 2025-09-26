"""
엔터프라이즈급 파일 업로드/다운로드 라우터
- 6가지 핵심 보안 기능 통합
- 원자적 저장, MIME 이중검사, 토큰 다운로드, TTL 정리, 하드닝, 감사로그
"""

import os
import logging
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Request, Query
from fastapi.responses import StreamingResponse, JSONResponse
from starlette.background import BackgroundTask

from app.core.database import get_database
from app.utils.security import get_current_user
from app.utils.enterprise_file_manager import create_enterprise_file_manager
from bson import ObjectId

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

@router.post("/upload")
async def upload_file_enterprise(
    post_id: str = Form(..., description="게시글 ID"),
    file: UploadFile = File(..., description="업로드할 파일"),
    db=Depends(get_database),
    user=Depends(get_current_user),
    request: Request = None
):
    """
    엔터프라이즈급 파일 업로드

    통합 보안 기능:
    - 원자적 저장 (임시→해시검증→rename)
    - MIME 이중검사 (브라우저 vs 실제 내용)
    - 확장자 화이트리스트
    - 중복 방지 (SHA-256 기반)
    - 완전한 감사 로그
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="파일명이 필요합니다")

    try:
        # 파일 내용 읽기
        file_content = await file.read()

        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="빈 파일은 업로드할 수 없습니다")

        # 사용자 데이터 준비
        user_data = {
            "user_id": str(user["_id"]),
            "username": user.get("username", "unknown"),
            "role": user.get("role", "user"),
            "client_ip": request.client.host if request else "unknown",
            "user_agent": request.headers.get("user-agent") if request else None
        }

        # 파일 데이터 준비
        file_data = {
            "content": file_content,
            "filename": file.filename,
            "mime_type": file.content_type,
            "post_id": post_id
        }

        # 엔터프라이즈 업로드 처리
        success, message, result = await file_manager.upload_file_enterprise(
            file_data=file_data,
            user_data=user_data,
            db=db
        )

        if not success:
            raise HTTPException(status_code=400, detail=message)

        return {
            "success": True,
            "message": message,
            "attachment_id": result["attachment_id"],
            "audit_id": result["audit_id"],
            "file_hash_short": result["file_hash"],
            "security_level": "enterprise",
            "upload_timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"엔터프라이즈 업로드 실패: {e}")
        raise HTTPException(status_code=500, detail=f"업로드 처리 실패: {str(e)}")

@router.get("/download-token/{attachment_id}")
async def generate_download_token(
    attachment_id: str,
    db=Depends(get_database),
    user=Depends(get_current_user),
    request: Request = None
):
    """
    보안 다운로드 토큰 생성
    - 권한 검증
    - 만료 시간 포함 (1시간)
    - HMAC 서명
    - 감사 로그 기록
    """
    try:
        # 사용자 데이터 준비
        user_data = {
            "user_id": str(user["_id"]),
            "username": user.get("username"),
            "role": user.get("role", "user"),
            "client_ip": request.client.host if request else "unknown",
            "user_agent": request.headers.get("user-agent") if request else None
        }

        # 토큰 생성
        success, message, result = await file_manager.generate_secure_download_token(
            attachment_id=attachment_id,
            user_data=user_data,
            db=db
        )

        if not success:
            raise HTTPException(status_code=403, detail=message)

        return {
            "success": True,
            "token": result["token"],
            "expires_in": result["expires_in"],
            "download_url": f"/api/enterprise-attachment/secure-download?token={result['token']}&attachment_id={attachment_id}",
            "generated_at": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"토큰 생성 실패: {e}")
        raise HTTPException(status_code=500, detail="토큰 생성에 실패했습니다")

@router.get("/secure-download")
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
    - 스트리밍 다운로드
    - 완전한 접근 로그
    """
    client_ip = request.client.host if request else "unknown"

    try:
        # 첨부파일 조회
        attachment = db.attachments.find_one({"_id": ObjectId(attachment_id)})

        if not attachment:
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다")

        # 토큰 검증
        is_valid = file_manager.security_manager.verify_download_token(
            token=token,
            attachment_id=attachment_id,
            user_id=attachment["uploader_id"]
        )

        if not is_valid:
            # 보안 이벤트 로그
            file_manager.audit_logger.log_security_event(
                event_type="invalid_download_token",
                severity="medium",
                details={
                    "attachment_id": attachment_id,
                    "client_ip": client_ip,
                    "attempted_token": token[:20] + "..." if len(token) > 20 else token
                }
            )
            raise HTTPException(status_code=403, detail="유효하지 않은 토큰입니다")

        # 파일 경로 확인
        file_path = attachment.get("file_path")
        if not file_path or not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="파일을 찾을 수 없습니다")

        # 파일 정보
        original_filename = attachment.get("original_filename", "download")
        file_size = attachment.get("file_size", 0)
        mime_type = attachment.get("mime_type", "application/octet-stream")

        # RFC5987 준수 파일명 인코딩
        import urllib.parse
        encoded_filename = urllib.parse.quote(original_filename, safe='')

        # 보안 헤더 설정
        headers = {
            # RFC5987 준수 Content-Disposition
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}",

            # 보안 헤더
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",

            # 파일 정보
            "Content-Length": str(file_size),
            "Content-Type": mime_type,

            # 추적 헤더
            "X-Download-Method": "enterprise-secure",
            "X-Security-Level": "high"
        }

        # 다운로드 시작 시간
        download_start = datetime.now()

        # 스트리밍 파일 생성기
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

        # 다운로드 완료 로그 (백그라운드)
        async def log_download_completion():
            download_end = datetime.now()
            duration_ms = int((download_end - download_start).total_seconds() * 1000)

            file_manager.audit_logger.log_access_audit(
                operation="download_completed",
                resource_data={
                    "resource_type": "file",
                    "attachment_id": attachment_id,
                    "file_path": file_path,
                    "file_size": file_size,
                    "mime_type": mime_type,
                    "bytes_transferred": file_size,
                    "transfer_duration_ms": duration_ms,
                    "token_used": True
                },
                user_data={
                    "user_id": attachment["uploader_id"],
                    "client_ip": client_ip
                },
                success=True,
                access_method="secure_token"
            )

        background_task = BackgroundTask(log_download_completion)

        return StreamingResponse(
            file_generator(),
            media_type=mime_type,
            headers=headers,
            background=background_task
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"보안 다운로드 실패: {e}")
        # 오류 로그
        file_manager.audit_logger.log_security_event(
            event_type="download_error",
            severity="medium",
            details={
                "attachment_id": attachment_id,
                "client_ip": client_ip,
                "error": str(e)
            }
        )
        raise HTTPException(status_code=500, detail="다운로드에 실패했습니다")

@router.post("/system/cleanup")
async def run_system_cleanup(
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """
    시스템 정리 실행
    - 드래프트 TTL 정리 (7일 후 자동 삭제)
    - 스토리지 하드닝 적용
    - 관리자만 실행 가능
    """
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="관리자만 실행할 수 있습니다")

    try:
        result = await file_manager.cleanup_system(db)

        return {
            "success": result["success"],
            "message": "시스템 정리 완료",
            "draft_cleanup": result["draft_cleanup"],
            "storage_hardening": result["storage_hardening"],
            "timestamp": result["timestamp"]
        }

    except Exception as e:
        logger.error(f"시스템 정리 실패: {e}")
        raise HTTPException(status_code=500, detail=f"시스템 정리 실패: {str(e)}")

@router.get("/system/status")
async def get_system_status(
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """
    시스템 상태 조회
    - 파일 통계
    - 드래프트 상태
    - 보안 상태
    - 감사 로그 요약
    """
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="관리자만 조회할 수 있습니다")

    try:
        status = await file_manager.get_system_status(db)
        return status

    except Exception as e:
        logger.error(f"시스템 상태 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="시스템 상태 조회에 실패했습니다")

@router.get("/audit-logs")
async def search_audit_logs(
    user_id: Optional[str] = Query(None, description="사용자 ID 필터"),
    operation: Optional[str] = Query(None, description="작업 유형 필터"),
    success: Optional[bool] = Query(None, description="성공/실패 필터"),
    start_date: Optional[str] = Query(None, description="시작 날짜 (ISO)"),
    end_date: Optional[str] = Query(None, description="종료 날짜 (ISO)"),
    limit: int = Query(100, description="결과 개수 제한"),
    user=Depends(get_current_user),
    db=Depends(get_database)
):
    """
    감사 로그 검색
    - 관리자만 접근 가능
    - 다양한 필터 지원
    - 사고 조사용
    """
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="관리자만 접근할 수 있습니다")

    try:
        # 필터 구성
        filters = {}
        if user_id:
            filters["user_id"] = user_id
        if operation:
            filters["operation"] = operation
        if success is not None:
            filters["success"] = success
        if start_date:
            filters["start_date"] = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        if end_date:
            filters["end_date"] = datetime.fromisoformat(end_date.replace('Z', '+00:00'))

        # 로그 검색
        logs = file_manager.audit_logger.search_audit_logs(filters, limit)

        return {
            "success": True,
            "logs": logs,
            "total_results": len(logs),
            "filters_applied": filters,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"감사 로그 검색 실패: {e}")
        raise HTTPException(status_code=500, detail="감사 로그 검색에 실패했습니다")

@router.get("/security-report")
async def generate_security_report(
    days: int = Query(7, description="보고서 기간 (일)"),
    user=Depends(get_current_user)
):
    """
    보안 보고서 생성
    - 지정된 기간의 감사 로그 분석
    - 보안 이벤트 요약
    - 관리자만 접근 가능
    """
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="관리자만 접근할 수 있습니다")

    try:
        report = file_manager.audit_logger.generate_audit_report(period_days=days)

        return {
            "success": True,
            "report": report,
            "generated_by": str(user["_id"]),
            "generated_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"보안 보고서 생성 실패: {e}")
        raise HTTPException(status_code=500, detail="보안 보고서 생성에 실패했습니다")

@router.get("/health")
async def health_check():
    """
    헬스 체크 엔드포인트
    - 시스템 가용성 확인
    - 모니터링 시스템용
    """
    try:
        return {
            "status": "healthy",
            "service": "enterprise-file-manager",
            "version": "1.0.0",
            "features": [
                "atomic_storage",
                "mime_double_check",
                "secure_download",
                "draft_ttl_cleanup",
                "storage_hardening",
                "audit_logging"
            ],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"헬스 체크 실패: {e}")
        raise HTTPException(status_code=503, detail="서비스 사용 불가")

# 직접 파일 접근 차단 (보안)
@router.get("/uploads/{path:path}")
async def block_direct_file_access(path: str):
    """
    직접 파일 경로 접근 차단
    - 보안 경고 기록
    - 403 Forbidden 응답
    """
    file_manager.audit_logger.log_security_event(
        event_type="direct_file_access_blocked",
        severity="medium",
        details={
            "attempted_path": path,
            "blocked_reason": "Direct file access is forbidden"
        }
    )

    return JSONResponse(
        status_code=403,
        content={
            "error": "Direct file access forbidden",
            "message": "파일에 직접 접근할 수 없습니다. 적절한 다운로드 API를 사용하세요.",
            "security_level": "enterprise"
        },
        headers={
            "X-Security-Warning": "Direct file access blocked",
            "X-Content-Type-Options": "nosniff"
        }
    )
