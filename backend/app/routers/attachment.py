# app/routers/attachment.py
import os
import uuid
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse, StreamingResponse
from app.core.database import get_database
from app.utils.security import get_current_user
from app.utils.advanced_file_manager import AdvancedFileManager
from app.services import gdrive  # 새로운 OAuth 기반 서비스
from app.models.attachment import AttachmentResponse
from bson import ObjectId
from datetime import datetime
import pytz
from typing import List, Optional
import logging
import io

# 로거 설정
logger = logging.getLogger(__name__)

router = APIRouter()

# 파일 관리자 초기화
file_manager = AdvancedFileManager(base_upload_dir="uploads")

# 서울 타임존
seoul_tz = pytz.timezone('Asia/Seoul')

@router.post("/upload")
async def upload_file_google_drive(
    post_id: str = Form(...),
    file: UploadFile = File(...),
    db=Depends(get_database),
    user=Depends(get_current_user),
    request: Request = None
):
    """
    Google Drive OAuth API를 사용한 파일 업로드 시스템
    - Google Drive OAuth 클라우드 저장소 사용
    - 다단계 보안 검증
    - SHA-256 해시 기반 중복 방지
    - Draft 게시글 지원
    """
    client_ip = request.client.host if request else "unknown"

    try:
        # 1. 기본 검증
        if not file.filename:
            raise HTTPException(status_code=400, detail="파일명이 필요합니다.")

        # 파일 내용 읽기
        file_content = await file.read()
        if not file_content:
            raise HTTPException(status_code=400, detail="빈 파일은 업로드할 수 없습니다.")

        # 2. 게시글 존재 확인 (Draft 상태 포함)
        try:
            post_oid = ObjectId(post_id)
            # 먼저 일반 게시글에서 찾기
            post = await db["board"].find_one({"_id": post_oid})
            is_draft = False

            # 일반 게시글에서 찾을 수 없으면 drafts 컬렉션에서 찾기
            if not post:
                post = await db["drafts"].find_one({"_id": post_oid})
                is_draft = True

            if not post:
                raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
        except Exception as e:
            raise HTTPException(status_code=400, detail="유효하지 않은 게시글 ID입니다.")

        # 3. 권한 확인 (Draft의 경우 작성자만, 발행된 글의 경우 일반 권한)
        if is_draft:
            # Draft 게시글인 경우 작성자만 파일 업로드 가능
            if post.get("writer_id") != str(user.id):
                logger.warning(f"Draft 파일 업로드 권한 없음 - 게시글 작성자: {post.get('writer_id')}, 현재 사용자: {str(user.id)}")
                raise HTTPException(status_code=403, detail="Draft 게시글의 작성자만 파일을 업로드할 수 있습니다.")
        else:
            # 발행된 게시글의 경우 일반적인 권한 확인 (필요시)
            pass

        # 4. 파일 해시 계산
        file_hash = file_manager.calculate_file_hash(file_content)
        hash_short = file_manager.get_hash_prefix(file_hash, 8)

        # 5. 보안 검증
        is_safe, security_message, detected_mime = file_manager.verify_file_security(
            file.filename, file_content
        )

        if not is_safe:
            logger.warning(f"보안 검증 실패 - 사용자: {str(user.id)}, 파일: {file.filename}, 이유: {security_message}")
            raise HTTPException(status_code=400, detail=f"파일 업로드 거부: {security_message}")

        # 6. 중복 파일 검사 (선택적 - 같은 사용자의 같은 파일)
        is_duplicate = file_manager.check_duplicate_by_hash(file_hash, str(user.id))
        if is_duplicate:
            # 중복이어도 허용하되 경고 로그
            logger.info(f"중복 파일 업로드 - 사용자: {str(user.id)}, 해시: {hash_short}")

        # 7. 첨부파일 ID 생성
        attachment_id = str(uuid.uuid4())

        # 8. Google Drive에 파일 업로드 (구조화된 폴더에 저장)
        try:
            # 날짜 정보 생성 (YYYY-MM-DD 형태)
            now = datetime.now(seoul_tz)
            date_str = now.strftime("%Y-%m-%d")
            timestamp = now.strftime("%Y%m%d_%H%M%S")
            safe_filename = f"{file.filename}_{timestamp}_{attachment_id[:8]}"

            logger.info(f"업로드 파일명 정보 - 원본: {file.filename}, safe_filename: {safe_filename}")

            # 구조화된 업로드 사용 (user/{user_id}/{year}/{month}/{day}/)
            drive_info = await gdrive.upload_bytes_structured(
                content=file_content,
                filename=safe_filename,
                user_id=str(user.id),
                date_str=date_str,
                mime=detected_mime
            )

            logger.info(f"Google Drive 구조화 업로드 성공 - 파일ID: {drive_info.get('id')}, 경로: user/{str(user.id)}/{date_str}/{safe_filename}")
            logger.info(f"Google Drive 응답 정보: {drive_info}")

            # 🔥 중요: 구글 드라이브에 실제 저장된 파일의 해시 계산
            logger.info("구글 드라이브에서 파일을 다시 다운로드하여 정확한 해시 계산 중...")
            actual_stored_content = await gdrive.download_file(drive_info['id'])
            actual_file_hash = file_manager.calculate_file_hash(actual_stored_content)

            logger.info(f"해시 비교 - 원본: {file_hash[:20]}..., 구글드라이브: {actual_file_hash[:20]}...")
            if file_hash != actual_file_hash:
                logger.warning(f"구글 드라이브 저장 후 해시 변경됨 - 원본: {file_hash}, 실제: {actual_file_hash}")
                file_hash = actual_file_hash  # 실제 저장된 파일의 해시 사용
                hash_short = file_manager.get_hash_prefix(file_hash, 8)

        except Exception as e:
            logger.error(f"Google Drive 구조화 업로드 실패 - 사용자: {str(user.id)}, 파일: {file.filename}, 오류: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"파일 업로드 실패: {str(e)}")

        # 9. 메타데이터 생성
        username = getattr(user, 'name', f"user_{str(user.id)}")
        metadata = file_manager.create_file_metadata(
            user_id=str(user.id),
            username=username,
            post_id=post_id,
            attachment_id=attachment_id,
            original_filename=file.filename,
            file_size=len(file_content),
            file_hash=file_hash,
            mime_type=detected_mime,
            file_path=f"google_drive_structured://{drive_info['id']}"  # 구조화된 Drive 경로 표시
        )

        # 10. 데이터베이스에 첨부파일 정보 저장
        attachment_doc = {
            "attachment_id": attachment_id,
            "post_id": post_id,
            "filename": drive_info['name'],  # Google Drive에 저장된 파일명
            "original_filename": file.filename,
            "safe_filename": metadata["safe_filename"],
            "file_size": len(file_content),
            "file_hash": file_hash,
            "file_hash_short": hash_short,
            "file_type": metadata["file_type"],
            "mime_type": detected_mime,
            "upload_date": datetime.now(seoul_tz),
            "uploader_id": str(user.id),
            "uploader_username": username,
            # Google Drive OAuth 관련 정보
            "storage_type": "google_drive_structured",
            "drive_file_id": drive_info['id'],
            "drive_filename": drive_info['name'],
            "drive_view_link": drive_info.get('webViewLink'),
            "drive_download_link": drive_info.get('webContentLink'),
            "drive_size": drive_info.get('size'),
            "drive_created_time": drive_info.get('createdTime'),
            # 구조화된 폴더 정보
            "structured_folder_path": f"user/{str(user.id)}/{date_str}",
            "structured_filename": safe_filename,
            # 기존 정보 유지
            "upload_ip": client_ip,
            "security_status": "verified",
            "is_duplicate": is_duplicate,
            "post_status": post.get("status", "published"),  # 게시글 상태 추가
            "is_draft_attachment": is_draft  # Draft 첨부파일 여부
        }

        result = await db["attachments"].insert_one(attachment_doc)
        attachment_doc["id"] = str(result.inserted_id)
        del attachment_doc["_id"]

        # 11. 로깅
        file_manager.log_file_operation(
            operation="google_drive_structured_upload",
            metadata={**metadata, "drive_file_id": drive_info['id']},
            success=True
        )

        # 12. 응답 (보안상 Google Drive 링크는 제한적으로 제공)
        response_data = {
            "id": attachment_doc["id"],
            "attachment_id": attachment_id,
            "filename": attachment_doc["safe_filename"],
            "original_filename": file.filename,
            "file_size": len(file_content),
            "file_type": metadata["file_type"],
            "mime_type": detected_mime,
            "upload_date": attachment_doc["upload_date"].isoformat(),
            "uploader_id": str(user.id),
            "file_hash_short": hash_short,
            "is_duplicate": is_duplicate,
            "is_draft_attachment": is_draft,
            "post_status": post.get("status", "published"),
            "_id": attachment_doc["id"],  # 프론트엔드 호환성
            "is_draft": is_draft,  # 추가 호환성 필드
            "security_status": "verified",  # 보안 검증 완료 상태
            "storage_type": "google_drive_structured",  # 저장소 타입
            "drive_file_id": drive_info['id']  # Google Drive 파일 ID
        }

        logger.info(f"Google Drive 구조화 파일 업로드 성공 - 사용자: {str(user.id)}, 파일: {file.filename}, DriveID: {drive_info['id']}, Draft: {is_draft}")
        return response_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"파일 업로드 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="파일 업로드 중 오류가 발생했습니다.")

@router.post("/start-direct-upload")
async def start_direct_upload(
    post_id: str = Form(...),
    filename: str = Form(...),
    mime_type: str = Form(...),
    file_size: int = Form(...),
    db=Depends(get_database),
    user=Depends(get_current_user),
    request: Request = None
):
    """
    🚀 브라우저 직접 업로드용 Google Drive resumable 세션 생성
    속도 개선: 브라우저 → 백엔드 → 구글 드라이브 대신 브라우저 → 구글 드라이브 직접
    """
    client_ip = request.client.host if request else "unknown"

    try:
        # 1. 기본 검증
        if not filename:
            raise HTTPException(status_code=400, detail="파일명이 필요합니다.")

        # 2. 보안 검증
        try:
            validation_result = file_manager.validate_upload_security(
                filename=filename,
                content=b'',  # 직접 업로드에서는 내용 검증 생략
                file_size=file_size,
                client_ip=client_ip,
                user_id=str(user['_id']),
                skip_content_scan=True  # 구글 드라이브에서 바이러스 스캔 처리
            )
            if not validation_result['is_valid']:
                raise HTTPException(status_code=400, detail=validation_result['reason'])
        except Exception as e:
            logger.error(f"보안 검증 실패: {str(e)}")
            raise HTTPException(status_code=400, detail=f"보안 검증 실패: {str(e)}")

        # 3. 폴더 구조 생성 (구글 드라이브)
        user_id = str(user['_id'])
        date_str = datetime.now(seoul_tz).strftime('%Y-%m-%d')
        target_folder_id = await gdrive.create_folder_structure(user_id, date_str)

        # 4. 직접 업로드 세션 생성
        session_info = await gdrive.create_direct_upload_session(
            filename=filename,
            mime_type=mime_type,
            parent_folder_id=target_folder_id
        )

        logger.info(f"✅ 직접 업로드 세션 생성: {filename} for user {user_id}")

        return JSONResponse({
            "success": True,
            "upload_url": session_info["upload_url"],
            "access_token": session_info["access_token"],
            "expires_at": session_info["expires_at"],
            "chunk_size": 32 * 1024 * 1024,  # 32MB 청크 권장
            "message": "직접 업로드 세션이 생성되었습니다."
        })

    except Exception as e:
        logger.error(f"직접 업로드 세션 생성 실패: {str(e)}")
        raise HTTPException(status_code=500, detail=f"세션 생성 실패: {str(e)}")

@router.post("/complete-direct-upload")
async def complete_direct_upload(
    post_id: str = Form(...),
    filename: str = Form(...),
    file_id: str = Form(...),
    file_size: int = Form(...),
    db=Depends(get_database),
    user=Depends(get_current_user),
    request: Request = None
):
    """
    🚀 브라우저 직접 업로드 완료 후 메타데이터 저장
    """
    client_ip = request.client.host if request else "unknown"

    try:
        # 1. 파일 정보 조회 (구글 드라이브에서)
        service = await gdrive.get_cached_drive()
        file_metadata = service.files().get(
            fileId=file_id,
            fields="id,name,size,webViewLink,webContentLink,createdTime,md5Checksum"
        ).execute()

        # 2. 데이터베이스에 첨부파일 정보 저장
        user_id = str(user['_id'])
        timestamp = datetime.now(seoul_tz)

        attachment_doc = {
            "post_id": post_id,
            "filename": filename,
            "file_size": int(file_metadata.get('size', file_size)),
            "upload_timestamp": timestamp,
            "user_id": user_id,
            "storage_type": "google_drive_direct",
            "file_id": file_id,
            "download_url": file_metadata.get('webContentLink'),
            "view_url": file_metadata.get('webViewLink'),
            "md5_checksum": file_metadata.get('md5Checksum'),
            "client_ip": client_ip,
            "upload_method": "direct_upload"
        }

        result = db.attachments.insert_one(attachment_doc)
        attachment_doc['_id'] = str(result.inserted_id)

        logger.info(f"✅ 직접 업로드 완료: {filename} (file_id: {file_id})")

        return JSONResponse({
            "success": True,
            "attachment_id": str(result.inserted_id),
            "file_id": file_id,
            "download_url": file_metadata.get('webContentLink'),
            "view_url": file_metadata.get('webViewLink'),
            "message": "파일 업로드가 완료되었습니다."
        })

    except Exception as e:
        logger.error(f"직접 업로드 완료 처리 실패: {str(e)}")
        raise HTTPException(status_code=500, detail=f"업로드 완료 처리 실패: {str(e)}")

@router.get("/post/{post_id}")
async def get_post_attachments(
    post_id: str,
    db=Depends(get_database),
    user=Depends(get_current_user)  # Draft 접근 권한 확인을 위해 추가
):
    """게시글의 첨부파일 목록 조회 (Draft 지원)"""

    try:
        # 게시글 상태 확인
        try:
            post_oid = ObjectId(post_id)
            # 먼저 일반 게시글에서 찾기
            post = await db["board"].find_one({"_id": post_oid})
            is_draft = False

            # 일반 게시글에서 찾을 수 없으면 drafts 컬렉션에서 찾기
            if not post:
                post = await db["drafts"].find_one({"_id": post_oid})
                is_draft = True

            if not post:
                raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
        except Exception:
            raise HTTPException(status_code=400, detail="유효하지 않은 게시글 ID입니다.")

        # Draft 게시글의 경우 작성자만 조회 가능
        if is_draft and post.get("writer_id") != str(user.id):
            raise HTTPException(status_code=403, detail="Draft 게시글의 첨부파일은 작성자만 조회할 수 있습니다.")

        attachments_cursor = db["attachments"].find({"post_id": post_id}).sort("upload_date", 1)
        attachments = await attachments_cursor.to_list(length=100)

        for attachment in attachments:
            attachment["id"] = str(attachment["_id"])
            # attachment_id 필드를 유지 (삭제 시 필요)
            if "attachment_id" in attachment:
                attachment["attachment_id"] = attachment["attachment_id"]
            del attachment["_id"]
            # 보안상 실제 파일 경로와 해시는 제외
            attachment.pop("file_path", None)
            attachment.pop("directory_path", None)
            attachment.pop("file_hash", None)
            attachment.pop("upload_ip", None)
            attachment["upload_date"] = attachment["upload_date"].isoformat()

        return {
            "attachments": attachments,
            "count": len(attachments),
            "post_status": post.get("status", "published"),
            "is_draft": is_draft
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"첨부파일 목록 조회 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="첨부파일 목록을 가져올 수 없습니다.")

@router.get("/download/{attachment_id}")
async def download_file_google_drive(
    attachment_id: str,
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """Google Drive OAuth에서 파일 다운로드 (Draft 지원)"""

    try:
        # attachment_id 또는 ObjectId로 검색
        attachment = None  # 변수 초기화

        if len(attachment_id) == 24:  # ObjectId 길이
            try:
                attachment_oid = ObjectId(attachment_id)
                attachment = await db["attachments"].find_one({"_id": attachment_oid})
            except:
                attachment = None

        # attachment_id UUID로 검색
        if not attachment:
            attachment = await db["attachments"].find_one({"attachment_id": attachment_id})

        if not attachment:
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다.")

        # Draft 첨부파일의 경우 권한 확인
        if attachment.get("is_draft_attachment", False) or attachment.get("is_draft", False):
            # 게시글 작성자 확인
            post_oid = ObjectId(attachment["post_id"])
            # 먼저 일반 게시글에서 찾기
            post = await db["board"].find_one({"_id": post_oid})

            # 일반 게시글에서 찾을 수 없으면 drafts 컬렉션에서 찾기
            if not post:
                post = await db["drafts"].find_one({"_id": post_oid})

            if post and post.get("writer_id") != str(user.id):
                raise HTTPException(status_code=403, detail="Draft 게시글의 첨부파일은 작성자만 다운로드할 수 있습니다.")

        # Google Drive OAuth에서 파일 다운로드
        if attachment.get("storage_type") in ["google_drive_structured", "google_drive"] and attachment.get("drive_file_id"):
            try:
                file_data = await gdrive.download_file(attachment["drive_file_id"])

                # 다운로드 로깅
                logger.info(f"Google Drive OAuth 파일 다운로드 - 사용자: {str(user.id)}, 파일: {attachment['original_filename']}")

                # 스트리밍 응답으로 파일 제공
                return StreamingResponse(
                    io.BytesIO(file_data),
                    media_type=attachment["mime_type"],
                    headers={"Content-Disposition": f"attachment; filename={attachment['original_filename']}"}
                )

            except Exception as e:
                logger.error(f"Google Drive OAuth 다운로드 실패: {str(e)}")
                raise HTTPException(status_code=500, detail=f"파일 다운로드 실패: {str(e)}")
        else:
            # 기존 로컬 파일 시스템 호환성 (혹시 남아있는 경우)
            raise HTTPException(status_code=404, detail="파일을 찾을 수 없습니다.")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"파일 다운로드 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="파일 다운로드 중 오류가 발생했습니다.")

@router.delete("/{attachment_id}")
async def delete_attachment_google_drive(
    attachment_id: str,
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """Google Drive OAuth 첨부파일 삭제 (Draft 지원)"""

    try:
        # 첨부파일 찾기
        attachment = None  # 변수 초기화

        if len(attachment_id) == 24:  # ObjectId 길이
            try:
                attachment_oid = ObjectId(attachment_id)
                attachment = await db["attachments"].find_one({"_id": attachment_oid})
            except:
                attachment = None

        if not attachment:
            attachment = await db["attachments"].find_one({"attachment_id": attachment_id})

        if not attachment:
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다.")

        # 권한 확인 (업로더만 삭제 가능)
        if attachment["uploader_id"] != str(user.id):
            raise HTTPException(status_code=403, detail="파일 업로더만 삭제할 수 있습니다.")

        # Google Drive OAuth에서 파일 삭제
        if attachment.get("storage_type") in ["google_drive_structured", "google_drive"] and attachment.get("drive_file_id"):
            try:
                await gdrive.delete_file(attachment["drive_file_id"])
                logger.info(f"Google Drive OAuth 파일 삭제 성공: {attachment['drive_file_id']}")
            except Exception as e:
                logger.warning(f"Google Drive OAuth 파일 삭제 실패: {str(e)}")
                # Google Drive 삭제 실패해도 데이터베이스에서는 삭제 진행

        # 데이터베이스에서 첨부파일 정보 삭제
        if len(attachment_id) == 24:
            await db["attachments"].delete_one({"_id": attachment_oid})
        else:
            await db["attachments"].delete_one({"attachment_id": attachment_id})

        # 삭제 로깅
        file_manager.log_file_operation(
            operation="google_drive_structured_delete",
            metadata={
                "user_id": str(user.id),
                "attachment_id": attachment.get("attachment_id"),
                "original_filename": attachment.get("original_filename"),
                "drive_file_id": attachment.get("drive_file_id")
            },
            success=True
        )

        logger.info(f"Google Drive 구조화 첨부파일 삭제 완료 - 사용자: {str(user.id)}, 파일: {attachment['original_filename']}")
        return {"message": "첨부파일이 삭제되었습니다."}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"첨부파일 삭제 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="첨부파일 삭제 중 오류가 발생했습니다.")

@router.get("/draft/{post_id}/cleanup")
async def cleanup_draft_attachments(
    post_id: str,
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """Draft 게시글 삭제 시 첨부파일 정리 (관리자 또는 작성자만)"""

    try:
        # 게시글 확인
        try:
            post_oid = ObjectId(post_id)
            post = await db["board"].find_one({"_id": post_oid})
        except Exception:
            raise HTTPException(status_code=400, detail="유효하지 않은 게시글 ID입니다.")

        # 권한 확인 (작성자 또는 관리자)
        if post and post.get("writer_id") != str(user.id) and not getattr(user, 'is_admin', False):
            raise HTTPException(status_code=403, detail="권한이 없습니다.")

        # Draft 첨부파일 찾기
        attachments = await db["attachments"].find({"post_id": post_id}).to_list(None)

        deleted_count = 0
        for attachment in attachments:
            try:
                # 파일 시스템에서 삭제
                file_path = attachment.get("file_path")
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Draft 첨부파일 삭제: {file_path}")

                # 데이터베이스에서 삭제
                await db["attachments"].delete_one({"_id": attachment["_id"]})
                deleted_count += 1

            except Exception as e:
                logger.error(f"첨부파일 삭제 실패: {attachment.get('original_filename')}, 오류: {e}")

        # 빈 디렉터리 정리
        if attachments:
            try:
                first_attachment = attachments[0]
                dir_path = first_attachment.get("directory_path")
                if dir_path:
                    file_manager.cleanup_empty_directories(dir_path)
            except Exception as e:
                logger.warning(f"디렉터리 정리 실패: {e}")

        logger.info(f"Draft 첨부파일 정리 완료 - 게시글: {post_id}, 삭제된 파일: {deleted_count}개")

        return {
            "message": f"Draft 첨부파일 {deleted_count}개가 정리되었습니다.",
            "deleted_count": deleted_count
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Draft 첨부파일 정리 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="첨부파일 정리 중 오류가 발생했습니다.")

@router.get("/info/{attachment_id}")
async def get_attachment_info(attachment_id: str, db=Depends(get_database)):
    """첨부파일 상세 정보 조회"""

    try:
        # 첨부파일 찾기
        attachment = None  # 변수 초기화

        if len(attachment_id) == 24:  # ObjectId 길이
            try:
                attachment_oid = ObjectId(attachment_id)
                attachment = await db["attachments"].find_one({"_id": attachment_oid})
            except:
                attachment = None

        if not attachment:
            attachment = await db["attachments"].find_one({"attachment_id": attachment_id})

        if not attachment:
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다.")

        # 응답 데이터 준비 (보안 정보 제외)
        attachment["id"] = str(attachment.get("_id", ""))
        attachment.pop("_id", None)
        attachment.pop("file_path", None)
        attachment.pop("directory_path", None)
        attachment.pop("file_hash", None)
        attachment.pop("upload_ip", None)
        attachment["upload_date"] = attachment["upload_date"].isoformat()

        return attachment

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"첨부파일 정보 조회 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="첨부파일 정보를 가져올 수 없습니다.")

@router.get("/user/{user_id}/storage")
async def get_user_storage_info(
    user_id: str,
    db=Depends(get_database),
    current_user=Depends(get_current_user)
):
    """사용자 저장소 정보 조회"""

    try:
        # 권한 확인 (본인 또는 관리자만)
        if str(current_user.id) != user_id and not getattr(current_user, 'is_admin', False):
            raise HTTPException(status_code=403, detail="권한이 없습니다.")

        # 파일 시스템 기반 저장소 정보
        storage_info = file_manager.get_user_storage_info(user_id)

        # 데이터베이스 기반 통계
        db_stats = await db["attachments"].aggregate([
            {"$match": {"uploader_id": user_id}},
            {"$group": {
                "_id": None,
                "total_files": {"$sum": 1},
                "total_size": {"$sum": "$file_size"},
                "file_types": {"$addToSet": "$file_type"}
            }}
        ]).to_list(1)

        if db_stats:
            storage_info.update({
                "db_total_files": db_stats[0]["total_files"],
                "db_total_size": db_stats[0]["total_size"],
                "db_total_size_mb": round(db_stats[0]["total_size"] / (1024 * 1024), 2),
                "file_types": db_stats[0]["file_types"]
            })

        return storage_info

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"저장소 정보 조회 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="저장소 정보를 가져올 수 없습니다.")

@router.post("/migrate-old-files")
async def migrate_old_files(
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """기존 파일들을 새로운 스키마로 마이그레이션 (관리자 전용)"""

    if not getattr(user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")

    try:
        # 구현은 필요시에 추가
        return {"message": "마이그레이션 기능은 추후 구현 예정입니다."}

    except Exception as e:
        logger.error(f"파일 마이그레이션 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="마이그레이션 중 오류가 발생했습니다.")

@router.get("/google-drive/status")
async def get_google_drive_status(
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """Google Drive OAuth 연결 상태 확인"""
    try:
        # 연결 테스트
        success, error, folder_info = await gdrive.test_connection()

        if success:
            return {
                "status": "connected",
                "folder_id": os.environ.get("GDRIVE_FOLDER_ID"),
                "folder_name": folder_info.get("name", "Unknown"),
                "folder_link": folder_info.get("webViewLink", ""),
                "message": "Google Drive OAuth 연결이 정상입니다.",
                "auth_type": "oauth"
            }
        else:
            return {
                "status": "error",
                "folder_id": os.environ.get("GDRIVE_FOLDER_ID"),
                "error": error,
                "message": "Google Drive OAuth 연결에 문제가 있습니다. /api/google/start에서 재인증이 필요할 수 있습니다.",
                "auth_type": "oauth"
            }

    except Exception as e:
        logger.error(f"Google Drive OAuth 상태 확인 오류: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "message": "Google Drive OAuth 상태를 확인할 수 없습니다. 인증이 필요합니다.",
            "auth_type": "oauth",
            "auth_url": "/api/google/start"
        }

@router.get("/google-drive/test")
async def test_google_drive_connection(
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """Google Drive 연결 테스트 (관리자만)"""

    if not getattr(user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")

    try:
        # 1. 폴더 정보 확인
        folder_success, folder_error, folder_info = drive_manager.get_folder_info()

        # 2. 파일 목록 확인 (최근 10개)
        files_success, files_error, files_list = drive_manager.list_files(limit=10)

        test_results = {
            "timestamp": datetime.now(seoul_tz).isoformat(),
            "folder_test": {
                "success": folder_success,
                "error": folder_error,
                "info": folder_info if folder_success else None
            },
            "files_test": {
                "success": files_success,
                "error": files_error,
                "count": len(files_list) if files_success else 0,
                "files": files_list[:5] if files_success else []  # 최근 5개만 표시
            },
            "overall_status": "success" if folder_success and files_success else "partial_error"
        }

        return test_results

    except Exception as e:
        logger.error(f"Google Drive 연결 테스트 오류: {str(e)}")
        return {
            "timestamp": datetime.now(seoul_tz).isoformat(),
            "overall_status": "error",
            "error": str(e),
            "message": "Google Drive 연결 테스트 중 오류가 발생했습니다."
        }

@router.get("/storage-migration/status")
async def get_storage_migration_status(
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """저장소 마이그레이션 상태 확인"""

    if not getattr(user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")

    try:
        # 전체 첨부파일 통계
        total_attachments = await db["attachments"].count_documents({})

        # Google Drive 첨부파일 통계
        gdrive_attachments = await db["attachments"].count_documents({
            "storage_type": "google_drive"
        })

        # 로컬 저장소 첨부파일 통계 (storage_type이 없거나 local인 것들)
        local_attachments = await db["attachments"].count_documents({
            "$or": [
                {"storage_type": {"$exists": False}},
                {"storage_type": "local"},
                {"storage_type": {"$ne": "google_drive"}}
            ]
        })

        migration_percentage = round((gdrive_attachments / total_attachments * 100), 2) if total_attachments > 0 else 0

        return {
            "total_attachments": total_attachments,
            "google_drive_attachments": gdrive_attachments,
            "local_attachments": local_attachments,
            "migration_percentage": migration_percentage,
            "migration_complete": local_attachments == 0,
            "message": f"전체 {total_attachments}개 중 {gdrive_attachments}개가 Google Drive로 마이그레이션됨 ({migration_percentage}%)"
        }

    except Exception as e:
        logger.error(f"마이그레이션 상태 확인 오류: {str(e)}")
        raise HTTPException(status_code=500, detail="마이그레이션 상태를 확인할 수 없습니다.")
