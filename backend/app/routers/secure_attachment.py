import os
import shutil
import tempfile
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import HTTPBearer
from bson import ObjectId
import pytz
import io
import logging
import re
from urllib.parse import quote

from app.core.database import get_database
from app.utils.auth_middleware import get_current_user
from app.models.user import User
from app.utils.file_security import FileSecurityManager, setup_file_security
from app.utils.file_logger import file_activity_logger
from app.utils.file_version_manager import FileVersionManager
from app.services import gdrive  # 구글드라이브 서비스 추가

router = APIRouter()
security = HTTPBearer()

# 로거 설정
logger = logging.getLogger(__name__)

# 서울 타임존
seoul_tz = pytz.timezone('Asia/Seoul')

def _create_content_disposition_header(original_filename: str) -> str:
    """
    한글 파일명을 안전하게 처리하는 Content-Disposition 헤더 생성
    RFC 5987/6266 표준에 따라 filename과 filename* 모두 제공
    """
    # 1) ASCII 안전한 대체 파일명 (비ASCII 문자는 '_'로 변환)
    ascii_fallback = re.sub(r'[^\x20-\x7E]', '_', original_filename)

    # 2) UTF-8 퍼센트 인코딩
    utf8_encoded = quote(original_filename, safe='')

    # 3) RFC 5987 방식으로 두 가지 파일명 모두 제공
    return f'attachment; filename="{ascii_fallback}"; filename*=UTF-8\'\'{utf8_encoded}'

# 고급 파일 보안 관리자 초기화
file_security = setup_file_security(encryption_enabled=False)  # 필요시 True로 변경

# 기본 업로드 디렉토리
BASE_UPLOAD_DIR = "uploads/secure_attachments"
os.makedirs(BASE_UPLOAD_DIR, exist_ok=True)

# 최대 파일 크기 (50MB)
MAX_FILE_SIZE = 50 * 1024 * 1024

def get_client_ip(request: Request) -> str:
    """클라이언트 IP 주소 추출"""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def get_user_agent(request: Request) -> str:
    """User-Agent 추출"""
    return request.headers.get("user-agent", "unknown")

@router.post("/secure-upload")
async def secure_upload_file(
    request: Request,
    post_id: str = Form(...),
    file: UploadFile = File(...),
    description: str = Form(""),
    db=Depends(get_database),
    user: User = Depends(get_current_user)
):
    """고급 보안 파일 업로드"""

    user_id = user.id
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    # 상세한 요청 정보 로깅
    print(f"🔍 파일 업로드 요청:")
    print(f"  - 사용자 ID: {user_id}")
    print(f"  - 게시글 ID: {post_id}")
    print(f"  - 파일명: {file.filename}")
    print(f"  - 파일 크기: {file.size}")
    print(f"  - MIME 타입: {file.content_type}")
    print(f"  - 설명: {description}")
    print(f"  - IP 주소: {ip_address}")

    # 업로드 시도 로깅
    file_activity_logger.log_upload_attempt(
        user_id, file.filename, file.size, ip_address, user_agent
    )

    try:
        # 1. 기본 검증
        if not file.filename:
            raise HTTPException(status_code=400, detail="파일명이 필요합니다.")

        if file.size > MAX_FILE_SIZE:
            file_activity_logger.log_upload_failure(
                user_id, file.filename, f"파일 크기 초과: {file.size} bytes", ip_address
            )
            raise HTTPException(status_code=400, detail=f"파일 크기는 {MAX_FILE_SIZE // (1024*1024)}MB 이하여야 합니다.")

        # 2. 게시글 존재 확인 (Draft 상태 포함)
        try:
            print(f"🔍 게시글 검증 시작: {post_id}")
            post_oid = ObjectId(post_id)
            post = await db["board"].find_one({"_id": post_oid})

            if not post:
                print(f"❌ 게시글을 찾을 수 없음: {post_id}")
                raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")

            print(f"✅ 게시글 발견:")
            print(f"  - 게시글 ID: {post_id}")
            print(f"  - 상태: {post.get('status', 'unknown')}")
            print(f"  - 작성자 ID: {post.get('writer_id', 'unknown')}")
            print(f"  - 현재 사용자 ID: {user_id}")

            # Draft 게시글인 경우 작성자 확인 (보안 강화)
            if post.get("status") == "draft":
                # 타입 안전한 비교를 위해 문자열로 변환
                post_writer_id = str(post.get("writer_id", ""))
                current_user_id = str(user_id)

                print(f"🔍 Draft 게시글 권한 검증:")
                print(f"  - 게시글 작성자: {post_writer_id}")
                print(f"  - 현재 사용자: {current_user_id}")
                print(f"  - 권한 일치: {post_writer_id == current_user_id}")

                if post_writer_id != current_user_id:
                    print(f"❌ 권한 없음: 타인의 Draft 게시글에 파일 업로드 시도")
                    file_activity_logger.log_security_violation(
                        user_id, file.filename, f"타인의 Draft 게시글에 파일 업로드 시도: {post_id}", ip_address
                    )
                    raise HTTPException(status_code=403, detail="본인의 임시 게시글에만 파일을 업로드할 수 있습니다.")

                print(f"✅ Draft 게시글 권한 확인 완료")
            else:
                print(f"✅ Published 게시글 - 권한 검증 통과")

            # Published 게시글인 경우는 기존과 동일하게 처리 (추후 필요시 권한 확인 로직 추가 가능)

        except HTTPException as http_ex:
            print(f"❌ HTTP 예외 발생:")
            print(f"  - 상태 코드: {http_ex.status_code}")
            print(f"  - 상세 메시지: {http_ex.detail}")
            raise
        except Exception as e:
            print(f"❌ 시스템 예외 발생:")
            print(f"  - 예외 타입: {type(e).__name__}")
            print(f"  - 예외 메시지: {str(e)}")
            import traceback
            print(f"  - 스택 트레이스:")
            traceback.print_exc()

            file_activity_logger.log_upload_failure(
                user_id, file.filename, f"시스템 오류: {str(e)}", ip_address
            )
            raise HTTPException(
                status_code=500,
                detail=f"파일 업로드 중 오류가 발생했습니다. 오류 정보: {type(e).__name__}: {str(e)}"
            )

        # 3. 임시 파일로 저장하여 검사
        print(f"🔍 파일 검증 시작")
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            shutil.copyfileobj(file.file, temp_file)
            temp_path = temp_file.name
            print(f"  - 임시 파일 생성: {temp_path}")

        try:
            # 4. 파일 해시 계산
            print(f"🔍 파일 해시 계산 중...")
            file_hash = file_security.calculate_file_hash(temp_path)
            print(f"  - 파일 해시: {file_hash}")

            # 5. 파일 타입 검증
            print(f"🔍 파일 타입 검증 중...")
            is_safe, message, detected_type = file_security.verify_file_type(temp_path)
            print(f"  - 안전 여부: {is_safe}")
            print(f"  - 메시지: {message}")
            print(f"  - 감지된 타입: {detected_type}")

            if not is_safe:
                print(f"❌ 파일 타입 검증 실패")
                file_activity_logger.log_security_violation(
                    user_id, "file_type_violation",
                    {"filename": file.filename, "reason": message, "detected_type": detected_type},
                    ip_address
                )
                raise HTTPException(status_code=400, detail=f"파일 검증 실패: {message}")

            # 6. 파일 내용 스캔
            print(f"🔍 파일 내용 스캔 중...")
            content_safe, scan_message = file_security.scan_file_content(temp_path)
            print(f"  - 내용 안전 여부: {content_safe}")
            print(f"  - 스캔 메시지: {scan_message}")

            if not content_safe:
                print(f"❌ 파일 내용 스캔 실패")
                file_activity_logger.log_security_violation(
                    user_id, "content_scan_violation",
                    {"filename": file.filename, "reason": scan_message},
                    ip_address
                )
                raise HTTPException(status_code=400, detail=f"파일 내용 검사 실패: {scan_message}")

            # 7. 버전 관리 시스템
            print(f"🔍 버전 관리 정보 생성 중...")
            version_manager = FileVersionManager(db)
            version_info = await version_manager.create_version_info(
                user_id, file.filename, file_hash, post_id
            )
            print(f"  - 버전 정보: {version_info}")

            # 8. 중복 파일 처리
            if version_info.get("is_duplicate"):
                existing_file = version_info["existing_file"]
                print(f"⚠️ 중복 파일 발견: {existing_file['id']}")
                file_activity_logger.log_upload_failure(
                    user_id, file.filename,
                    f"중복 파일 (기존 파일 ID: {existing_file['id']})", ip_address
                )
                return {
                    "message": "동일한 파일이 이미 존재합니다.",
                    "existing_file": existing_file,
                    "is_duplicate": True
                }

            # 9. 안전한 파일명 생성
            secure_filename, unique_id = file_security.generate_secure_filename(
                version_info["versioned_filename"], user_id
            )

            # 10. 사용자별 디렉터리 경로 생성
            user_dir = file_security.get_user_directory_path(user_id, BASE_UPLOAD_DIR)
            final_path = os.path.join(user_dir, secure_filename)

            # 11. 파일 이동
            shutil.move(temp_path, final_path)

            # 12. 파일 타입 분류
            file_type = get_file_type(file.filename)

            # 13. 데이터베이스에 첨부파일 정보 저장
            attachment_doc = {
                "post_id": post_id,
                "filename": secure_filename,
                "original_filename": file.filename,
                "original_filename_base": version_info["original_filename_base"],
                "version": version_info["version"],
                "file_size": file.size,
                "file_type": file_type,
                "mime_type": detected_type,
                "file_hash": file_hash,
                "upload_date": datetime.now(seoul_tz),
                "uploader_id": user_id,
                "file_path": final_path,
                "unique_id": unique_id,
                "description": description,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "is_encrypted": False,  # 향후 암호화 기능 활성화시 사용
                "scan_status": "clean",
                "download_count": 0
            }

            result = await db["attachments"].insert_one(attachment_doc)
            attachment_id = str(result.inserted_id)

            # 14. 성공 로깅
            file_activity_logger.log_upload_success(
                user_id, attachment_id, file.filename, file.size, file_hash, final_path, ip_address
            )

            # 15. 응답 데이터 준비
            attachment_doc["id"] = attachment_id
            del attachment_doc["_id"]
            del attachment_doc["file_path"]  # 보안상 경로 제외
            del attachment_doc["ip_address"]
            del attachment_doc["user_agent"]

            return {
                "message": "파일이 안전하게 업로드되었습니다.",
                "attachment": attachment_doc,
                "security_info": {
                    "hash_verified": True,
                    "content_scanned": True,
                    "version": version_info["version"]
                }
            }

        finally:
            # 임시 파일 정리
            if os.path.exists(temp_path):
                os.remove(temp_path)
                print(f"🧹 임시 파일 삭제: {temp_path}")

    except HTTPException as http_ex:
        print(f"❌ 최종 HTTP 예외:")
        print(f"  - 상태 코드: {http_ex.status_code}")
        print(f"  - 상세 메시지: {http_ex.detail}")
        raise
    except Exception as e:
        print(f"❌ 최종 시스템 예외:")
        print(f"  - 예외 타입: {type(e).__name__}")
        print(f"  - 예외 메시지: {str(e)}")
        import traceback
        print(f"  - 스택 트레이스:")
        traceback.print_exc()

        file_activity_logger.log_upload_failure(
            user_id, file.filename, f"시스템 오류: {str(e)}", ip_address
        )
        raise HTTPException(
            status_code=500,
            detail=f"파일 업로드 중 오류가 발생했습니다. 오류 정보: {type(e).__name__}: {str(e)}"
        )

@router.get("/secure-download/{attachment_id}")
async def secure_download_file(
    request: Request,
    attachment_id: str,
    token: Optional[str] = None,
    db=Depends(get_database),
    user: User = Depends(get_current_user)
):
    """고급 보안 파일 다운로드 (로컬 + 구글드라이브 지원)"""

    user_id = user.id
    ip_address = get_client_ip(request)

    # 강제 출력으로 디버깅
    print(f"\n=== 🔥 SECURE DOWNLOAD DEBUG START ===")
    print(f"요청된 attachment_id: {attachment_id}")
    print(f"요청 사용자 ID: {user_id}")
    print(f"IP 주소: {ip_address}")
    print(f"=====================================\n")

    # 다운로드 시도 로깅
    try:
        file_activity_logger.log_download_attempt(
            user_id, attachment_id, "unknown", ip_address
        )
        print(f"✅ 다운로드 시도 로깅 완료")
    except Exception as e:
        print(f"❌ 다운로드 시도 로깅 실패: {e}")

    try:
        print(f"🔍 TRY 블록 시작 - attachment_id: {attachment_id}")

        # 1. 첨부파일 조회 (다양한 ID 형태 지원)
        attachment = None
        attachment_oid = None

        print(f"📋 첨부파일 조회 시작 - ID: {attachment_id}, 타입: {type(attachment_id)}, 길이: {len(attachment_id)}")
        logger.info(f"첨부파일 조회 시작 - ID: {attachment_id}, 타입: {type(attachment_id)}, 길이: {len(attachment_id)}")

        # ObjectId 형태로 먼저 시도 (24자리 16진수)
        try:
            if len(attachment_id) == 24 and all(c in '0123456789abcdefABCDEF' for c in attachment_id):
                print(f"🎯 ObjectId 형태로 조회 시도: {attachment_id}")
                attachment_oid = ObjectId(attachment_id)
                attachment = await db["attachments"].find_one({"_id": attachment_oid})
                if attachment:
                    print(f"✅ ObjectId로 조회 성공: {attachment_id}")
                    logger.info(f"ObjectId로 조회 성공: {attachment_id}")
                else:
                    print(f"❌ ObjectId로 조회했지만 데이터 없음: {attachment_id}")
        except Exception as e:
            print(f"❌ ObjectId로 조회 실패: {e}")
            logger.warning(f"ObjectId로 조회 실패: {e}")

        # ObjectId로 찾지 못했으면 attachment_id UUID로 조회
        if not attachment:
            print(f"🔄 UUID attachment_id로 조회 시도: {attachment_id}")
            attachment = await db["attachments"].find_one({"attachment_id": attachment_id})
            if attachment:
                print(f"✅ attachment_id로 조회 성공: {attachment_id}")
                logger.info(f"attachment_id로 조회 성공: {attachment_id}")
                attachment_oid = attachment["_id"]
            else:
                print(f"❌ attachment_id로도 조회 실패: {attachment_id}")

        if not attachment:
            print(f"💥 첨부파일을 찾을 수 없음 - ID: {attachment_id}")
            logger.error(f"첨부파일을 찾을 수 없음 - ID: {attachment_id}")
            file_activity_logger.log_download_failure(
                user_id, attachment_id, "파일을 찾을 수 없음", ip_address
            )
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다.")

        # 찾은 attachment 정보 로깅
        print(f"🎉 첨부파일 조회 성공!")
        print(f"📂 Storage Type: {attachment.get('storage_type', 'N/A')}")
        print(f"🗂️ Drive File ID: {attachment.get('drive_file_id', 'N/A')}")
        print(f"📄 Original Filename: {attachment.get('original_filename', 'N/A')}")
        print(f"👤 Uploader ID: {attachment.get('uploader_id', 'N/A')}")

        logger.info(f"첨부파일 조회 성공 - attachment 정보: {attachment}")
        logger.info(f"Storage Type: {attachment.get('storage_type', 'N/A')}")
        logger.info(f"Drive File ID: {attachment.get('drive_file_id', 'N/A')}")
        logger.info(f"Original Filename: {attachment.get('original_filename', 'N/A')}")

        # 2. 다운로드 권한 확인 (개선된 권한 시스템)
        print(f"🔐 권한 확인 - 업로더 ID: {attachment['uploader_id']}, 현재 사용자 ID: {user_id}")

        # 업로더 본인이면 항상 허용
        if attachment["uploader_id"] == user_id:
            print(f"✅ 권한 확인 통과 - 업로더 본인")
        else:
            # 게시글이 공개 게시글인지 확인
            post_id = attachment.get("post_id")
            if post_id:
                print(f"🔍 게시글 공개 상태 확인 - post_id: {post_id}")
                # 게시글 정보 조회
                post = await db["posts"].find_one({"_id": ObjectId(post_id)})
                if post:
                    # 비공개 게시글이 아니라면 다운로드 허용
                    is_private = post.get("is_private", False)
                    if not is_private:
                        print(f"✅ 권한 확인 통과 - 공개 게시글의 첨부파일")
                    else:
                        print(f"❌ 권한 없음 - 비공개 게시글의 첨부파일")
                        file_activity_logger.log_access_denied(
                            user_id, attachment_id, "비공개 게시글 권한 없음", ip_address
                        )
                        raise HTTPException(status_code=403, detail="파일 다운로드 권한이 없습니다.")
                else:
                    print(f"⚠️ 게시글을 찾을 수 없음 - 업로더만 다운로드 허용 정책 적용")
                    # 게시글을 찾을 수 없는 경우 기본 정책 적용 (업로더만 허용)
                    file_activity_logger.log_access_denied(
                        user_id, attachment_id, "게시글 없음, 권한 없음", ip_address
                    )
                    raise HTTPException(status_code=403, detail="파일 다운로드 권한이 없습니다.")
            else:
                print(f"⚠️ post_id 없음 - 업로더만 다운로드 허용 정책 적용")
                # post_id가 없는 경우 기본 정책 적용 (업로더만 허용)
                file_activity_logger.log_access_denied(
                    user_id, attachment_id, "post_id 없음, 권한 없음", ip_address
                )
                raise HTTPException(status_code=403, detail="파일 다운로드 권한이 없습니다.")

        # 3. 토큰 검증 (제공된 경우)
        if token:
            print(f"🔑 토큰 검증 시작 - 토큰: {token[:20]}...")
            if not file_security.verify_download_token(token, attachment_id, user_id):
                print(f"❌ 토큰 검증 실패")
                file_activity_logger.log_access_denied(
                    user_id, attachment_id, "잘못된 다운로드 토큰", ip_address
                )
                raise HTTPException(status_code=403, detail="유효하지 않은 다운로드 토큰입니다.")
            print(f"✅ 토큰 검증 통과")

        # 4. 저장소 타입에 따른 파일 처리
        storage_type = attachment.get("storage_type", "local")
        print(f"💾 저장소 타입: {storage_type}")

        if storage_type == "google_drive_structured":
            print(f"🔄 구글드라이브 구조화 저장 방식으로 처리 시작")
            # 구글드라이브 구조화 저장 방식
            drive_file_id = attachment.get("drive_file_id")
            print(f"📁 Drive File ID: {drive_file_id}")

            if not drive_file_id:
                print(f"❌ 구글드라이브 파일 ID 없음")
                logger.error(f"구글드라이브 파일 ID 없음 - attachment_id: {attachment_id}, attachment: {attachment}")
                raise HTTPException(status_code=404, detail="구글드라이브 파일 ID를 찾을 수 없습니다.")

            print(f"🚀 구글드라이브 다운로드 시작 - attachment_id: {attachment_id}, drive_file_id: {drive_file_id}")
            logger.info(f"구글드라이브 다운로드 시작 - attachment_id: {attachment_id}, drive_file_id: {drive_file_id}")
            logger.info(f"첨부파일 정보 - original_filename: {attachment.get('original_filename')}, structured_filename: {attachment.get('structured_filename')}")

            try:
                print(f"📡 Google Drive API 호출 시작 - file_id: {drive_file_id}")
                # 구글드라이브에서 파일 다운로드
                file_content = await gdrive.download_file(drive_file_id)
                print(f"✅ Google Drive API 호출 성공 - 파일 크기: {len(file_content)} bytes")

                logger.info(f"구글드라이브 파일 다운로드 성공 - 크기: {len(file_content)} bytes")

                # 파일 무결성 검증 (구글드라이브용) - 근본적 해결 완료
                print(f"🔐 파일 무결성 검증 시작")
                if attachment.get("file_hash"):
                    import hashlib
                    current_hash = hashlib.sha256(file_content).hexdigest()
                    print(f"📊 해시 비교 - 저장된 해시: {attachment['file_hash'][:20]}...")
                    print(f"📊 해시 비교 - 현재 해시: {current_hash[:20]}...")
                    if current_hash != attachment["file_hash"]:
                        print(f"❌ 파일 무결성 검증 실패 - 데이터 손상 가능성")
                        # 실제 해시 불일치는 보안 문제이므로 엄격하게 처리
                        file_activity_logger.log_security_violation(
                            user_id, "gdrive_integrity_violation",
                            {
                                "attachment_id": attachment_id,
                                "drive_file_id": drive_file_id,
                                "stored_hash": attachment["file_hash"][:20] + "...",
                                "current_hash": current_hash[:20] + "...",
                                "reason": "file_integrity_mismatch"
                            },
                            ip_address
                        )
                        # 해시 불일치는 파일 손상을 의미하므로 다운로드 차단
                        raise HTTPException(
                            status_code=500,
                            detail="파일 무결성 검증에 실패했습니다. 파일이 손상되었을 가능성이 있습니다."
                        )
                    print(f"✅ 파일 무결성 검증 통과")

                print(f"📈 다운로드 카운트 증가")
                # 다운로드 카운트 증가
                await db["attachments"].update_one(
                    {"_id": attachment_oid},
                    {
                        "$inc": {"download_count": 1},
                        "$set": {"last_download_date": datetime.now(seoul_tz)}
                    }
                )

                print(f"📝 성공 로깅")
                # 성공 로깅
                file_activity_logger.log_download_success(
                    user_id, attachment_id, attachment["original_filename"],
                    attachment["file_size"], ip_address
                )

                print(f"📤 파일 스트림 응답 준비")
                # 🚀 최적화된 스트림 응답 (Content-Length 헤더 추가)
                headers = {
                    "Content-Disposition": _create_content_disposition_header(attachment['original_filename']),
                    "Content-Length": str(len(file_content)),  # 브라우저 진행률 표시
                    "Accept-Ranges": "bytes",  # 부분 다운로드 지원
                    "Cache-Control": "private, no-cache"  # 캐시 제어
                }

                print(f"🎉 파일 다운로드 성공! 응답 반환 (크기: {len(file_content):,} bytes)")
                return StreamingResponse(
                    io.BytesIO(file_content),
                    media_type=attachment["mime_type"] or "application/octet-stream",
                    headers=headers
                )

            except Exception as e:
                print(f"💥 Google Drive 다운로드 예외 발생!")
                print(f"❌ 예외 타입: {type(e).__name__}")
                print(f"❌ 예외 메시지: {str(e)}")
                import traceback
                print(f"❌ 스택 트레이스:")
                traceback.print_exc()

                logger.error(f"구글드라이브 다운로드 실패 - attachment_id: {attachment_id}, drive_file_id: {drive_file_id}, 오류: {str(e)}", exc_info=True)
                file_activity_logger.log_download_failure(
                    user_id, attachment_id, f"구글드라이브 다운로드 실패: {str(e)}", ip_address
                )
                raise HTTPException(status_code=500, detail=f"구글드라이브에서 파일 다운로드 실패: {str(e)}")

        else:
            # 기존 로컬 파일 시스템 방식
            file_path = attachment["file_path"]
            if not os.path.exists(file_path):
                file_activity_logger.log_download_failure(
                    user_id, attachment_id, "파일이 존재하지 않음", ip_address
                )
                raise HTTPException(status_code=404, detail="파일이 존재하지 않습니다.")

            # 5. 파일 무결성 검증 (로컬 파일용)
            current_hash = file_security.calculate_file_hash(file_path)
            stored_hash = attachment.get("file_hash")

            if stored_hash and current_hash != stored_hash:
                file_activity_logger.log_security_violation(
                    user_id, "file_integrity_violation",
                    {"attachment_id": attachment_id, "stored_hash": stored_hash, "current_hash": current_hash},
                    ip_address
                )
                raise HTTPException(status_code=500, detail="파일 무결성 검증에 실패했습니다.")

            # 6. 다운로드 카운트 증가
            await db["attachments"].update_one(
                {"_id": attachment_oid},
                {
                    "$inc": {"download_count": 1},
                    "$set": {"last_download_date": datetime.now(seoul_tz)}
                }
            )

            # 7. 성공 로깅
            file_activity_logger.log_download_success(
                user_id, attachment_id, attachment["original_filename"],
                attachment["file_size"], ip_address
            )

            # 8. 파일 응답
            return FileResponse(
                path=file_path,
                filename=attachment["original_filename"],
                media_type=attachment["mime_type"]
            )

    except HTTPException as http_ex:
        print(f"🚨 HTTP 예외 발생 - 상태코드: {http_ex.status_code}, 메시지: {http_ex.detail}")
        raise
    except Exception as e:
        print(f"💥 최종 예외 처리 - 예외 타입: {type(e).__name__}")
        print(f"💥 최종 예외 처리 - 예외 메시지: {str(e)}")
        import traceback
        print(f"💥 최종 예외 처리 - 스택 트레이스:")
        traceback.print_exc()

        file_activity_logger.log_download_failure(
            user_id, attachment_id, f"시스템 오류: {str(e)}", ip_address
        )
        raise HTTPException(status_code=500, detail="파일 다운로드 중 오류가 발생했습니다.")

@router.get("/download-token/{attachment_id}")
async def generate_download_token(
    attachment_id: str,
    db=Depends(get_database),
    user: User = Depends(get_current_user)
):
    """다운로드 토큰 생성"""

    user_id = user.id

    try:
        # 첨부파일 확인
        attachment_oid = ObjectId(attachment_id)
        attachment = await db["attachments"].find_one({"_id": attachment_oid})

        if not attachment:
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다.")

        # 권한 확인 (개선된 권한 시스템)
        if attachment["uploader_id"] == user_id:
            # 업로더 본인이면 항상 허용
            pass
        else:
            # 게시글이 공개 게시글인지 확인
            post_id = attachment.get("post_id")
            if post_id:
                # 게시글 정보 조회
                post = await db["posts"].find_one({"_id": ObjectId(post_id)})
                if post:
                    # 비공개 게시글이라면 토큰 생성 거부
                    is_private = post.get("is_private", False)
                    if is_private:
                        raise HTTPException(status_code=403, detail="토큰 생성 권한이 없습니다.")
                else:
                    # 게시글을 찾을 수 없는 경우 토큰 생성 거부
                    raise HTTPException(status_code=403, detail="토큰 생성 권한이 없습니다.")
            else:
                # post_id가 없는 경우 토큰 생성 거부
                raise HTTPException(status_code=403, detail="토큰 생성 권한이 없습니다.")

        # 토큰 생성 (1시간 유효)
        token = file_security.generate_download_token(attachment_id, user_id, 3600)

        return {
            "token": token,
            "expires_in": 3600,
            "download_url": f"/api/secure-attachment/secure-download/{attachment_id}?token={token}"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="토큰 생성 중 오류가 발생했습니다.")

@router.get("/post/{post_id}/versions")
async def get_post_attachments_with_versions(
    post_id: str,
    db=Depends(get_database),
    user: User = Depends(get_current_user)
):
    """게시글의 첨부파일 및 버전 정보 조회"""

    try:
        # 게시글의 모든 첨부파일 조회
        attachments_cursor = db["attachments"].find({"post_id": post_id}).sort("upload_date", -1)
        attachments = await attachments_cursor.to_list(length=200)

        # 버전별로 그룹화
        version_groups = {}

        for attachment in attachments:
            attachment["id"] = str(attachment["_id"])
            del attachment["_id"]
            del attachment["file_path"]
            if "ip_address" in attachment:
                del attachment["ip_address"]
            if "user_agent" in attachment:
                del attachment["user_agent"]

            base_name = attachment.get("original_filename_base", attachment["original_filename"])

            if base_name not in version_groups:
                version_groups[base_name] = []

            version_groups[base_name].append(attachment)

        return {
            "post_id": post_id,
            "total_files": len(attachments),
            "version_groups": version_groups
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail="첨부파일 조회 중 오류가 발생했습니다.")

@router.delete("/secure-delete/{attachment_id}")
async def secure_delete_file(
    request: Request,
    attachment_id: str,
    reason: str = Form("사용자 요청"),
    db=Depends(get_database),
    user: User = Depends(get_current_user)
):
    """고급 보안 파일 삭제"""

    user_id = user.id
    ip_address = get_client_ip(request)

    try:
        # UUID와 ObjectId 형식을 모두 처리할 수 있도록 개선
        attachment = None
        attachment_oid = None

        print(f"🔍 첨부파일 삭제 요청 - ID: {attachment_id}, 타입: {type(attachment_id)}, 길이: {len(attachment_id)}")

        # 먼저 ObjectId 형식으로 시도 (24자리 16진수)
        try:
            if len(attachment_id) == 24 and all(c in '0123456789abcdefABCDEF' for c in attachment_id):
                attachment_oid = ObjectId(attachment_id)
                attachment = await db["attachments"].find_one({"_id": attachment_oid})
                if attachment:
                    print(f"✅ ObjectId로 검색 성공: {attachment_id}")
        except Exception as e:
            print(f"❌ ObjectId로 검색 실패: {e}")

        # ObjectId로 찾지 못했으면 UUID 또는 문자열 ID로 검색
        if not attachment:
            # unique_id 필드로 검색 (UUID가 unique_id에 저장되었을 가능성)
            attachment = await db["attachments"].find_one({"unique_id": attachment_id})
            if attachment:
                print(f"✅ unique_id로 검색 성공: {attachment_id}")
                attachment_oid = attachment["_id"]
            else:
                # id 필드로도 검색 시도
                attachment = await db["attachments"].find_one({"id": attachment_id})
                if attachment:
                    print(f"✅ id 필드로 검색 성공: {attachment_id}")
                    attachment_oid = attachment["_id"]

        if not attachment:
            print(f"❌ 모든 방법으로 첨부파일 검색 실패: {attachment_id}")
            raise HTTPException(status_code=404, detail="첨부파일을 찾을 수 없습니다.")

        # 삭제 권한 확인 (업로더만 삭제 가능)
        if attachment["uploader_id"] != user_id:
            raise HTTPException(status_code=403, detail="파일 삭제 권한이 없습니다.")

        # 파일 시스템에서 파일 삭제
        file_path = attachment["file_path"]
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"✅ 파일 시스템에서 삭제 완료: {file_path}")
            except Exception as e:
                print(f"❌ 파일 삭제 오류: {e}")

        # 데이터베이스에서 첨부파일 정보 삭제
        delete_result = await db["attachments"].delete_one({"_id": attachment_oid})
        print(f"✅ 데이터베이스에서 삭제 완료: {delete_result.deleted_count}개 문서")

        # 삭제 로깅
        file_activity_logger.log_file_deletion(
            user_id, attachment_id, attachment["original_filename"], user_id, reason
        )

        return {"message": "첨부파일이 안전하게 삭제되었습니다."}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="파일 삭제 중 오류가 발생했습니다.")

def get_file_type(filename: str) -> str:
    """파일 확장자에 따른 파일 타입 분류"""
    ext = os.path.splitext(filename.lower())[1]

    if ext in ['.txt']:
        return 'text'
    elif ext in ['.pdf']:
        return 'pdf'
    elif ext in ['.doc', '.docx']:
        return 'word'
    elif ext in ['.xls', '.xlsx']:
        return 'excel'
    elif ext in ['.ppt', '.pptx']:
        return 'powerpoint'
    elif ext in ['.hwp']:
        return 'hwp'
    elif ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
        return 'image'
    elif ext in ['.zip', '.rar', '.7z']:
        return 'archive'
    elif ext in ['.mp4', '.avi', '.mov']:
        return 'video'
    elif ext in ['.mp3', '.wav']:
        return 'audio'
    else:
        return 'other'
