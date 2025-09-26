import os
import re
import hashlib
import shutil
import uuid
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict, Optional, List
import pytz
import aiofiles
import tempfile

try:
    import puremagic
    PUREMAGIC_AVAILABLE = True
except ImportError:
    PUREMAGIC_AVAILABLE = False

try:
    import magic
    PYTHON_MAGIC_AVAILABLE = True
except ImportError:
    PYTHON_MAGIC_AVAILABLE = False

import mimetypes
import logging

# 로거 설정
logger = logging.getLogger(__name__)

class AdvancedFileManager:
    """
    고급 파일 업로드 관리 시스템
    옵션 B: /uploads/user/{user_id}/{YYYY}/{MM}/{DD}/{post_id}/{attachment_id}_{sha8}_{safe_basename}.{ext}
    """

    # 서울 타임존
    SEOUL_TZ = pytz.timezone('Asia/Seoul')

    # 허용된 확장자 (화이트리스트)
    ALLOWED_EXTENSIONS = {
        # 텍스트/문서
        '.txt', '.csv', '.md', '.rtf', '.json', '.xml',
        # MS Office & 호환 문서
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # 한글 문서 (구버전 + 신버전)
        '.hwp', '.hwpx',
        # LibreOffice 문서
        '.odt', '.ods', '.odp',
        # 이미지
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg', '.tiff', '.ico',
        # 비디오
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', '.m4v',
        # 오디오
        '.mp3', '.wav', '.flac', '.ogg', '.aac', '.m4a', '.wma',
        # 압축파일
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        # 기타 자주 사용되는 형식
        '.epub', '.mobi'  # 전자책
    }

    # 위험한 확장자 (블랙리스트)
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
        '.sh', '.bash', '.zsh', '.ps1', '.msi', '.deb', '.rpm', '.dmg',
        '.app', '.ipa', '.apk', '.pkg', '.run', '.bin', '.dll', '.so'
    }

    # 허용된 MIME 타입
    ALLOWED_MIME_TYPES = {
        # 텍스트/문서
        'text/plain', 'text/csv', 'text/markdown', 'text/rtf', 'application/json', 'application/xml', 'text/xml',
        # MS Office & PDF
        'application/pdf', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/powerpoint', 'application/mspowerpoint',
        # 한글 문서 (구버전 + 신버전)
        'application/vnd.hancom.hwp', 'application/haansofthwp',
        'application/vnd.hancom.hwpx', 'application/hwpx',
        # LibreOffice 문서
        'application/vnd.oasis.opendocument.text',           # .odt
        'application/vnd.oasis.opendocument.spreadsheet',    # .ods
        'application/vnd.oasis.opendocument.presentation',   # .odp
        # 이미지
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp', 'image/svg+xml',
        'image/tiff', 'image/x-icon', 'image/vnd.microsoft.icon',
        # 비디오
        'video/mp4', 'video/avi', 'video/quicktime', 'video/x-msvideo', 'video/webm', 'video/x-m4v',
        'video/x-ms-wmv', 'video/x-flv', 'video/x-matroska',
        # 오디오
        'audio/mpeg', 'audio/wav', 'audio/flac', 'audio/ogg', 'audio/aac',
        'audio/mp4', 'audio/x-m4a', 'audio/x-ms-wma',
        # 압축파일
        'application/zip', 'application/x-zip-compressed', 'application/x-zip',
        'application/x-rar-compressed', 'application/x-7z-compressed',
        'application/x-tar', 'application/gzip', 'application/x-bzip2',
        # 전자책
        'application/epub+zip', 'application/x-mobipocket-ebook',
        # 일반 바이너리 (확장자로 추가 검증)
        'application/octet-stream'
    }

    # 최대 파일 크기 (50MB)
    MAX_FILE_SIZE = 50 * 1024 * 1024

    def __init__(self, base_upload_dir: str = "uploads"):
        self.base_upload_dir = base_upload_dir
        os.makedirs(base_upload_dir, exist_ok=True)

        # 보안 권한 설정
        try:
            os.chmod(base_upload_dir, 0o750)  # rwxr-x---
        except OSError:
            pass  # Windows에서는 chmod가 제한적

    def sanitize_filename(self, filename: str) -> str:
        """파일명 정규화 및 보안 처리"""
        if not filename:
            return "untitled"

        # 유니코드 정규화 (NFC)
        filename = unicodedata.normalize('NFC', filename)

        # 파일명과 확장자 분리
        name, ext = os.path.splitext(filename)

        # 위험한 문자 제거 및 정규화
        # 경로 traversal 방지: .., /, \, :, *, ?, ", <, >, | 제거
        name = re.sub(r'[<>:"/\\|?*]', '', name)
        name = re.sub(r'\.\.+', '.', name)  # 연속 점 제거

        # 공백을 언더스코어로 변경
        name = re.sub(r'\s+', '_', name)

        # 연속 언더스코어 압축
        name = re.sub(r'_+', '_', name)

        # 앞뒤 공백, 점, 언더스코어 제거
        name = name.strip('._')

        # 빈 이름 처리
        if not name:
            name = "file"

        # 길이 제한 (확장자 포함 255자)
        max_name_length = 250 - len(ext)
        if len(name) > max_name_length:
            name = name[:max_name_length]

        return f"{name}{ext.lower()}"

    def calculate_file_hash(self, content: bytes) -> str:
        """파일 내용의 SHA-256 해시 계산"""
        return hashlib.sha256(content).hexdigest()

    def get_hash_prefix(self, file_hash: str, length: int = 8) -> str:
        """해시의 상위 N자리 반환"""
        return file_hash[:length]

    def verify_file_security(self, filename: str, content: bytes) -> Tuple[bool, str, str]:
        """다단계 파일 보안 검증"""
        # 1. 확장자 검사
        file_ext = Path(filename).suffix.lower()

        # 위험한 확장자 차단
        if file_ext in self.DANGEROUS_EXTENSIONS:
            return False, f"위험한 파일 확장자: {file_ext}", "security_risk"

        # 허용된 확장자 확인
        if file_ext not in self.ALLOWED_EXTENSIONS:
            return False, f"허용되지 않은 파일 확장자: {file_ext}", "not_allowed"

        # 2. 파일 크기 검사
        if len(content) > self.MAX_FILE_SIZE:
            return False, f"파일 크기 초과: {len(content)} bytes", "size_exceeded"

        # 3. MIME 타입 검증
        detected_mime = self._detect_mime_type(content, filename)

        # application/octet-stream인 경우 확장자 기반으로 추가 검증
        if detected_mime == "application/octet-stream":
            # Office 파일들 (docx, xlsx, pptx 등)은 ZIP 아카이브이므로 ZIP 시그니처 확인
            if file_ext in {'.docx', '.xlsx', '.pptx', '.hwpx'}:
                # ZIP 파일 시그니처 확인 (PK)
                if content[:2] == b'PK':
                    logger.info(f"Office 파일 ZIP 시그니처 확인: {filename}")
                else:
                    return False, f"손상된 Office 파일: {filename}", "corrupted_office"

            # PDF 파일 시그니처 확인
            elif file_ext == '.pdf':
                if content[:4] == b'%PDF':
                    logger.info(f"PDF 파일 시그니처 확인: {filename}")
                else:
                    return False, f"손상된 PDF 파일: {filename}", "corrupted_pdf"

            # 이미지 파일 시그니처 확인
            elif file_ext in {'.jpg', '.jpeg'}:
                if content[:3] == b'\xff\xd8\xff':
                    logger.info(f"JPEG 파일 시그니처 확인: {filename}")
                else:
                    return False, f"손상된 JPEG 파일: {filename}", "corrupted_jpeg"
            elif file_ext == '.png':
                if content[:8] == b'\x89PNG\r\n\x1a\n':
                    logger.info(f"PNG 파일 시그니처 확인: {filename}")
                else:
                    return False, f"손상된 PNG 파일: {filename}", "corrupted_png"
            elif file_ext == '.gif':
                if content[:6] in (b'GIF87a', b'GIF89a'):
                    logger.info(f"GIF 파일 시그니처 확인: {filename}")
                else:
                    return False, f"손상된 GIF 파일: {filename}", "corrupted_gif"

            # ZIP 파일 시그니처 확인
            elif file_ext == '.zip':
                if content[:2] == b'PK':
                    logger.info(f"ZIP 파일 시그니처 확인: {filename}")
                else:
                    return False, f"손상된 ZIP 파일: {filename}", "corrupted_zip"

            # 허용된 확장자라면 통과 (이미 1단계에서 확인됨)
            logger.info(f"MIME 타입 감지 실패, 확장자 기반 허용: {filename} ({file_ext})")
        elif detected_mime not in self.ALLOWED_MIME_TYPES:
            return False, f"허용되지 않은 MIME 타입: {detected_mime}", "mime_not_allowed"

        # 4. 악성 패턴 검사
        is_safe, scan_result = self._scan_content_patterns(content)
        if not is_safe:
            return False, f"위험한 패턴 발견: {scan_result}", "malicious_pattern"

        return True, "파일 보안 검사 통과", detected_mime

    def _detect_mime_type(self, content: bytes, filename: str) -> str:
        """다단계 MIME 타입 감지"""
        detected_mime = "application/octet-stream"

        # 1차: puremagic으로 시그니처 검사 (가장 정확)
        if PUREMAGIC_AVAILABLE:
            try:
                results = puremagic.from_string(content[:8192])  # 처음 8KB만 검사
                if results:
                    # puremagic.from_string은 확장자를 반환하므로 MIME 타입으로 변환
                    ext = results[0] if isinstance(results, list) else results
                    mime_type, _ = mimetypes.guess_type(f"test{ext}")
                    if mime_type:
                        detected_mime = mime_type
                        return detected_mime
            except Exception as e:
                logger.warning(f"puremagic 감지 실패: {e}")

        # 2차: python-magic 사용
        if PYTHON_MAGIC_AVAILABLE:
            try:
                detected_mime = magic.from_buffer(content[:8192], mime=True)
                return detected_mime
            except Exception as e:
                logger.warning(f"python-magic 감지 실패: {e}")

        # 3차: mimetypes로 확장자 기반 추정
        try:
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type:
                detected_mime = mime_type
        except Exception as e:
            logger.warning(f"mimetypes 감지 실패: {e}")

        return detected_mime

    def _scan_content_patterns(self, content: bytes) -> Tuple[bool, str]:
        """기본적인 악성 패턴 스캔"""
        try:
            # 처음 1MB만 스캔
            scan_content = content[:1024*1024].lower()

            # 위험한 패턴들
            dangerous_patterns = [
                b'eval(', b'exec(', b'system(', b'shell_exec(',
                b'<script', b'javascript:', b'vbscript:',
                b'cmd.exe', b'powershell.exe', b'/bin/sh',
                b'rm -rf', b'format c:', b'del /f'
            ]

            for pattern in dangerous_patterns:
                if pattern in scan_content:
                    return False, pattern.decode('utf-8', errors='ignore')

            return True, "내용 스캔 통과"

        except Exception as e:
            logger.warning(f"내용 스캔 실패: {e}")
            return True, "스캔 건너뜀"

    def generate_file_path(self, user_id: str, username: str, post_id: str,
                          attachment_id: str, original_filename: str,
                          file_hash: str) -> Tuple[str, str]:
        """
        옵션 B 스키마에 따른 파일 경로 생성
        /uploads/user/{user_id}/{YYYY}/{MM}/{DD}/{post_id}/{attachment_id}_{sha8}_{safe_basename}.{ext}
        """
        # Asia/Seoul 기준 날짜
        now = datetime.now(self.SEOUL_TZ)
        year = now.strftime("%Y")
        month = now.strftime("%m")
        day = now.strftime("%d")

        # 안전한 파일명 생성
        safe_basename = self.sanitize_filename(original_filename)

        # SHA-256 상위 8자
        sha8 = self.get_hash_prefix(file_hash, 8)

        # 최종 파일명: {attachment_id}_{sha8}_{safe_basename}
        final_filename = f"{attachment_id}_{sha8}_{safe_basename}"

        # 디렉터리 경로
        dir_path = os.path.join(
            self.base_upload_dir,
            "user",
            str(user_id),
            year, month, day,
            str(post_id)
        )

        # 전체 파일 경로
        file_path = os.path.join(dir_path, final_filename)

        return file_path, dir_path

    async def save_file_atomic(self, file_path: str, content: bytes) -> bool:
        """원자적 파일 저장 (임시파일→rename)"""
        try:
            # 디렉터리 생성
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # 임시 파일 생성
            temp_dir = os.path.dirname(file_path)
            with tempfile.NamedTemporaryFile(dir=temp_dir, delete=False) as temp_file:
                temp_path = temp_file.name
                temp_file.write(content)

            # 원자적 이동 (rename)
            shutil.move(temp_path, file_path)

            # 파일 권한 설정
            try:
                os.chmod(file_path, 0o640)  # rw-r-----
            except OSError:
                pass  # Windows에서는 chmod가 제한적

            return True

        except Exception as e:
            logger.error(f"파일 저장 실패: {e}")
            # 임시 파일 정리
            try:
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
            return False

    def check_duplicate_by_hash(self, file_hash: str, user_id: str = None) -> bool:
        """해시 기반 중복 파일 검사"""
        # 전체 uploads 디렉터리에서 해시 패턴 검색
        search_pattern = f"*_{self.get_hash_prefix(file_hash, 8)}_*"

        if user_id:
            # 특정 사용자 디렉터리에서만 검색
            user_base = os.path.join(self.base_upload_dir, "user", str(user_id))
            if os.path.exists(user_base):
                for root, dirs, files in os.walk(user_base):
                    for file in files:
                        if self.get_hash_prefix(file_hash, 8) in file:
                            return True
        else:
            # 전체 uploads에서 검색
            for root, dirs, files in os.walk(self.base_upload_dir):
                for file in files:
                    if self.get_hash_prefix(file_hash, 8) in file:
                        return True

        return False

    def create_file_metadata(self, user_id: str, username: str, post_id: str,
                           attachment_id: str, original_filename: str,
                           file_size: int, file_hash: str, mime_type: str,
                           file_path: str) -> Dict:
        """파일 메타데이터 생성"""
        now = datetime.now(self.SEOUL_TZ)

        return {
            "attachment_id": attachment_id,
            "post_id": post_id,
            "user_id": user_id,
            "username": username,
            "original_filename": original_filename,
            "safe_filename": self.sanitize_filename(original_filename),
            "file_size": file_size,
            "file_hash": file_hash,
            "file_hash_short": self.get_hash_prefix(file_hash, 8),
            "mime_type": mime_type,
            "file_type": self._get_file_category(mime_type),
            "file_path": file_path,
            "upload_date": now,
            "upload_date_iso": now.isoformat(),
            "upload_year": now.year,
            "upload_month": now.month,
            "upload_day": now.day
        }

    def _get_file_category(self, mime_type: str) -> str:
        """MIME 타입을 카테고리로 분류"""
        if mime_type.startswith('image/'):
            return 'image'
        elif mime_type.startswith('video/'):
            return 'video'
        elif mime_type.startswith('audio/'):
            return 'audio'
        elif mime_type.startswith('text/'):
            return 'text'
        elif 'pdf' in mime_type:
            return 'pdf'
        elif any(x in mime_type for x in ['word', 'document']):
            return 'document'
        elif any(x in mime_type for x in ['sheet', 'excel']):
            return 'spreadsheet'
        elif any(x in mime_type for x in ['presentation', 'powerpoint']):
            return 'presentation'
        elif any(x in mime_type for x in ['zip', 'rar', '7z', 'tar', 'gzip']):
            return 'archive'
        else:
            return 'other'

    def log_file_operation(self, operation: str, metadata: Dict,
                          success: bool, error_message: str = None):
        """파일 작업 로깅"""
        log_entry = {
            "timestamp": datetime.now(self.SEOUL_TZ).isoformat(),
            "operation": operation,
            "success": success,
            "user_id": metadata.get("user_id"),
            "post_id": metadata.get("post_id"),
            "attachment_id": metadata.get("attachment_id"),
            "filename": metadata.get("original_filename"),
            "file_size": metadata.get("file_size"),
            "file_hash": metadata.get("file_hash_short"),
            "mime_type": metadata.get("mime_type")
        }

        if error_message:
            log_entry["error"] = error_message

        logger.info(f"File operation: {log_entry}")

        # 파일 로그도 저장 (옵션)
        try:
            log_dir = os.path.join(self.base_upload_dir, "..", "logs")
            os.makedirs(log_dir, exist_ok=True)

            log_file = os.path.join(log_dir, f"file_operations_{datetime.now().strftime('%Y%m')}.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{log_entry}\n")
        except Exception as e:
            logger.warning(f"파일 로그 저장 실패: {e}")

    def cleanup_empty_directories(self, base_path: str):
        """빈 디렉터리 정리"""
        try:
            for root, dirs, files in os.walk(base_path, topdown=False):
                if not files and not dirs:
                    try:
                        os.rmdir(root)
                        logger.info(f"빈 디렉터리 삭제: {root}")
                    except OSError:
                        pass
        except Exception as e:
            logger.warning(f"디렉터리 정리 실패: {e}")

    def get_user_storage_info(self, user_id: str) -> Dict:
        """사용자 저장소 정보 조회"""
        user_base = os.path.join(self.base_upload_dir, "user", str(user_id))

        if not os.path.exists(user_base):
            return {
                "user_id": user_id,
                "total_files": 0,
                "total_size": 0,
                "directories": []
            }

        total_files = 0
        total_size = 0
        directories = []

        for root, dirs, files in os.walk(user_base):
            if files:
                dir_info = {
                    "path": root,
                    "file_count": len(files),
                    "size": sum(os.path.getsize(os.path.join(root, f)) for f in files)
                }
                directories.append(dir_info)
                total_files += len(files)
                total_size += dir_info["size"]

        return {
            "user_id": user_id,
            "total_files": total_files,
            "total_size": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "directories": directories
        }
