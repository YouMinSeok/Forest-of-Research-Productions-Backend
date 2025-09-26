"""
강화된 파일 보안 시스템
- MIME 이중검사 (브라우저 vs 실제 내용)
- 확장자 화이트리스트 강화
- 위장 파일 차단
- 다운로드 보안 게이트
"""

import os
import hashlib
import mimetypes
import tempfile
import uuid
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple, Dict, Optional, List
import base64
import hmac

try:
    import magic
    PYTHON_MAGIC_AVAILABLE = True
except ImportError:
    PYTHON_MAGIC_AVAILABLE = False

try:
    import puremagic
    PUREMAGIC_AVAILABLE = True
except ImportError:
    PUREMAGIC_AVAILABLE = False

logger = logging.getLogger(__name__)

class EnhancedFileSecurityManager:
    """강화된 파일 보안 관리 시스템"""

    # 허용된 확장자 (엄격한 화이트리스트)
    ALLOWED_EXTENSIONS = {
        '.pdf', '.txt', '.csv', '.md', '.rtf',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.hwp',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg',
        '.mp4', '.avi', '.mov', '.wmv', '.mp3', '.wav', '.flac',
        '.zip', '.rar', '.7z'
    }

    # 위험한 확장자 (블랙리스트)
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
        '.sh', '.bash', '.zsh', '.ps1', '.msi', '.deb', '.rpm', '.dmg',
        '.app', '.ipa', '.apk', '.pkg', '.run', '.bin', '.dll', '.so',
        '.php', '.asp', '.jsp', '.py', '.rb', '.pl', '.cgi'
    }

    # MIME 타입별 허용 확장자 매핑
    MIME_EXTENSION_MAP = {
        'application/pdf': ['.pdf'],
        'text/plain': ['.txt', '.md'],
        'text/csv': ['.csv'],
        'application/msword': ['.doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
        'application/vnd.ms-excel': ['.xls'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
        'application/vnd.ms-powerpoint': ['.ppt'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
        'application/vnd.hancom.hwp': ['.hwp'],
        'image/jpeg': ['.jpg', '.jpeg'],
        'image/png': ['.png'],
        'image/gif': ['.gif'],
        'image/bmp': ['.bmp'],
        'image/webp': ['.webp'],
        'image/svg+xml': ['.svg'],
        'video/mp4': ['.mp4'],
        'video/avi': ['.avi'],
        'video/quicktime': ['.mov'],
        'video/x-ms-wmv': ['.wmv'],
        'audio/mpeg': ['.mp3'],
        'audio/wav': ['.wav'],
        'audio/flac': ['.flac'],
        'application/zip': ['.zip'],
        'application/x-rar-compressed': ['.rar'],
        'application/x-7z-compressed': ['.7z']
    }

    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()

    def enhanced_mime_check(self, file_content: bytes, filename: str,
                           declared_mime: str = None) -> Tuple[bool, str, Dict]:
        """
        강화된 MIME 이중검사
        1. 브라우저가 선언한 MIME vs 실제 파일 내용 비교
        2. 확장자와 MIME 타입 일치성 검증
        3. 위장 파일 탐지
        """
        result = {
            'declared_mime': declared_mime,
            'detected_mime': None,
            'extension': Path(filename).suffix.lower(),
            'consistency_check': False,
            'security_level': 'unknown'
        }

        # 1. 확장자 검사
        file_ext = result['extension']
        if file_ext in self.DANGEROUS_EXTENSIONS:
            return False, f"위험한 파일 확장자: {file_ext}", result

        if file_ext not in self.ALLOWED_EXTENSIONS:
            return False, f"허용되지 않은 확장자: {file_ext}", result

        # 2. 실제 MIME 타입 감지 (다단계)
        detected_mime = self._detect_actual_mime(file_content, filename)
        result['detected_mime'] = detected_mime

        # 3. 브라우저 선언 vs 실제 내용 비교
        if declared_mime and detected_mime:
            if not self._is_mime_consistent(declared_mime, detected_mime):
                return False, f"MIME 불일치: 선언={declared_mime}, 실제={detected_mime}", result

        # 4. MIME와 확장자 일치성 검증
        if detected_mime in self.MIME_EXTENSION_MAP:
            allowed_exts = self.MIME_EXTENSION_MAP[detected_mime]
            if file_ext not in allowed_exts:
                return False, f"확장자-MIME 불일치: {file_ext} vs {detected_mime}", result

        # 5. 악성 패턴 스캔
        is_safe, scan_result = self._enhanced_content_scan(file_content)
        if not is_safe:
            return False, f"위험한 패턴: {scan_result}", result

        result['consistency_check'] = True
        result['security_level'] = 'high'

        return True, "보안 검사 통과", result

    def _detect_actual_mime(self, content: bytes, filename: str) -> str:
        """실제 파일 내용 기반 MIME 타입 감지"""
        detected_mime = "application/octet-stream"

        # 1차: python-magic (libmagic 기반, 가장 정확)
        if PYTHON_MAGIC_AVAILABLE:
            try:
                detected_mime = magic.from_buffer(content[:8192], mime=True)
                logger.debug(f"python-magic 감지: {detected_mime}")
                return detected_mime
            except Exception as e:
                logger.warning(f"python-magic 실패: {e}")

        # 2차: puremagic (순수 Python, 시그니처 기반)
        if PUREMAGIC_AVAILABLE:
            try:
                results = puremagic.magic(content[:8192])
                if results:
                    detected_mime = results[0].mime_type
                    logger.debug(f"puremagic 감지: {detected_mime}")
                    return detected_mime
            except Exception as e:
                logger.warning(f"puremagic 실패: {e}")

        # 3차: 파일 시그니처 직접 확인
        detected_mime = self._check_file_signature(content)
        if detected_mime != "application/octet-stream":
            return detected_mime

        # 4차: mimetypes (확장자 기반, 보조)
        try:
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type:
                detected_mime = mime_type
        except Exception as e:
            logger.warning(f"mimetypes 실패: {e}")

        return detected_mime

    def _check_file_signature(self, content: bytes) -> str:
        """파일 시그니처 직접 확인"""
        if len(content) < 8:
            return "application/octet-stream"

        # 주요 파일 시그니처 매핑
        signatures = {
            b'\x25\x50\x44\x46': 'application/pdf',  # PDF
            b'\x89\x50\x4E\x47': 'image/png',         # PNG
            b'\xFF\xD8\xFF': 'image/jpeg',            # JPEG
            b'\x47\x49\x46\x38': 'image/gif',         # GIF
            b'\x42\x4D': 'image/bmp',                 # BMP
            b'\x52\x49\x46\x46': 'video/avi',        # AVI
            b'\x00\x00\x00\x20\x66\x74\x79\x70': 'video/mp4',  # MP4
            b'\x50\x4B\x03\x04': 'application/zip',  # ZIP
            b'\x52\x61\x72\x21': 'application/x-rar-compressed',  # RAR
            b'\xD0\xCF\x11\xE0': 'application/msword'  # MS Office
        }

        for signature, mime_type in signatures.items():
            if content.startswith(signature):
                return mime_type

        return "application/octet-stream"

    def _is_mime_consistent(self, declared: str, detected: str) -> bool:
        """MIME 타입 일치성 검사"""
        # 정확히 일치
        if declared == detected:
            return True

        # 일반적인 변형 허용
        variations = {
            'text/plain': ['text/plain; charset=utf-8'],
            'image/jpeg': ['image/jpg'],
            'application/javascript': ['text/javascript'],
        }

        for base_type, allowed_variants in variations.items():
            if declared == base_type and detected in allowed_variants:
                return True
            if detected == base_type and declared in allowed_variants:
                return True

        # 주 타입이 같으면 허용 (예: image/*, text/*)
        declared_main = declared.split('/')[0]
        detected_main = detected.split('/')[0]

        if declared_main == detected_main and declared_main in ['image', 'text', 'audio', 'video']:
            return True

        return False

    def _enhanced_content_scan(self, content: bytes) -> Tuple[bool, str]:
        """강화된 악성 패턴 스캔"""
        try:
            # 처음 1MB만 스캔
            scan_content = content[:1024*1024].lower()

            # 실행 가능한 패턴
            executable_patterns = [
                b'mz\x90\x00',  # PE 헤더
                b'\x7felf',     # ELF 헤더
                b'\xca\xfe\xba\xbe',  # Java class
                b'\xfe\xed\xfa',      # Mach-O
            ]

            # 스크립트 패턴
            script_patterns = [
                b'<script',
                b'javascript:',
                b'vbscript:',
                b'eval(',
                b'exec(',
                b'system(',
                b'shell_exec(',
                b'cmd.exe',
                b'powershell',
                b'/bin/sh',
                b'/bin/bash'
            ]

            # 위험한 명령어
            dangerous_commands = [
                b'rm -rf',
                b'format c:',
                b'del /f',
                b'shutdown',
                b'reboot'
            ]

            all_patterns = executable_patterns + script_patterns + dangerous_commands

            for pattern in all_patterns:
                if pattern in scan_content:
                    return False, pattern.decode('utf-8', errors='ignore')

            return True, "안전"

        except Exception as e:
            logger.warning(f"콘텐츠 스캔 실패: {e}")
            return True, "스캔 건너뜀"

    def generate_secure_download_token(self, attachment_id: str, user_id: str,
                                      expires_in: int = 3600) -> str:
        """보안 다운로드 토큰 생성 (RFC5987 준수)"""
        expiry = int((datetime.now() + timedelta(seconds=expires_in)).timestamp())

        # 토큰 페이로드: attachment_id:user_id:expiry
        payload = f"{attachment_id}:{user_id}:{expiry}"

        # HMAC 서명
        signature = hmac.new(
            self.secret_key,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        # 최종 토큰: base64(payload:signature)
        token = base64.urlsafe_b64encode(f"{payload}:{signature}".encode()).decode()

        return token

    def verify_download_token(self, token: str, attachment_id: str, user_id: str) -> bool:
        """다운로드 토큰 검증"""
        try:
            # 토큰 디코딩
            decoded = base64.urlsafe_b64decode(token.encode()).decode()

            # 구성 요소 분리
            parts = decoded.rsplit(':', 1)
            if len(parts) != 2:
                return False

            payload, signature = parts
            payload_parts = payload.split(':')

            if len(payload_parts) != 3:
                return False

            token_attachment_id, token_user_id, expiry_str = payload_parts

            # 기본 검증
            if token_attachment_id != attachment_id or token_user_id != user_id:
                return False

            # 만료 시간 검증
            expiry = int(expiry_str)
            if datetime.now().timestamp() > expiry:
                return False

            # HMAC 서명 검증
            expected_signature = hmac.new(
                self.secret_key,
                payload.encode(),
                hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(signature, expected_signature)

        except Exception as e:
            logger.error(f"토큰 검증 실패: {e}")
            return False

    def generate_audit_log_entry(self, operation: str, user_id: str, attachment_id: str,
                                filename: str, file_size: int, sha256_hash: str,
                                mime_type: str, storage_path: str,
                                success: bool, error_msg: str = None) -> Dict:
        """감사 로그 항목 생성"""
        timestamp = datetime.now()

        entry = {
            # 필수 감사 정보
            'timestamp': timestamp.isoformat(),
            'timestamp_unix': int(timestamp.timestamp()),
            'operation': operation,
            'success': success,

            # 파일 정보
            'attachment_id': attachment_id,
            'original_filename': filename,
            'file_size_bytes': file_size,
            'sha256_full': sha256_hash,
            'sha256_short': sha256_hash[:8] if sha256_hash else None,
            'mime_detected': mime_type,
            'storage_path': storage_path,

            # 사용자 정보
            'uploaded_by': user_id,
            'user_id': user_id,

            # 메타데이터
            'created_at': timestamp.isoformat(),
            'file_extension': Path(filename).suffix.lower() if filename else None,

            # 오류 정보
            'error_message': error_msg if not success else None,

            # 보안 수준
            'security_level': 'high' if success else 'failed'
        }

        return entry

    def atomic_file_save(self, content: bytes, final_path: str) -> bool:
        """원자적 파일 저장 (임시→해시 검증→rename)"""
        try:
            # 디렉터리 생성
            os.makedirs(os.path.dirname(final_path), exist_ok=True)

            # 임시 파일 생성 (같은 디렉터리 내)
            temp_dir = os.path.dirname(final_path)
            with tempfile.NamedTemporaryFile(dir=temp_dir, delete=False, prefix='upload_') as temp_file:
                temp_path = temp_file.name
                temp_file.write(content)
                temp_file.flush()
                os.fsync(temp_file.fileno())  # 강제 디스크 플러시

            # 해시 재검증 (무결성 확인)
            with open(temp_path, 'rb') as f:
                saved_content = f.read()
                if saved_content != content:
                    os.remove(temp_path)
                    return False

            # 원자적 이동 (rename은 원자적 연산)
            os.rename(temp_path, final_path)

            # 보안 권한 설정
            try:
                os.chmod(final_path, 0o640)  # rw-r-----
                os.chmod(os.path.dirname(final_path), 0o750)  # rwxr-x---
            except OSError:
                logger.warning("권한 설정 실패 (Windows?)")

            return True

        except Exception as e:
            logger.error(f"원자적 파일 저장 실패: {e}")
            # 임시 파일 정리
            try:
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
            return False
