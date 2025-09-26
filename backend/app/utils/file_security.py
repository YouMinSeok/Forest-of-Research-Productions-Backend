import hashlib
import os
import mimetypes

try:
    import puremagic
    PUREMAGIC_AVAILABLE = True
except ImportError:
    PUREMAGIC_AVAILABLE = False

try:
    import filetype
    FILETYPE_AVAILABLE = True
except ImportError:
    FILETYPE_AVAILABLE = False

try:
    import magic
    PYTHON_MAGIC_AVAILABLE = True
except ImportError:
    PYTHON_MAGIC_AVAILABLE = False
import uuid
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class FileSecurityManager:
    """고급 파일 보안 관리 시스템"""

    # 위험한 파일 확장자 (확장)
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
        '.sh', '.bash', '.zsh', '.ps1', '.msi', '.deb', '.rpm', '.dmg',
        '.app', '.ipa', '.apk', '.pkg', '.run', '.bin'
    }

    # 허용된 MIME 타입
    ALLOWED_MIME_TYPES = {
        'text/plain', 'text/csv', 'text/html', 'text/css',
        'application/pdf', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/vnd.hancom.hwp',
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
        'video/mp4', 'video/avi', 'video/quicktime', 'video/x-msvideo',
        'audio/mpeg', 'audio/wav', 'audio/x-wav',
        'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed'
    }

    def __init__(self, encryption_key: Optional[str] = None):
        self.encryption_key = encryption_key
        if encryption_key:
            self.cipher = Fernet(encryption_key.encode())

    def calculate_file_hash(self, file_path: str) -> str:
        """파일의 SHA-256 해시 계산"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # 큰 파일을 위해 청크 단위로 읽기
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise Exception(f"파일 해시 계산 실패: {str(e)}")

    def calculate_content_hash(self, content: bytes) -> str:
        """파일 내용의 SHA-256 해시 계산"""
        return hashlib.sha256(content).hexdigest()

    def verify_file_type(self, file_path: str) -> Tuple[bool, str, str]:
        """다단계 파일 타입 검증"""
        try:
            # 파일 확장자 검사
            file_ext = Path(file_path).suffix.lower()
            if file_ext in self.DANGEROUS_EXTENSIONS:
                return False, "위험한 파일 확장자", file_ext

            detected_mime = None

            # 1차: puremagic으로 시그니처 검사 (가장 신뢰도 높음)
            if PUREMAGIC_AVAILABLE:
                try:
                    with open(file_path, 'rb') as f:
                        first_chunk = f.read(8192)  # 처음 8KB만 읽기

                    results = puremagic.magic(first_chunk)
                    if results:
                        detected_mime = results[0].mime_type
                        if detected_mime in self.ALLOWED_MIME_TYPES:
                            return True, "안전한 파일 (puremagic)", detected_mime
                        else:
                            # 허용되지 않는 MIME 타입이지만 다음 단계로 진행
                            pass
                except Exception as e:
                    print(f"puremagic 검증 실패: {e}")

            # 2차: filetype으로 경량 시그니처 검사
            if FILETYPE_AVAILABLE:
                try:
                    kind = filetype.guess(file_path)
                    if kind is not None:
                        detected_mime = kind.mime
                        if detected_mime in self.ALLOWED_MIME_TYPES:
                            return True, "안전한 파일 (filetype)", detected_mime
                        else:
                            # 허용되지 않는 MIME 타입이지만 다음 단계로 진행
                            pass
                except Exception as e:
                    print(f"filetype 검증 실패: {e}")

            # 3차: python-magic 시도 (환경에 따라 실패할 수 있음)
            if PYTHON_MAGIC_AVAILABLE:
                try:
                    detected_mime = magic.from_file(file_path, mime=True)
                    if detected_mime in self.ALLOWED_MIME_TYPES:
                        return True, "안전한 파일 (python-magic)", detected_mime
                    else:
                        # 허용되지 않는 MIME 타입이지만 다음 단계로 진행
                        pass
                except Exception as e:
                    print(f"python-magic 검증 실패: {e}")

            # 4차: mimetypes로 확장자 기반 검사 (보조 수단)
            try:
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type and mime_type in self.ALLOWED_MIME_TYPES:
                    return True, "안전한 파일 (mimetypes)", mime_type
                elif mime_type:
                    detected_mime = mime_type
            except Exception as e:
                print(f"mimetypes 검증 실패: {e}")

            # 5차: 특수 파일 확장자 기반 검사 (HWP 등 한국 파일 형식)
            safe_extensions = {'.hwp', '.hwpx', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
                              '.ppt', '.pptx', '.txt', '.csv', '.jpg', '.jpeg', '.png',
                              '.gif', '.bmp', '.webp', '.mp4', '.avi', '.mov', '.mp3',
                              '.wav', '.zip', '.rar', '.7z'}

            if file_ext in safe_extensions:
                # HWP 파일의 경우 특별 처리
                if file_ext in ['.hwp', '.hwpx']:
                    print(f"✅ HWP 파일 확장자로 안전 인정: {file_ext}")
                    return True, "안전한 파일 (HWP 확장자)", 'application/vnd.hancom.hwp'
                else:
                    print(f"✅ 안전한 확장자로 인정: {file_ext}")
                    return True, f"안전한 파일 (확장자 {file_ext})", detected_mime or 'application/octet-stream'

            # 모든 검증이 실패했거나 허용되지 않는 타입
            return False, f"허용되지 않는 파일 타입: {detected_mime or 'unknown'}", detected_mime or "unknown"

        except Exception as e:
            return False, f"파일 타입 검증 실패: {str(e)}", "unknown"

    def scan_file_content(self, file_path: str) -> Tuple[bool, str]:
        """파일 내용 스캔 (기본적인 악성코드 패턴 검사)"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # 첫 1MB만 스캔

            # 기본적인 악성 패턴 검사
            dangerous_patterns = [
                b'eval(', b'exec(', b'system(', b'shell_exec(',
                b'<script>', b'javascript:', b'vbscript:',
                b'cmd.exe', b'powershell.exe'
            ]

            for pattern in dangerous_patterns:
                if pattern in content.lower():
                    return False, f"위험한 패턴 발견: {pattern.decode('utf-8', errors='ignore')}"

            return True, "안전한 파일 내용"

        except Exception as e:
            return False, f"파일 내용 스캔 실패: {str(e)}"

    def generate_secure_filename(self, original_filename: str, user_id: str) -> Tuple[str, str]:
        """보안 파일명 생성"""
        file_ext = Path(original_filename).suffix.lower()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]

        # 안전한 파일명: timestamp_userid_uniqueid.ext
        secure_filename = f"{timestamp}_{user_id}_{unique_id}{file_ext}"

        return secure_filename, unique_id

    def get_user_directory_path(self, user_id: str, base_upload_dir: str) -> str:
        """사용자별 디렉터리 경로 생성"""
        now = datetime.now()
        year = now.strftime("%Y")
        month = now.strftime("%m")

        user_dir = os.path.join(base_upload_dir, str(user_id), year, month)
        os.makedirs(user_dir, exist_ok=True)

        return user_dir

    def encrypt_file(self, file_path: str) -> str:
        """파일 암호화 (선택사항)"""
        if not self.encryption_key:
            raise Exception("암호화 키가 설정되지 않았습니다")

        try:
            with open(file_path, 'rb') as f:
                original_data = f.read()

            encrypted_data = self.cipher.encrypt(original_data)
            encrypted_path = f"{file_path}.encrypted"

            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            # 원본 파일 삭제
            os.remove(file_path)

            return encrypted_path

        except Exception as e:
            raise Exception(f"파일 암호화 실패: {str(e)}")

    def decrypt_file(self, encrypted_file_path: str, output_path: str) -> str:
        """파일 복호화"""
        if not self.encryption_key:
            raise Exception("암호화 키가 설정되지 않았습니다")

        try:
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.cipher.decrypt(encrypted_data)

            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            return output_path

        except Exception as e:
            raise Exception(f"파일 복호화 실패: {str(e)}")

    def check_file_duplicate(self, file_hash: str, user_id: str, db) -> Optional[Dict]:
        """파일 중복 검사"""
        # 같은 사용자의 같은 해시 파일이 있는지 확인
        existing_file = db["attachments"].find_one({
            "uploader_id": user_id,
            "file_hash": file_hash
        })

        return existing_file

    def generate_download_token(self, attachment_id: str, user_id: str, expires_in: int = 3600) -> str:
        """다운로드 토큰 생성 (1시간 유효)"""
        token_data = f"{attachment_id}:{user_id}:{datetime.now().timestamp() + expires_in}"
        token_hash = hashlib.sha256(token_data.encode()).hexdigest()
        return base64.b64encode(f"{token_data}:{token_hash}".encode()).decode()

    def verify_download_token(self, token: str, attachment_id: str, user_id: str) -> bool:
        """다운로드 토큰 검증"""
        try:
            decoded = base64.b64decode(token.encode()).decode()
            parts = decoded.split(':')

            if len(parts) != 4:
                return False

            token_attachment_id, token_user_id, expires_str, token_hash = parts

            # 토큰 내용 검증
            if token_attachment_id != attachment_id or token_user_id != user_id:
                return False

            # 만료 시간 검증
            expires_time = float(expires_str)
            if datetime.now().timestamp() > expires_time:
                return False

            # 해시 검증
            expected_data = f"{token_attachment_id}:{token_user_id}:{expires_str}"
            expected_hash = hashlib.sha256(expected_data.encode()).hexdigest()

            return token_hash == expected_hash

        except Exception:
            return False


def generate_encryption_key() -> str:
    """새로운 암호화 키 생성"""
    return Fernet.generate_key().decode()


def setup_file_security(encryption_enabled: bool = False) -> FileSecurityManager:
    """파일 보안 관리자 설정"""
    encryption_key = None
    if encryption_enabled:
        # 환경변수에서 키를 가져오거나 새로 생성
        encryption_key = os.getenv('FILE_ENCRYPTION_KEY')
        if not encryption_key:
            encryption_key = generate_encryption_key()
            print(f"새 암호화 키 생성됨: {encryption_key}")
            print("이 키를 환경변수 FILE_ENCRYPTION_KEY에 저장하세요!")

    return FileSecurityManager(encryption_key)
