import os
import io
import json
import logging
from datetime import datetime
from typing import Dict, Optional, Tuple, List
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import service_account
import pytz

# 로거 설정
logger = logging.getLogger(__name__)

class GoogleDriveManager:
    """
    Google Drive API를 사용한 파일 업로드 관리자
    서비스 계정을 사용하여 파일을 업로드하고 관리합니다.
    """

    def __init__(self):
        self.service = None
        self.folder_id = os.getenv('GDRIVE_FOLDER_ID')
        self.credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        self.seoul_tz = pytz.timezone('Asia/Seoul')

        # 필수 환경 변수 확인
        if not self.folder_id:
            raise ValueError("GDRIVE_FOLDER_ID 환경 변수가 설정되지 않았습니다.")
        if not self.credentials_path and not os.getenv('GOOGLE_SERVICE_ACCOUNT_JSON'):
            raise ValueError("GOOGLE_APPLICATION_CREDENTIALS 또는 GOOGLE_SERVICE_ACCOUNT_JSON 환경 변수가 설정되지 않았습니다.")

        # Google Drive 서비스 초기화
        self._initialize_service()

    def _initialize_service(self):
        """Google Drive API 서비스 초기화"""
        try:
            # 서비스 계정 인증 설정
            scopes = ['https://www.googleapis.com/auth/drive.file']

            # 환경변수에서 JSON 정보 로드 (우선순위)
            service_account_json = os.getenv('GOOGLE_SERVICE_ACCOUNT_JSON')
            if service_account_json:
                try:
                    service_account_info = json.loads(service_account_json)
                    credentials = service_account.Credentials.from_service_account_info(
                        service_account_info, scopes=scopes
                    )
                    logger.info("환경변수에서 Google Drive 서비스 계정 정보를 로드했습니다.")
                except json.JSONDecodeError as e:
                    logger.error(f"환경변수 JSON 파싱 실패: {str(e)}")
                    raise GoogleAuthError(f"서비스 계정 JSON 파싱 실패: {str(e)}")
            else:
                # 파일 방식 fallback
                if self.credentials_path and os.path.exists(self.credentials_path):
                    credentials = service_account.Credentials.from_service_account_file(
                        self.credentials_path, scopes=scopes
                    )
                    logger.info("파일에서 Google Drive 서비스 계정 정보를 로드했습니다.")
                else:
                    raise GoogleAuthError("Google Drive 서비스 계정 정보를 찾을 수 없습니다. 환경변수(GOOGLE_SERVICE_ACCOUNT_JSON) 또는 파일을 확인하세요.")

            # Google Drive API 서비스 빌드
            self.service = build('drive', 'v3', credentials=credentials)
            logger.info("Google Drive API 서비스가 성공적으로 초기화되었습니다.")

        except Exception as e:
            import traceback
            logger.error(f"Google Drive API 서비스 초기화 실패: {str(e)}")
            traceback.print_exc()  # ✅ 상세한 스택 트레이스 출력
            raise GoogleAuthError(f"Google Drive 인증 실패: {str(e)}")

    def upload_file(
        self,
        file_content: bytes,
        filename: str,
        mime_type: str,
        user_id: str,
        post_id: str,
        attachment_id: str
    ) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        파일을 Google Drive에 업로드

        Args:
            file_content: 파일 바이너리 데이터
            filename: 원본 파일명
            mime_type: MIME 타입
            user_id: 업로드하는 사용자 ID
            post_id: 게시글 ID
            attachment_id: 첨부파일 ID

        Returns:
            Tuple[성공여부, 에러메시지, 파일정보]
        """
        try:
            if not self.service:
                self._initialize_service()

            # 파일명을 Google Drive용으로 안전하게 변환
            safe_filename = self._create_safe_filename(filename, user_id, post_id, attachment_id)

            # 파일 메타데이터 설정
            file_metadata = {
                'name': safe_filename,
                'parents': [self.folder_id],
                'description': f'업로드자: {user_id}, 게시글: {post_id}, 첨부파일ID: {attachment_id}, 업로드시간: {datetime.now(self.seoul_tz).isoformat()}'
            }

            # 파일 데이터를 메모리 스트림으로 변환
            file_stream = io.BytesIO(file_content)
            media = MediaIoBaseUpload(file_stream, mimetype=mime_type, resumable=True)

            # Google Drive에 파일 업로드
            file_result = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id,name,size,createdTime,webViewLink,webContentLink'
            ).execute()

            logger.info(f"Google Drive 업로드 성공 - 파일ID: {file_result.get('id')}, 파일명: {safe_filename}")

            return True, None, {
                'drive_file_id': file_result.get('id'),
                'drive_filename': file_result.get('name'),
                'drive_size': file_result.get('size'),
                'drive_created_time': file_result.get('createdTime'),
                'drive_view_link': file_result.get('webViewLink'),
                'drive_download_link': file_result.get('webContentLink'),
                'drive_folder_id': self.folder_id
            }

        except Exception as e:
            import traceback
            error_msg = f"Google Drive 업로드 실패: {str(e)}"
            logger.error(error_msg)
            traceback.print_exc()  # ✅ 상세한 스택 트레이스 출력
            return False, error_msg, None

    def delete_file(self, drive_file_id: str) -> Tuple[bool, Optional[str]]:
        """
        Google Drive에서 파일 삭제

        Args:
            drive_file_id: Google Drive 파일 ID

        Returns:
            Tuple[성공여부, 에러메시지]
        """
        try:
            if not self.service:
                self._initialize_service()

            self.service.files().delete(fileId=drive_file_id).execute()
            logger.info(f"Google Drive 파일 삭제 성공 - 파일ID: {drive_file_id}")
            return True, None

        except Exception as e:
            import traceback
            error_msg = f"Google Drive 파일 삭제 실패: {str(e)}"
            logger.error(error_msg)
            traceback.print_exc()  # ✅ 상세한 스택 트레이스 출력
            return False, error_msg

    def get_file_info(self, drive_file_id: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Google Drive 파일 정보 조회

        Args:
            drive_file_id: Google Drive 파일 ID

        Returns:
            Tuple[성공여부, 에러메시지, 파일정보]
        """
        try:
            if not self.service:
                self._initialize_service()

            file_info = self.service.files().get(
                fileId=drive_file_id,
                fields='id,name,size,createdTime,modifiedTime,webViewLink,webContentLink,mimeType'
            ).execute()

            return True, None, file_info

        except Exception as e:
            error_msg = f"Google Drive 파일 정보 조회 실패: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None

    def download_file(self, drive_file_id: str) -> Tuple[bool, Optional[str], Optional[bytes]]:
        """
        Google Drive에서 파일 다운로드

        Args:
            drive_file_id: Google Drive 파일 ID

        Returns:
            Tuple[성공여부, 에러메시지, 파일데이터]
        """
        try:
            if not self.service:
                self._initialize_service()

            request = self.service.files().get_media(fileId=drive_file_id)
            file_data = request.execute()

            logger.info(f"Google Drive 파일 다운로드 성공 - 파일ID: {drive_file_id}")
            return True, None, file_data

        except Exception as e:
            import traceback
            error_msg = f"Google Drive 파일 다운로드 실패: {str(e)}"
            logger.error(error_msg)
            traceback.print_exc()  # ✅ 상세한 스택 트레이스 출력
            return False, error_msg, None

    def _create_safe_filename(self, original_filename: str, user_id: str, post_id: str, attachment_id: str) -> str:
        """
        Google Drive용 안전한 파일명 생성
        """
        # 파일명과 확장자 분리
        name, ext = os.path.splitext(original_filename)

        # 특수문자 제거 및 안전한 문자로 변환
        safe_name = "".join(c for c in name if c.isalnum() or c in (' ', '-', '_', '.')).strip()

        # 한글/유니코드 처리
        if not safe_name or len(safe_name) < 1:
            safe_name = "file"

        # 최대 길이 제한 (Google Drive 파일명 최대 255자)
        max_name_length = 200  # 추가 정보를 위한 여유 공간 확보
        if len(safe_name) > max_name_length:
            safe_name = safe_name[:max_name_length]

        # 현재 시간 추가로 고유성 보장
        timestamp = datetime.now(self.seoul_tz).strftime("%Y%m%d_%H%M%S")

        # 최종 파일명 구성: {safe_name}_{timestamp}_{attachment_id[:8]}{ext}
        final_filename = f"{safe_name}_{timestamp}_{attachment_id[:8]}{ext}"

        return final_filename

    def get_folder_info(self) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        업로드 폴더 정보 조회
        """
        try:
            if not self.service:
                self._initialize_service()

            folder_info = self.service.files().get(
                fileId=self.folder_id,
                fields='id,name,createdTime,modifiedTime,webViewLink'
            ).execute()

            return True, None, folder_info

        except Exception as e:
            error_msg = f"Google Drive 폴더 정보 조회 실패: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None

    def list_files(self, limit: int = 100) -> Tuple[bool, Optional[str], Optional[List]]:
        """
        업로드 폴더의 파일 목록 조회
        """
        try:
            if not self.service:
                self._initialize_service()

            query = f"'{self.folder_id}' in parents and trashed=false"
            results = self.service.files().list(
                q=query,
                pageSize=limit,
                fields="files(id,name,size,createdTime,modifiedTime,mimeType)"
            ).execute()

            files = results.get('files', [])
            return True, None, files

        except Exception as e:
            error_msg = f"Google Drive 파일 목록 조회 실패: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None
