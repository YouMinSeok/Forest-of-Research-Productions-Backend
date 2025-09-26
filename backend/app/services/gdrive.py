# app/services/gdrive.py
import os
import io
import requests
import logging
from datetime import datetime
from typing import Dict, Optional, List
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload, MediaFileUpload
from app.services.token_repo import load_refresh_token

# 로거 설정
logger = logging.getLogger(__name__)

SCOPE = ["https://www.googleapis.com/auth/drive.file"]
TOKEN_URI = "https://oauth2.googleapis.com/token"

# 🚀 성능 최적화: 서비스 객체 캐싱
_drive_service = None
_last_token_refresh = None

# 🚀 성능 최적화: 파일 크기 기준 (5MB)
SMALL_FILE_THRESHOLD = 5 * 1024 * 1024  # 5MB
LARGE_CHUNK_SIZE = 32 * 1024 * 1024     # 32MB (큰 파일용)
MEDIUM_CHUNK_SIZE = 16 * 1024 * 1024    # 16MB (중간 파일용)

async def get_cached_drive():
    """🚀 최적화: Drive 서비스 객체 캐싱 및 재사용"""
    global _drive_service, _last_token_refresh

    rt = await load_refresh_token()
    if not rt:
        raise RuntimeError("refresh_token 미설정. /api/google/start → callback 먼저 수행")

    # 기존 서비스가 있고 토큰이 변경되지 않았으면 재사용
    if _drive_service and _last_token_refresh == rt:
        return _drive_service

    logger.info("🔄 Drive 서비스 객체 생성/갱신 중...")
    creds = Credentials(
        None,
        refresh_token=rt,
        token_uri=TOKEN_URI,
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        scopes=SCOPE,
    )

    # cache_discovery=False로 성능 향상
    _drive_service = build("drive", "v3", credentials=creds, cache_discovery=False)
    _last_token_refresh = rt

    logger.info("✅ Drive 서비스 객체 준비 완료")
    return _drive_service

async def build_drive():
    """기존 호환성을 위한 wrapper (내부적으로 캐시된 서비스 사용)"""
    return await get_cached_drive()

async def find_or_create_folder(parent_id: str, folder_name: str) -> str:
    """🚀 최적화된 폴더 찾기/생성"""
    service = await get_cached_drive()

    # 먼저 폴더가 존재하는지 확인
    query = f"name='{folder_name}' and parents in '{parent_id}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    results = service.files().list(q=query, fields="files(id, name)").execute()
    files = results.get('files', [])

    if files:
        logger.info(f"폴더 발견: {folder_name} (ID: {files[0]['id']})")
        return files[0]['id']

    # 폴더가 없으면 생성
    folder_metadata = {
        'name': folder_name,
        'parents': [parent_id],
        'mimeType': 'application/vnd.google-apps.folder'
    }

    folder = service.files().create(body=folder_metadata, fields='id').execute()
    logger.info(f"폴더 생성: {folder_name} (ID: {folder.get('id')})")
    return folder.get('id')

async def create_folder_structure(user_id: str, date_str: str) -> str:
    """로컬과 동일한 폴더 구조를 구글 드라이브에 생성합니다.

    구조: GDRIVE_FOLDER_ID/user/{user_id}/{year}/{month}/{day}
    """
    root_folder_id = os.environ["GDRIVE_FOLDER_ID"]

    # 날짜 파싱 (YYYY-MM-DD 형태)
    date_parts = date_str.split('-')
    year = date_parts[0]
    month = date_parts[1]
    day = date_parts[2]

    # 폴더 구조 생성
    # 1. user 폴더
    user_folder_id = await find_or_create_folder(root_folder_id, "user")

    # 2. user_id 폴더
    user_id_folder_id = await find_or_create_folder(user_folder_id, user_id)

    # 3. year 폴더
    year_folder_id = await find_or_create_folder(user_id_folder_id, year)

    # 4. month 폴더
    month_folder_id = await find_or_create_folder(year_folder_id, month)

    # 5. day 폴더
    day_folder_id = await find_or_create_folder(month_folder_id, day)

    logger.info(f"폴더 구조 생성 완료: user/{user_id}/{year}/{month}/{day} (최종 ID: {day_folder_id})")
    return day_folder_id

async def upload_bytes_structured(content: bytes, filename: str, user_id: str, date_str: str, mime: str | None = None):
    """🚀 최적화된 구조화 폴더 업로드 - 파일 크기별 전략 적용"""
    service = await get_cached_drive()  # 캐시된 서비스 사용

    # 폴더 구조 생성
    target_folder_id = await create_folder_structure(user_id, date_str)

    # 🚀 파일 크기별 업로드 전략 선택
    file_size = len(content)
    body = {
        "name": filename,
        "parents": [target_folder_id]
    }
    # 최소 필드만 요청하여 네트워크 트래픽 감소
    fields = "id,name,size,webViewLink,webContentLink,createdTime"

    if file_size <= SMALL_FILE_THRESHOLD:
        # 🚀 5MB 이하: 단일 요청 (가장 빠름)
        logger.info(f"📁 소형 파일 업로드 시작: {filename} ({file_size:,} bytes)")
        media = MediaIoBaseUpload(
            io.BytesIO(content),
            mimetype=mime or "application/octet-stream",
            resumable=False  # 단일 요청
        )
    else:
        # 🚀 5MB 초과: resumable + 큰 청크
        chunk_size = LARGE_CHUNK_SIZE if file_size > 50*1024*1024 else MEDIUM_CHUNK_SIZE
        logger.info(f"📁 대형 파일 업로드 시작: {filename} ({file_size:,} bytes, 청크: {chunk_size//1024//1024}MB)")
        media = MediaIoBaseUpload(
            io.BytesIO(content),
            mimetype=mime or "application/octet-stream",
            resumable=True,
            chunksize=chunk_size
        )

    # 파일 업로드 실행
    file = service.files().create(
        body=body,
        media_body=media,
        fields=fields
    ).execute()

    logger.info(f"✅ 업로드 완료: {filename} → user/{user_id}/{date_str} (크기: {file_size:,} bytes)")
    return file

async def find_file_by_path(user_id: str, date_str: str, filename: str) -> Optional[Dict]:
    """폴더 구조를 따라 파일을 검색합니다."""
    try:
        root_folder_id = os.environ["GDRIVE_FOLDER_ID"]

        # 날짜 파싱
        date_parts = date_str.split('-')
        year = date_parts[0]
        month = date_parts[1]
        day = date_parts[2]

        # 폴더 구조 탐색
        user_folder_id = await find_folder(root_folder_id, "user")
        if not user_folder_id:
            return None

        user_id_folder_id = await find_folder(user_folder_id, user_id)
        if not user_id_folder_id:
            return None

        year_folder_id = await find_folder(user_id_folder_id, year)
        if not year_folder_id:
            return None

        month_folder_id = await find_folder(year_folder_id, month)
        if not month_folder_id:
            return None

        day_folder_id = await find_folder(month_folder_id, day)
        if not day_folder_id:
            return None

        # 최종 폴더에서 파일 검색
        service = await get_cached_drive()
        query = f"name='{filename}' and parents in '{day_folder_id}' and trashed=false"
        results = service.files().list(q=query, fields="files(id,name,size,webViewLink,webContentLink,createdTime)").execute()
        files = results.get('files', [])

        if files:
            logger.info(f"파일 발견: {filename} in user/{user_id}/{date_str}")
            return files[0]
        else:
            logger.warning(f"파일 없음: {filename} in user/{user_id}/{date_str}")
            return None

    except Exception as e:
        logger.error(f"파일 검색 실패: {filename} in user/{user_id}/{date_str}, 오류: {str(e)}")
        return None

async def find_folder(parent_id: str, folder_name: str) -> Optional[str]:
    """🚀 최적화된 폴더 검색"""
    service = await get_cached_drive()
    query = f"name='{folder_name}' and parents in '{parent_id}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    results = service.files().list(q=query, fields="files(id, name)").execute()
    files = results.get('files', [])

    if files:
        return files[0]['id']
    return None

async def upload_bytes(content: bytes, filename: str, mime: str | None = None):
    """🚀 최적화된 바이트 업로드 (레거시 호환)"""
    service = await get_cached_drive()  # 캐시된 서비스 사용

    # 🚀 파일 크기별 업로드 전략
    file_size = len(content)
    body = {"name": filename, "parents": [os.environ["GDRIVE_FOLDER_ID"]]}

    if file_size <= SMALL_FILE_THRESHOLD:
        # 5MB 이하: 단일 요청
        logger.info(f"📁 소형 파일 업로드: {filename} ({file_size:,} bytes)")
        media = MediaIoBaseUpload(
            io.BytesIO(content),
            mimetype=mime or "application/octet-stream",
            resumable=False
        )
    else:
        # 5MB 초과: resumable + 큰 청크
        chunk_size = LARGE_CHUNK_SIZE if file_size > 50*1024*1024 else MEDIUM_CHUNK_SIZE
        logger.info(f"📁 대형 파일 업로드: {filename} ({file_size:,} bytes, 청크: {chunk_size//1024//1024}MB)")
        media = MediaIoBaseUpload(
            io.BytesIO(content),
            mimetype=mime or "application/octet-stream",
            resumable=True,
            chunksize=chunk_size
        )

    file = service.files().create(
        body=body, media_body=media,
        fields="id,name,size,webViewLink,webContentLink,createdTime"
    ).execute()

    logger.info(f"✅ 업로드 완료: {filename} (크기: {file_size:,} bytes)")
    return file  # dict

async def download_file(file_id: str) -> bytes:
    """🚀 최적화된 파일 다운로드"""
    service = await get_cached_drive()
    req = service.files().get_media(fileId=file_id)
    buf = io.BytesIO()
    downloader = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    buf.seek(0)
    return buf.getvalue()

async def delete_file(file_id: str):
    """🚀 최적화된 파일 삭제"""
    service = await get_cached_drive()
    service.files().delete(fileId=file_id).execute()

async def get_file_info(file_id: str):
    """🚀 최적화된 파일 정보 조회"""
    service = await get_cached_drive()
    return service.files().get(
        fileId=file_id,
        fields="id,name,size,webViewLink,webContentLink,createdTime"
    ).execute()

async def test_connection():
    """🚀 최적화된 연결 테스트"""
    try:
        service = await get_cached_drive()
        folder_id = os.environ["GDRIVE_FOLDER_ID"]
        folder_info = service.files().get(
            fileId=folder_id,
            fields="id,name,createdTime,modifiedTime,webViewLink"
        ).execute()
        return True, None, folder_info
    except Exception as e:
        return False, str(e), None

async def get_access_token():
    """🚀 프론트엔드 직접 업로드용 access_token 획득"""
    rt = await load_refresh_token()
    if not rt:
        raise RuntimeError("refresh_token 미설정. /api/google/start → callback 먼저 수행")

    creds = Credentials(
        None,
        refresh_token=rt,
        token_uri=TOKEN_URI,
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        scopes=SCOPE,
    )

    # 토큰 갱신
    creds.refresh(requests.Request())

    return {
        "access_token": creds.token,
        "expires_at": creds.expiry.timestamp() if creds.expiry else None
    }

async def create_direct_upload_session(filename: str, mime_type: str, parent_folder_id: str):
    """🚀 브라우저 직접 업로드용 resumable 세션 생성"""
    import httpx

    token_info = await get_access_token()
    access_token = token_info["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Upload-Content-Type": mime_type or "application/octet-stream",
        "Content-Type": "application/json; charset=UTF-8",
    }

    metadata = {
        "name": filename,
        "parents": [parent_folder_id]
    }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
            headers=headers,
            json=metadata
        )
        response.raise_for_status()

        upload_url = response.headers.get("Location")
        if not upload_url:
            raise RuntimeError("업로드 세션 URL을 받지 못했습니다.")

        return {
            "upload_url": upload_url,
            "access_token": access_token,
            "expires_at": token_info["expires_at"]
        }
