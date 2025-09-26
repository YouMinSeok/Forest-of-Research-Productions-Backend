import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import asyncio
from bson import ObjectId

class FileVersionManager:
    """파일 버전 관리 시스템"""

    def __init__(self, db):
        self.db = db

    async def get_next_version(self, user_id: str, original_filename: str,
                              post_id: str = None) -> Tuple[str, int]:
        """다음 버전 번호를 가져와서 파일명 생성"""

        # 기본 파일명 (확장자 제외)
        name_without_ext = Path(original_filename).stem
        file_ext = Path(original_filename).suffix

        # 현재 사용자의 동일한 파일명을 가진 파일들 검색
        query = {
            "uploader_id": user_id,
            "original_filename_base": name_without_ext
        }

        # 특정 게시글에 속한 파일이라면 해당 게시글 내에서만 버전 관리
        if post_id:
            query["post_id"] = post_id

        existing_files = await self.db["attachments"].find(query).sort("version", -1).to_list(length=1)

        if not existing_files:
            # 첫 번째 버전
            return original_filename, 1
        else:
            # 다음 버전 번호
            latest_version = existing_files[0].get("version", 1)
            next_version = latest_version + 1

            # 버전이 포함된 파일명 생성
            versioned_filename = f"{name_without_ext}_v{next_version}{file_ext}"
            return versioned_filename, next_version

    async def get_file_versions(self, user_id: str, original_filename_base: str,
                               post_id: str = None) -> List[Dict]:
        """파일의 모든 버전 조회"""

        query = {
            "uploader_id": user_id,
            "original_filename_base": original_filename_base
        }

        if post_id:
            query["post_id"] = post_id

        versions = await self.db["attachments"].find(query).sort("version", 1).to_list(length=100)

        # ID 변환
        for version in versions:
            version["id"] = str(version["_id"])
            del version["_id"]
            if "file_path" in version:
                del version["file_path"]  # 보안상 경로 제외

        return versions

    async def get_latest_version(self, user_id: str, original_filename_base: str,
                                post_id: str = None) -> Optional[Dict]:
        """파일의 최신 버전 조회"""

        query = {
            "uploader_id": user_id,
            "original_filename_base": original_filename_base
        }

        if post_id:
            query["post_id"] = post_id

        latest = await self.db["attachments"].find(query).sort("version", -1).limit(1).to_list(length=1)

        if latest:
            latest_file = latest[0]
            latest_file["id"] = str(latest_file["_id"])
            del latest_file["_id"]
            if "file_path" in latest_file:
                del latest_file["file_path"]
            return latest_file

        return None

    async def mark_version_as_obsolete(self, attachment_id: str, user_id: str) -> bool:
        """특정 버전을 구버전으로 표시"""

        try:
            attachment_oid = ObjectId(attachment_id)

            # 파일 소유권 확인
            attachment = await self.db["attachments"].find_one({
                "_id": attachment_oid,
                "uploader_id": user_id
            })

            if not attachment:
                return False

            # 구버전으로 표시
            await self.db["attachments"].update_one(
                {"_id": attachment_oid},
                {
                    "$set": {
                        "is_obsolete": True,
                        "marked_obsolete_date": datetime.now()
                    }
                }
            )

            return True

        except Exception:
            return False

    async def delete_old_versions(self, user_id: str, original_filename_base: str,
                                 keep_latest_count: int = 5, post_id: str = None) -> int:
        """오래된 버전들 삭제 (최신 N개만 유지)"""

        query = {
            "uploader_id": user_id,
            "original_filename_base": original_filename_base
        }

        if post_id:
            query["post_id"] = post_id

        # 모든 버전을 최신순으로 정렬
        all_versions = await self.db["attachments"].find(query).sort("version", -1).to_list(length=100)

        if len(all_versions) <= keep_latest_count:
            return 0  # 삭제할 파일이 없음

        # 삭제할 오래된 버전들
        versions_to_delete = all_versions[keep_latest_count:]
        deleted_count = 0

        for version in versions_to_delete:
            try:
                # 파일 시스템에서 삭제
                file_path = version.get("file_path")
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)

                # 데이터베이스에서 삭제
                await self.db["attachments"].delete_one({"_id": version["_id"]})
                deleted_count += 1

            except Exception as e:
                print(f"버전 삭제 실패: {str(e)}")
                continue

        return deleted_count

    async def create_version_info(self, user_id: str, original_filename: str,
                                 new_file_hash: str, post_id: str = None) -> Dict:
        """새 파일의 버전 정보 생성"""

        name_without_ext = Path(original_filename).stem

        # 중복 파일 체크 (같은 해시)
        query = {
            "uploader_id": user_id,
            "file_hash": new_file_hash,
            "original_filename_base": name_without_ext
        }

        if post_id:
            query["post_id"] = post_id

        duplicate_file = await self.db["attachments"].find_one(query)

        if duplicate_file:
            return {
                "is_duplicate": True,
                "existing_file": {
                    "id": str(duplicate_file["_id"]),
                    "filename": duplicate_file["filename"],
                    "version": duplicate_file.get("version", 1),
                    "upload_date": duplicate_file["upload_date"]
                }
            }

        # 새 버전 정보 생성
        versioned_filename, version_number = await self.get_next_version(
            user_id, original_filename, post_id
        )

        return {
            "is_duplicate": False,
            "versioned_filename": versioned_filename,
            "version": version_number,
            "original_filename_base": name_without_ext
        }

    async def get_version_history_summary(self, user_id: str,
                                        original_filename_base: str,
                                        post_id: str = None) -> Dict:
        """버전 히스토리 요약 정보"""

        versions = await self.get_file_versions(user_id, original_filename_base, post_id)

        if not versions:
            return {}

        # 총 버전 수
        total_versions = len(versions)

        # 최신 버전
        latest_version = max(versions, key=lambda x: x.get("version", 1))

        # 총 파일 크기
        total_size = sum(v.get("file_size", 0) for v in versions)

        # 첫 업로드 날짜
        first_upload = min(versions, key=lambda x: x.get("upload_date", datetime.now()))

        # 마지막 업로드 날짜
        last_upload = max(versions, key=lambda x: x.get("upload_date", datetime.now()))

        return {
            "total_versions": total_versions,
            "latest_version": latest_version.get("version", 1),
            "total_size": total_size,
            "first_upload_date": first_upload.get("upload_date"),
            "last_upload_date": last_upload.get("upload_date"),
            "versions": versions
        }

    async def cleanup_orphaned_versions(self) -> int:
        """고아 파일 버전들 정리 (파일 시스템에는 없지만 DB에는 있는 경우)"""

        orphaned_count = 0

        # 모든 첨부파일 조회
        all_attachments = await self.db["attachments"].find({}).to_list(length=10000)

        for attachment in all_attachments:
            file_path = attachment.get("file_path")

            if file_path and not os.path.exists(file_path):
                # 파일이 실제로 존재하지 않으면 DB에서 삭제
                try:
                    await self.db["attachments"].delete_one({"_id": attachment["_id"]})
                    orphaned_count += 1
                except Exception as e:
                    print(f"고아 파일 정리 실패: {str(e)}")

        return orphaned_count

    def extract_version_from_filename(self, filename: str) -> Tuple[str, int]:
        """파일명에서 버전 정보 추출"""

        # _v숫자 패턴 찾기
        version_pattern = r'_v(\d+)(\.[^.]+)?$'
        match = re.search(version_pattern, filename)

        if match:
            version_num = int(match.group(1))
            base_name = filename[:match.start()]
            extension = match.group(2) or ''

            return f"{base_name}{extension}", version_num
        else:
            # 버전 정보가 없는 경우
            return filename, 1

    async def merge_versions(self, user_id: str, original_filename_base: str,
                           target_version: int, post_id: str = None) -> bool:
        """특정 버전을 최신 버전으로 승격"""

        try:
            query = {
                "uploader_id": user_id,
                "original_filename_base": original_filename_base,
                "version": target_version
            }

            if post_id:
                query["post_id"] = post_id

            target_file = await self.db["attachments"].find_one(query)

            if not target_file:
                return False

            # 현재 최신 버전 번호 찾기
            latest_query = {
                "uploader_id": user_id,
                "original_filename_base": original_filename_base
            }

            if post_id:
                latest_query["post_id"] = post_id

            latest_files = await self.db["attachments"].find(latest_query).sort("version", -1).limit(1).to_list(length=1)

            if latest_files:
                next_version = latest_files[0].get("version", 1) + 1
            else:
                next_version = 1

            # 타겟 파일을 새 버전으로 복사
            new_file_data = target_file.copy()
            del new_file_data["_id"]
            new_file_data["version"] = next_version
            new_file_data["upload_date"] = datetime.now()
            new_file_data["promoted_from_version"] = target_version

            await self.db["attachments"].insert_one(new_file_data)

            return True

        except Exception as e:
            print(f"버전 병합 실패: {str(e)}")
            return False
