"""
드래프트 TTL 정리 시스템
- 7일 후 draft 상태 게시글 자동 삭제
- 첨부파일 CASCADE 삭제
- 스케줄러 기반 정리
- 감사 로그 기록
"""

import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pathlib import Path

import pytz
from bson import ObjectId
from pymongo.database import Database

from app.utils.file_logger import FileActivityLogger

logger = logging.getLogger(__name__)

class DraftCleanupManager:
    """드래프트 정리 관리자"""

    def __init__(self, base_upload_dir: str = "uploads"):
        self.base_upload_dir = base_upload_dir
        self.file_logger = FileActivityLogger()
        self.seoul_tz = pytz.timezone('Asia/Seoul')

        # TTL 설정 (7일)
        self.draft_ttl_days = 7

    async def cleanup_expired_drafts(self, db: Database) -> Dict:
        """만료된 드래프트 정리 메인 함수"""
        cleanup_start = datetime.now(self.seoul_tz)

        try:
            # 만료된 드래프트 조회
            expired_drafts = await self._find_expired_drafts(db)

            if not expired_drafts:
                logger.info("정리할 만료된 드래프트가 없습니다")
                return {
                    "success": True,
                    "processed_drafts": 0,
                    "deleted_files": 0,
                    "freed_space_mb": 0,
                    "start_time": cleanup_start.isoformat(),
                    "duration_seconds": 0
                }

            # 정리 작업 수행
            cleanup_result = await self._cleanup_drafts_batch(db, expired_drafts)

            # 빈 디렉터리 정리
            await self._cleanup_empty_directories()

            cleanup_end = datetime.now(self.seoul_tz)
            duration = (cleanup_end - cleanup_start).total_seconds()

            # 정리 완료 로그
            self.file_logger.log_system_event(
                event_type="draft_cleanup_completed",
                details={
                    "processed_drafts": cleanup_result["processed_drafts"],
                    "deleted_files": cleanup_result["deleted_files"],
                    "freed_space_mb": cleanup_result["freed_space_mb"],
                    "duration_seconds": duration
                }
            )

            logger.info(f"드래프트 정리 완료: {cleanup_result}")

            return {
                "success": True,
                "start_time": cleanup_start.isoformat(),
                "end_time": cleanup_end.isoformat(),
                "duration_seconds": duration,
                **cleanup_result
            }

        except Exception as e:
            logger.error(f"드래프트 정리 실패: {e}")
            self.file_logger.log_system_event(
                event_type="draft_cleanup_failed",
                details={"error": str(e)}
            )

            return {
                "success": False,
                "error": str(e),
                "start_time": cleanup_start.isoformat()
            }

    async def _find_expired_drafts(self, db: Database) -> List[Dict]:
        """만료된 드래프트 조회"""
        try:
            # 7일 전 시간 계산
            cutoff_date = datetime.now(self.seoul_tz) - timedelta(days=self.draft_ttl_days)

            # MongoDB 쿼리: status='draft'이고 생성일이 7일 이전
            expired_drafts = list(db.posts.find({
                "status": "draft",
                "created_at": {"$lt": cutoff_date}
            }))

            logger.info(f"만료된 드래프트 {len(expired_drafts)}개 발견")

            return expired_drafts

        except Exception as e:
            logger.error(f"만료 드래프트 조회 실패: {e}")
            return []

    async def _cleanup_drafts_batch(self, db: Database, drafts: List[Dict]) -> Dict:
        """드래프트 배치 정리"""
        processed_drafts = 0
        deleted_files = 0
        freed_space_bytes = 0
        errors = []

        for draft in drafts:
            try:
                draft_id = draft["_id"]

                # 1. 첨부파일 정리
                attachments_result = await self._cleanup_draft_attachments(db, draft_id)
                deleted_files += attachments_result["deleted_files"]
                freed_space_bytes += attachments_result["freed_space_bytes"]

                # 2. 드래프트 게시글 삭제
                delete_result = db.posts.delete_one({"_id": draft_id})

                if delete_result.deleted_count > 0:
                    processed_drafts += 1

                    # 삭제 로그
                    self.file_logger.log_file_operation(
                        operation="draft_deleted",
                        user_id=str(draft.get("author_id", "")),
                        post_id=str(draft_id),
                        filename=f"draft_{draft_id}",
                        success=True,
                        additional_data={
                            "title": draft.get("title", ""),
                            "created_at": draft.get("created_at", "").isoformat() if draft.get("created_at") else "",
                            "attachments_deleted": attachments_result["deleted_files"]
                        }
                    )

                    logger.info(f"드래프트 삭제 완료: {draft_id}")
                else:
                    logger.warning(f"드래프트 삭제 실패: {draft_id}")

            except Exception as e:
                error_msg = f"드래프트 {draft.get('_id')} 정리 실패: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        return {
            "processed_drafts": processed_drafts,
            "deleted_files": deleted_files,
            "freed_space_mb": round(freed_space_bytes / (1024 * 1024), 2),
            "errors": errors
        }

    async def _cleanup_draft_attachments(self, db: Database, draft_id: ObjectId) -> Dict:
        """드래프트의 첨부파일 정리 (CASCADE)"""
        deleted_files = 0
        freed_space_bytes = 0

        try:
            # 해당 드래프트의 첨부파일 조회
            attachments = list(db.attachments.find({"post_id": str(draft_id)}))

            for attachment in attachments:
                try:
                    # 물리적 파일 삭제
                    file_path = attachment.get("file_path")
                    if file_path and os.path.exists(file_path):
                        file_size = os.path.getsize(file_path)
                        os.remove(file_path)
                        freed_space_bytes += file_size
                        deleted_files += 1

                        logger.debug(f"첨부파일 삭제: {file_path}")

                    # DB에서 첨부파일 기록 삭제
                    db.attachments.delete_one({"_id": attachment["_id"]})

                except Exception as e:
                    logger.error(f"첨부파일 {attachment.get('_id')} 삭제 실패: {e}")

            return {
                "deleted_files": deleted_files,
                "freed_space_bytes": freed_space_bytes
            }

        except Exception as e:
            logger.error(f"첨부파일 정리 실패: {e}")
            return {"deleted_files": 0, "freed_space_bytes": 0}

    async def _cleanup_empty_directories(self):
        """빈 디렉터리 정리"""
        try:
            for root, dirs, files in os.walk(self.base_upload_dir, topdown=False):
                # 파일이 없고 하위 디렉터리도 없는 경우
                if not files and not dirs:
                    try:
                        os.rmdir(root)
                        logger.debug(f"빈 디렉터리 삭제: {root}")
                    except OSError as e:
                        # 디렉터리가 이미 삭제되었거나 권한 문제
                        logger.debug(f"디렉터리 삭제 실패: {root} - {e}")
        except Exception as e:
            logger.warning(f"빈 디렉터리 정리 실패: {e}")

    async def get_draft_statistics(self, db: Database) -> Dict:
        """드래프트 통계 정보"""
        try:
            now = datetime.now(self.seoul_tz)
            cutoff_date = now - timedelta(days=self.draft_ttl_days)

            # 전체 드래프트 수
            total_drafts = await db.drafts.count_documents({"status": "draft"})

            # 만료 예정 드래프트 수
            expiring_drafts = await db.drafts.count_documents({
                "status": "draft",
                "created_at": {"$lt": cutoff_date}
            })

            # 최근 생성된 드래프트 수 (24시간 내)
            recent_cutoff = now - timedelta(hours=24)
            recent_drafts = await db.drafts.count_documents({
                "status": "draft",
                "created_at": {"$gte": recent_cutoff}
            })

            # 드래프트별 첨부파일 통계
            pipeline = [
                {"$match": {"status": "draft"}},
                {"$lookup": {
                    "from": "attachments",
                    "localField": "_id",
                    "foreignField": "post_id",
                    "as": "attachments"
                }},
                {"$project": {
                    "attachment_count": {"$size": "$attachments"},
                    "total_size": {"$sum": "$attachments.file_size"}
                }},
                {"$group": {
                    "_id": None,
                    "total_attachment_count": {"$sum": "$attachment_count"},
                    "total_attachment_size": {"$sum": "$total_size"}
                }}
            ]

            attachment_stats = await db.drafts.aggregate(pipeline).to_list(length=None)
            total_attachments = attachment_stats[0]["total_attachment_count"] if attachment_stats else 0
            total_size_mb = round(attachment_stats[0]["total_attachment_size"] / (1024 * 1024), 2) if attachment_stats else 0

            return {
                "total_drafts": total_drafts,
                "expiring_drafts": expiring_drafts,
                "recent_drafts": recent_drafts,
                "total_attachments": total_attachments,
                "total_size_mb": total_size_mb,
                "ttl_days": self.draft_ttl_days,
                "next_cleanup_after": cutoff_date.isoformat()
            }

        except Exception as e:
            logger.error(f"드래프트 통계 조회 실패: {e}")
            return {"error": str(e)}

    async def force_cleanup_user_drafts(self, db: Database, user_id: str) -> Dict:
        """특정 사용자의 드래프트 강제 정리"""
        try:
            # 사용자의 모든 드래프트 조회
            user_drafts = list(db.posts.find({
                "status": "draft",
                "author_id": ObjectId(user_id)
            }))

            if not user_drafts:
                return {
                    "success": True,
                    "message": "정리할 드래프트가 없습니다",
                    "processed_drafts": 0
                }

            # 강제 정리 수행
            cleanup_result = await self._cleanup_drafts_batch(db, user_drafts)

            # 강제 정리 로그
            self.file_logger.log_system_event(
                event_type="force_draft_cleanup",
                user_id=user_id,
                details={
                    "admin_action": True,
                    **cleanup_result
                }
            )

            return {
                "success": True,
                "message": f"사용자 {user_id}의 드래프트 {cleanup_result['processed_drafts']}개 정리 완료",
                **cleanup_result
            }

        except Exception as e:
            logger.error(f"사용자 드래프트 강제 정리 실패: {e}")
            return {
                "success": False,
                "error": str(e)
            }


# 스케줄러용 함수들
async def run_daily_draft_cleanup(db: Database):
    """일일 드래프트 정리 작업"""
    cleanup_manager = DraftCleanupManager()
    result = await cleanup_manager.cleanup_expired_drafts(db)
    return result

async def get_cleanup_status(db: Database):
    """정리 상태 조회"""
    cleanup_manager = DraftCleanupManager()
    stats = await cleanup_manager.get_draft_statistics(db)
    return stats
