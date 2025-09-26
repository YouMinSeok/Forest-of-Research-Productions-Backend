"""
엔터프라이즈급 파일 관리 시스템
- 6가지 핵심 보안 기능 통합
- 원자적 저장 + MIME 이중검사 + 토큰 다운로드 + TTL 정리 + 하드닝 + 감사로그
"""

import os
import logging
import tempfile
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, List
from pathlib import Path

import pytz
from bson import ObjectId
from pymongo.database import Database

from .enhanced_security import EnhancedFileSecurityManager
from .audit_logger import AuditLogger
from .draft_cleaner import DraftCleanupManager
from .storage_hardening import StorageHardeningManager
from .advanced_file_manager import AdvancedFileManager

logger = logging.getLogger(__name__)

class EnterpriseFileManager:
    """
    엔터프라이즈급 파일 관리 시스템

    통합 기능:
    1. 경로/저장 원자성 (임시→SHA-256→atomic rename)
    2. MIME 이중검사 + 확장자 화이트리스트
    3. 다운로드 보안 게이트 (토큰 기반)
    4. 드래프트 TTL 정리 (7일 후 자동 삭제)
    5. 스토리지 하드닝 (NAS 설정)
    6. 감사 로그 최소셋
    """

    def __init__(self, config: Dict):
        self.config = config
        self.seoul_tz = pytz.timezone('Asia/Seoul')

        # 하위 관리자 초기화
        self.file_manager = AdvancedFileManager(
            base_upload_dir=config.get("upload_dir", "uploads")
        )

        self.security_manager = EnhancedFileSecurityManager(
            secret_key=config.get("secret_key", "default-secret-key")
        )

        self.audit_logger = AuditLogger(
            log_base_dir=config.get("log_dir", "logs")
        )

        self.draft_cleaner = DraftCleanupManager(
            base_upload_dir=config.get("upload_dir", "uploads")
        )

        self.storage_hardening = StorageHardeningManager(
            base_upload_dir=config.get("upload_dir", "uploads")
        )

        logger.info("엔터프라이즈 파일 매니저 초기화 완료")

    async def upload_file_enterprise(self, file_data: Dict, user_data: Dict,
                                   db: Database) -> Tuple[bool, str, Dict]:
        """
        엔터프라이즈급 파일 업로드
        모든 보안 기능이 통합된 업로드 프로세스
        """
        audit_id = None
        temp_path = None

        try:
            # === 1단계: 기본 검증 및 준비 ===
            file_content = file_data["content"]
            original_filename = file_data["filename"]
            declared_mime = file_data.get("mime_type")

            # 파일 해시 계산
            sha256_hash = self.file_manager.calculate_file_hash(file_content)

            # === 2단계: 강화된 보안 검증 ===
            security_check, security_msg, security_details = self.security_manager.enhanced_mime_check(
                file_content=file_content,
                filename=original_filename,
                declared_mime=declared_mime
            )

            if not security_check:
                # 보안 검사 실패 로그
                audit_id = self.audit_logger.log_file_audit(
                    operation="upload_blocked",
                    file_data={
                        "original_filename": original_filename,
                        "size_bytes": len(file_content),
                        "sha256_full": sha256_hash,
                        "mime_detected": security_details.get("detected_mime"),
                        "mime_declared": declared_mime,
                        "security_scan_passed": False
                    },
                    user_data=user_data,
                    success=False,
                    error_message=security_msg
                )

                return False, f"보안 검사 실패: {security_msg}", {
                    "audit_id": audit_id,
                    "security_details": security_details
                }

            # === 3단계: 중복 검사 ===
            duplicate_check = self.file_manager.check_duplicate_by_hash(
                sha256_hash, user_data["user_id"]
            )

            if duplicate_check and self.config.get("prevent_duplicates", True):
                audit_id = self.audit_logger.log_file_audit(
                    operation="duplicate_upload",
                    file_data={
                        "original_filename": original_filename,
                        "size_bytes": len(file_content),
                        "sha256_full": sha256_hash,
                        "mime_detected": security_details.get("detected_mime")
                    },
                    user_data=user_data,
                    success=False,
                    error_message="중복 파일"
                )

                return False, "이미 업로드된 파일입니다", {
                    "audit_id": audit_id,
                    "duplicate": True
                }

            # === 4단계: 파일 경로 생성 ===
            attachment_id = str(ObjectId())
            file_path, dir_path = self.file_manager.generate_file_path(
                user_id=user_data["user_id"],
                username=user_data["username"],
                post_id=file_data["post_id"],
                attachment_id=attachment_id,
                original_filename=original_filename,
                file_hash=sha256_hash
            )

            # === 5단계: 원자적 파일 저장 ===
            save_success = self.security_manager.atomic_file_save(
                content=file_content,
                final_path=file_path
            )

            if not save_success:
                audit_id = self.audit_logger.log_file_audit(
                    operation="upload_failed",
                    file_data={
                        "original_filename": original_filename,
                        "size_bytes": len(file_content),
                        "sha256_full": sha256_hash,
                        "storage_path": file_path
                    },
                    user_data=user_data,
                    success=False,
                    error_message="파일 저장 실패"
                )

                return False, "파일 저장에 실패했습니다", {"audit_id": audit_id}

            # === 6단계: 메타데이터 생성 및 DB 저장 ===
            metadata = self.file_manager.create_file_metadata(
                user_id=user_data["user_id"],
                username=user_data["username"],
                post_id=file_data["post_id"],
                attachment_id=attachment_id,
                original_filename=original_filename,
                file_size=len(file_content),
                file_hash=sha256_hash,
                mime_type=security_details.get("detected_mime"),
                file_path=file_path
            )

            # DB에 첨부파일 정보 저장
            attachment_doc = {
                "_id": ObjectId(attachment_id),
                "post_id": file_data["post_id"],
                "uploader_id": user_data["user_id"],
                "original_filename": original_filename,
                "safe_filename": metadata["safe_filename"],
                "file_size": len(file_content),
                "file_hash": sha256_hash,
                "mime_type": security_details.get("detected_mime"),
                "file_path": file_path,
                "upload_date": datetime.now(self.seoul_tz),
                "security_scan_passed": True,
                "audit_trail": []
            }

            db.attachments.insert_one(attachment_doc)

            # === 7단계: 성공 감사 로그 ===
            audit_id = self.audit_logger.log_file_audit(
                operation="upload_success",
                file_data={
                    "attachment_id": attachment_id,
                    "original_filename": original_filename,
                    "size_bytes": len(file_content),
                    "sha256_full": sha256_hash,
                    "mime_detected": security_details.get("detected_mime"),
                    "mime_declared": declared_mime,
                    "storage_path": file_path,
                    "security_scan_passed": True,
                    "file_created_at": datetime.now(self.seoul_tz).isoformat()
                },
                user_data=user_data,
                success=True
            )

            logger.info(f"파일 업로드 성공: {attachment_id} - {original_filename}")

            return True, "파일 업로드 성공", {
                "attachment_id": attachment_id,
                "audit_id": audit_id,
                "file_path": file_path,
                "file_hash": sha256_hash[:8],
                "security_details": security_details,
                "metadata": metadata
            }

        except Exception as e:
            # 실패 시 정리
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass

            # 오류 감사 로그
            audit_id = self.audit_logger.log_file_audit(
                operation="upload_error",
                file_data={
                    "original_filename": original_filename,
                    "size_bytes": len(file_content) if file_content else 0
                },
                user_data=user_data,
                success=False,
                error_message=str(e)
            )

            logger.error(f"파일 업로드 오류: {e}")
            return False, f"업로드 처리 중 오류: {str(e)}", {"audit_id": audit_id}

    async def generate_secure_download_token(self, attachment_id: str,
                                           user_data: Dict, db: Database) -> Tuple[bool, str, Dict]:
        """보안 다운로드 토큰 생성"""
        try:
            # 첨부파일 존재 및 권한 확인
            attachment = db.attachments.find_one({"_id": ObjectId(attachment_id)})

            if not attachment:
                return False, "첨부파일을 찾을 수 없습니다", {}

            # 권한 검사
            can_access = await self._check_download_permission(attachment, user_data, db)
            if not can_access:
                # 권한 없음 감사 로그
                self.audit_logger.log_security_event(
                    event_type="unauthorized_download_attempt",
                    severity="medium",
                    details={
                        "attachment_id": attachment_id,
                        "requested_by": user_data["user_id"],
                        "file_owner": attachment["uploader_id"]
                    },
                    user_data=user_data
                )

                return False, "다운로드 권한이 없습니다", {}

            # 토큰 생성
            token = self.security_manager.generate_secure_download_token(
                attachment_id=attachment_id,
                user_id=user_data["user_id"],
                expires_in=3600
            )

            # 토큰 발급 감사 로그
            self.audit_logger.log_access_audit(
                operation="token_generated",
                resource_data={
                    "resource_type": "file",
                    "attachment_id": attachment_id,
                    "token_used": True
                },
                user_data=user_data,
                success=True,
                access_method="secure_token"
            )

            return True, "토큰 생성 성공", {
                "token": token,
                "expires_in": 3600,
                "attachment_id": attachment_id
            }

        except Exception as e:
            logger.error(f"토큰 생성 실패: {e}")
            return False, f"토큰 생성 오류: {str(e)}", {}

    async def cleanup_system(self, db: Database) -> Dict:
        """시스템 정리 (드래프트 TTL + 스토리지 하드닝)"""
        try:
            results = {
                "success": True,
                "draft_cleanup": {},
                "storage_hardening": {},
                "timestamp": datetime.now(self.seoul_tz).isoformat()
            }

            # 1. 드래프트 TTL 정리
            draft_result = await self.draft_cleaner.cleanup_expired_drafts(db)
            results["draft_cleanup"] = draft_result

            # 2. 스토리지 하드닝
            hardening_result = self.storage_hardening.apply_storage_hardening()
            results["storage_hardening"] = hardening_result

            # 3. 시스템 정리 감사 로그
            self.audit_logger.log_security_event(
                event_type="system_cleanup",
                severity="low",
                details={
                    "draft_cleanup": draft_result,
                    "storage_hardening": hardening_result
                }
            )

            return results

        except Exception as e:
            logger.error(f"시스템 정리 실패: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now(self.seoul_tz).isoformat()
            }

    async def get_system_status(self, db: Database) -> Dict:
        """시스템 전체 상태 조회"""
        try:
            # 드래프트 통계
            draft_stats = await self.draft_cleaner.get_draft_statistics(db)

            # 스토리지 보안 상태
            security_status = self.storage_hardening.get_security_status()

            # 감사 로그 요약 (최근 24시간)
            audit_report = self.audit_logger.generate_audit_report(period_days=1)

            # 전체 파일 통계
            total_attachments = db.attachments.count_documents({})
            total_posts = db.posts.count_documents({})

            return {
                "system_health": "healthy",
                "timestamp": datetime.now(self.seoul_tz).isoformat(),
                "file_statistics": {
                    "total_attachments": total_attachments,
                    "total_posts": total_posts
                },
                "draft_statistics": draft_stats,
                "security_status": security_status,
                "audit_summary": audit_report.get("summary", {}),
                "recommendations": self._generate_recommendations(
                    draft_stats, security_status, audit_report
                )
            }

        except Exception as e:
            logger.error(f"시스템 상태 조회 실패: {e}")
            return {
                "system_health": "error",
                "error": str(e),
                "timestamp": datetime.now(self.seoul_tz).isoformat()
            }

    async def _check_download_permission(self, attachment: Dict, user_data: Dict, db: Database) -> bool:
        """다운로드 권한 검사"""
        try:
            # 1. 업로더 본인
            if str(attachment["uploader_id"]) == user_data["user_id"]:
                return True

            # 2. 관리자
            if user_data.get("role") == "admin":
                return True

            # 3. 게시글 권한 확인
            post_id = attachment.get("post_id")
            if post_id:
                post = db.posts.find_one({"_id": ObjectId(post_id)})
                if post and post.get("status") == "published":
                    return True

                # 게시글 작성자
                if post and str(post.get("author_id")) == user_data["user_id"]:
                    return True

            return False

        except Exception as e:
            logger.error(f"권한 검사 오류: {e}")
            return False

    def _generate_recommendations(self, draft_stats: Dict, security_status: Dict,
                                audit_report: Dict) -> List[str]:
        """시스템 권장사항 생성"""
        recommendations = []

        # 드래프트 관련
        if draft_stats.get("expiring_drafts", 0) > 10:
            recommendations.append("만료 예정 드래프트가 많습니다. 정리를 고려하세요.")

        # 보안 관련
        if security_status.get("executable_files", 0) > 0:
            recommendations.append("실행 가능한 파일이 발견되었습니다. 즉시 검토하세요.")

        if security_status.get("overall_status") != "secure":
            recommendations.append("스토리지 보안 설정을 강화하세요.")

        # 감사 로그 관련
        failed_ops = audit_report.get("summary", {}).get("failed_operations", 0)
        total_ops = audit_report.get("summary", {}).get("total_events", 1)

        if failed_ops / total_ops > 0.1:  # 10% 이상 실패
            recommendations.append("최근 작업 실패율이 높습니다. 시스템을 점검하세요.")

        if not recommendations:
            recommendations.append("시스템이 안정적으로 운영되고 있습니다.")

        return recommendations


# 팩토리 함수
def create_enterprise_file_manager(config: Dict) -> EnterpriseFileManager:
    """엔터프라이즈 파일 매니저 생성"""
    default_config = {
        "upload_dir": "uploads",
        "log_dir": "logs",
        "secret_key": "change-this-secret-key",
        "prevent_duplicates": True,
        "max_file_size": 50 * 1024 * 1024,  # 50MB
        "allowed_extensions": [".pdf", ".jpg", ".png", ".docx", ".xlsx"],
        "security_level": "high"
    }

    # 설정 병합
    final_config = {**default_config, **config}

    return EnterpriseFileManager(final_config)
