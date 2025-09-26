import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import pytz

class FileActivityLogger:
    """파일 업로드/다운로드 활동 로깅 시스템"""

    def __init__(self, log_dir: str = "logs", timezone: str = "Asia/Seoul"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.timezone = pytz.timezone(timezone)

        # 로거 설정
        self.setup_loggers()

    def setup_loggers(self):
        """로깅 시스템 설정"""

        # 파일 업로드 로거
        self.upload_logger = logging.getLogger('file_upload')
        self.upload_logger.setLevel(logging.INFO)

        upload_handler = logging.FileHandler(
            self.log_dir / 'file_uploads.log',
            encoding='utf-8'
        )
        upload_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(message)s')
        )

        if not self.upload_logger.handlers:
            self.upload_logger.addHandler(upload_handler)

        # 파일 다운로드 로거
        self.download_logger = logging.getLogger('file_download')
        self.download_logger.setLevel(logging.INFO)

        download_handler = logging.FileHandler(
            self.log_dir / 'file_downloads.log',
            encoding='utf-8'
        )
        download_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(message)s')
        )

        if not self.download_logger.handlers:
            self.download_logger.addHandler(download_handler)

        # 보안 이벤트 로거
        self.security_logger = logging.getLogger('file_security')
        self.security_logger.setLevel(logging.WARNING)

        security_handler = logging.FileHandler(
            self.log_dir / 'security_events.log',
            encoding='utf-8'
        )
        security_handler.setFormatter(
            logging.Formatter('%(asctime)s - SECURITY - %(message)s')
        )

        if not self.security_logger.handlers:
            self.security_logger.addHandler(security_handler)

        # 시스템 로거
        self.system_logger = logging.getLogger('file_system')
        self.system_logger.setLevel(logging.INFO)

        system_handler = logging.FileHandler(
            self.log_dir / 'system_events.log',
            encoding='utf-8'
        )
        system_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )

        if not self.system_logger.handlers:
            self.system_logger.addHandler(system_handler)

    def get_current_time(self) -> str:
        """현재 시간을 로컬 타임존으로 반환"""
        return datetime.now(self.timezone).isoformat()

    def log_upload_attempt(self, user_id: str, filename: str, file_size: int,
                          ip_address: str = None, user_agent: str = None):
        """파일 업로드 시도 로깅"""
        log_data = {
            "event": "upload_attempt",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "filename": filename,
            "file_size": file_size,
            "ip_address": ip_address,
            "user_agent": user_agent
        }

        self.upload_logger.info(json.dumps(log_data, ensure_ascii=False))

    def log_upload_success(self, user_id: str, attachment_id: str, filename: str,
                          file_size: int, file_hash: str, file_path: str,
                          ip_address: str = None):
        """파일 업로드 성공 로깅"""
        log_data = {
            "event": "upload_success",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "attachment_id": attachment_id,
            "filename": filename,
            "file_size": file_size,
            "file_hash": file_hash,
            "file_path": file_path,
            "ip_address": ip_address
        }

        self.upload_logger.info(json.dumps(log_data, ensure_ascii=False))

    def log_upload_failure(self, user_id: str, filename: str, reason: str,
                          ip_address: str = None):
        """파일 업로드 실패 로깅"""
        log_data = {
            "event": "upload_failure",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "filename": filename,
            "reason": reason,
            "ip_address": ip_address
        }

        self.upload_logger.warning(json.dumps(log_data, ensure_ascii=False))

    def log_download_attempt(self, user_id: str, attachment_id: str, filename: str,
                           ip_address: str = None, user_agent: str = None):
        """파일 다운로드 시도 로깅"""
        log_data = {
            "event": "download_attempt",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "attachment_id": attachment_id,
            "filename": filename,
            "ip_address": ip_address,
            "user_agent": user_agent
        }

        self.download_logger.info(json.dumps(log_data, ensure_ascii=False))

    def log_download_success(self, user_id: str, attachment_id: str, filename: str,
                           file_size: int, ip_address: str = None):
        """파일 다운로드 성공 로깅"""
        log_data = {
            "event": "download_success",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "attachment_id": attachment_id,
            "filename": filename,
            "file_size": file_size,
            "ip_address": ip_address
        }

        self.download_logger.info(json.dumps(log_data, ensure_ascii=False))

    def log_download_failure(self, user_id: str, attachment_id: str, reason: str,
                           ip_address: str = None):
        """파일 다운로드 실패 로깅"""
        log_data = {
            "event": "download_failure",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "attachment_id": attachment_id,
            "reason": reason,
            "ip_address": ip_address
        }

        self.download_logger.warning(json.dumps(log_data, ensure_ascii=False))

    def log_security_violation(self, user_id: str, violation_type: str,
                             details: Dict[str, Any], ip_address: str = None):
        """보안 위반 로깅"""
        log_data = {
            "event": "security_violation",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "violation_type": violation_type,
            "details": details,
            "ip_address": ip_address
        }

        self.security_logger.error(json.dumps(log_data, ensure_ascii=False))

    def log_file_deletion(self, user_id: str, attachment_id: str, filename: str,
                         deleted_by: str, reason: str = None):
        """파일 삭제 로깅"""
        log_data = {
            "event": "file_deletion",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "attachment_id": attachment_id,
            "filename": filename,
            "deleted_by": deleted_by,
            "reason": reason
        }

        self.system_logger.info(json.dumps(log_data, ensure_ascii=False))

    def log_access_denied(self, user_id: str, attachment_id: str, reason: str,
                         ip_address: str = None):
        """접근 거부 로깅"""
        log_data = {
            "event": "access_denied",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "attachment_id": attachment_id,
            "reason": reason,
            "ip_address": ip_address
        }

        self.security_logger.warning(json.dumps(log_data, ensure_ascii=False))

    def log_virus_detection(self, user_id: str, filename: str, virus_info: str,
                           ip_address: str = None):
        """바이러스 탐지 로깅"""
        log_data = {
            "event": "virus_detection",
            "timestamp": self.get_current_time(),
            "user_id": user_id,
            "filename": filename,
            "virus_info": virus_info,
            "ip_address": ip_address
        }

        self.security_logger.critical(json.dumps(log_data, ensure_ascii=False))

    def log_backup_event(self, backup_type: str, status: str, details: Dict[str, Any]):
        """백업 이벤트 로깅"""
        log_data = {
            "event": "backup_event",
            "timestamp": self.get_current_time(),
            "backup_type": backup_type,
            "status": status,
            "details": details
        }

        self.system_logger.info(json.dumps(log_data, ensure_ascii=False))

    def get_user_activity_stats(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """사용자 활동 통계 조회"""
        # 실제 구현에서는 데이터베이스 쿼리를 사용하겠지만,
        # 여기서는 로그 파일을 파싱하는 방식으로 구현

        try:
            stats = {
                "uploads": 0,
                "downloads": 0,
                "total_uploaded_size": 0,
                "total_downloaded_size": 0,
                "recent_files": []
            }

            # 로그 파일들을 읽어서 통계 계산
            # (실제로는 더 효율적인 방법을 사용해야 함)

            return stats

        except Exception as e:
            self.system_logger.error(f"통계 조회 실패: {str(e)}")
            return {}

    def get_security_alerts(self, hours: int = 24) -> list:
        """최근 보안 알림 조회"""
        alerts = []

        try:
            security_log_path = self.log_dir / 'security_events.log'
            if security_log_path.exists():
                with open(security_log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                # 최근 24시간 내 보안 이벤트 파싱
                cutoff_time = datetime.now(self.timezone).timestamp() - (hours * 3600)

                for line in lines:
                    try:
                        # 로그 파싱 로직
                        if 'SECURITY' in line:
                            alerts.append(line.strip())
                    except:
                        continue

            return alerts[-50:]  # 최근 50개만 반환

        except Exception as e:
            self.system_logger.error(f"보안 알림 조회 실패: {str(e)}")
            return []


# 전역 로거 인스턴스
file_activity_logger = FileActivityLogger()
