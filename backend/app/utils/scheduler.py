"""
자동 정리 스케줄러
- 드래프트 TTL 정리 (매일 자정)
- 스토리지 하드닝 검사 (주간)
- 감사 로그 정리 (월간)
"""

import asyncio
import logging
from datetime import datetime, time
from typing import Dict, Optional

import pytz
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from pymongo.database import Database

from .enterprise_file_manager import create_enterprise_file_manager
from .draft_cleaner import DraftCleanupManager
from .storage_hardening import StorageHardeningManager
from .audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class FileSystemScheduler:
    """파일 시스템 자동 정리 스케줄러"""

    def __init__(self, config: Dict):
        self.config = config
        self.scheduler = AsyncIOScheduler(timezone=pytz.timezone('Asia/Seoul'))
        self.seoul_tz = pytz.timezone('Asia/Seoul')

        # 매니저 초기화
        self.file_manager = create_enterprise_file_manager(config)
        self.draft_cleaner = DraftCleanupManager(config.get("upload_dir", "uploads"))
        self.storage_hardening = StorageHardeningManager(config.get("upload_dir", "uploads"))
        self.audit_logger = AuditLogger(config.get("log_dir", "logs"))

        self.db: Optional[Database] = None

    def start(self, db: Database):
        """스케줄러 시작"""
        self.db = db

        try:
            # 1. 드래프트 TTL 정리 (매일 오전 2시)
            self.scheduler.add_job(
                func=self._daily_draft_cleanup,
                trigger=CronTrigger(hour=2, minute=0),
                id="daily_draft_cleanup",
                name="드래프트 TTL 정리",
                max_instances=1,
                coalesce=True
            )

            # 2. 스토리지 하드닝 검사 (매주 일요일 오전 3시)
            self.scheduler.add_job(
                func=self._weekly_storage_check,
                trigger=CronTrigger(day_of_week='sun', hour=3, minute=0),
                id="weekly_storage_check",
                name="주간 스토리지 보안 검사",
                max_instances=1,
                coalesce=True
            )

            # 3. 감사 로그 정리 (매월 1일 오전 4시)
            self.scheduler.add_job(
                func=self._monthly_log_cleanup,
                trigger=CronTrigger(day=1, hour=4, minute=0),
                id="monthly_log_cleanup",
                name="월간 로그 정리",
                max_instances=1,
                coalesce=True
            )

            # 4. 시스템 상태 체크 (매시간)
            self.scheduler.add_job(
                func=self._hourly_health_check,
                trigger=CronTrigger(minute=0),
                id="hourly_health_check",
                name="시간별 시스템 상태 체크",
                max_instances=1,
                coalesce=True
            )

            # 5. 보안 이벤트 모니터링 (매 10분)
            self.scheduler.add_job(
                func=self._security_monitoring,
                trigger=CronTrigger(minute='*/10'),
                id="security_monitoring",
                name="보안 이벤트 모니터링",
                max_instances=1,
                coalesce=True
            )

            self.scheduler.start()
            logger.info("파일 시스템 스케줄러 시작됨")

            # 시작 로그
            self.audit_logger.log_security_event(
                event_type="scheduler_started",
                severity="low",
                details={
                    "jobs_registered": len(self.scheduler.get_jobs()),
                    "timezone": "Asia/Seoul"
                }
            )

        except Exception as e:
            logger.error(f"스케줄러 시작 실패: {e}")
            raise

    def stop(self):
        """스케줄러 정지"""
        try:
            if self.scheduler.running:
                self.scheduler.shutdown()
                logger.info("파일 시스템 스케줄러 정지됨")

                # 정지 로그
                self.audit_logger.log_security_event(
                    event_type="scheduler_stopped",
                    severity="low",
                    details={"stop_time": datetime.now(self.seoul_tz).isoformat()}
                )
        except Exception as e:
            logger.error(f"스케줄러 정지 실패: {e}")

    def get_job_status(self) -> Dict:
        """스케줄러 작업 상태 조회"""
        try:
            jobs = []
            for job in self.scheduler.get_jobs():
                jobs.append({
                    "id": job.id,
                    "name": job.name,
                    "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                    "trigger": str(job.trigger)
                })

            return {
                "scheduler_running": self.scheduler.running,
                "total_jobs": len(jobs),
                "jobs": jobs,
                "timezone": str(self.scheduler.timezone),
                "status_time": datetime.now(self.seoul_tz).isoformat()
            }

        except Exception as e:
            logger.error(f"작업 상태 조회 실패: {e}")
            return {"error": str(e)}

    async def _daily_draft_cleanup(self):
        """일일 드래프트 정리 작업"""
        try:
            logger.info("일일 드래프트 정리 시작")

            result = await self.draft_cleaner.cleanup_expired_drafts(self.db)

            # 정리 결과 로그
            self.audit_logger.log_security_event(
                event_type="scheduled_draft_cleanup",
                severity="low",
                details={
                    "cleanup_result": result,
                    "scheduled": True
                }
            )

            logger.info(f"일일 드래프트 정리 완료: {result}")

        except Exception as e:
            logger.error(f"일일 드래프트 정리 실패: {e}")

            # 실패 로그
            self.audit_logger.log_security_event(
                event_type="scheduled_cleanup_failed",
                severity="medium",
                details={
                    "job_type": "draft_cleanup",
                    "error": str(e)
                }
            )

    async def _weekly_storage_check(self):
        """주간 스토리지 보안 검사"""
        try:
            logger.info("주간 스토리지 보안 검사 시작")

            # 보안 상태 확인
            security_status = self.storage_hardening.get_security_status()

            # 필요시 하드닝 적용
            if security_status.get("overall_status") != "secure":
                hardening_result = self.storage_hardening.apply_storage_hardening()

                # 하드닝 결과 로그
                self.audit_logger.log_security_event(
                    event_type="automatic_hardening_applied",
                    severity="medium",
                    details={
                        "security_status": security_status,
                        "hardening_result": hardening_result,
                        "scheduled": True
                    }
                )
            else:
                # 정상 상태 로그
                self.audit_logger.log_security_event(
                    event_type="storage_security_verified",
                    severity="low",
                    details={
                        "security_status": security_status,
                        "scheduled": True
                    }
                )

            logger.info(f"주간 스토리지 검사 완료: {security_status}")

        except Exception as e:
            logger.error(f"주간 스토리지 검사 실패: {e}")

            # 실패 로그
            self.audit_logger.log_security_event(
                event_type="scheduled_security_check_failed",
                severity="high",
                details={
                    "job_type": "storage_security_check",
                    "error": str(e)
                }
            )

    async def _monthly_log_cleanup(self):
        """월간 로그 정리"""
        try:
            logger.info("월간 로그 정리 시작")

            import os
            import glob
            from datetime import timedelta

            # 90일 이전 로그 파일 정리
            cutoff_date = datetime.now(self.seoul_tz) - timedelta(days=90)
            log_dir = self.config.get("log_dir", "logs")

            removed_files = []
            total_freed_bytes = 0

            # 패턴별 로그 파일 검사
            log_patterns = [
                "audit_*.log",
                "access_*.log",
                "security_events_*.log"
            ]

            for pattern in log_patterns:
                log_files = glob.glob(os.path.join(log_dir, pattern))

                for log_file in log_files:
                    try:
                        # 파일 생성 시간 확인
                        file_time = datetime.fromtimestamp(
                            os.path.getctime(log_file),
                            tz=self.seoul_tz
                        )

                        if file_time < cutoff_date:
                            file_size = os.path.getsize(log_file)
                            os.remove(log_file)
                            removed_files.append(log_file)
                            total_freed_bytes += file_size

                    except Exception as e:
                        logger.warning(f"로그 파일 {log_file} 정리 실패: {e}")

            # 정리 결과 로그
            self.audit_logger.log_security_event(
                event_type="scheduled_log_cleanup",
                severity="low",
                details={
                    "removed_files": len(removed_files),
                    "freed_space_mb": round(total_freed_bytes / (1024 * 1024), 2),
                    "cutoff_date": cutoff_date.isoformat(),
                    "scheduled": True
                }
            )

            logger.info(f"월간 로그 정리 완료: {len(removed_files)}개 파일, {total_freed_bytes} bytes")

        except Exception as e:
            logger.error(f"월간 로그 정리 실패: {e}")

            # 실패 로그
            self.audit_logger.log_security_event(
                event_type="scheduled_log_cleanup_failed",
                severity="medium",
                details={
                    "error": str(e),
                    "scheduled": True
                }
            )

    async def _hourly_health_check(self):
        """시간별 시스템 상태 체크"""
        try:
            # 시스템 상태 확인
            status = await self.file_manager.get_system_status(self.db)

            # 임계 상황 감지
            alerts = []

            # 1. 실패율 체크
            audit_summary = status.get("audit_summary", {})
            failed_ops = audit_summary.get("failed_operations", 0)
            total_ops = audit_summary.get("total_events", 1)

            if total_ops > 0 and (failed_ops / total_ops) > 0.2:  # 20% 이상 실패
                alerts.append("높은 작업 실패율 감지")

            # 2. 보안 상태 체크
            security_status = status.get("security_status", {})
            if security_status.get("executable_files", 0) > 0:
                alerts.append("실행 가능한 파일 발견")

            # 3. 드래프트 누적 체크
            draft_stats = status.get("draft_statistics", {})
            if draft_stats.get("expiring_drafts", 0) > 100:
                alerts.append("대량의 만료 예정 드래프트")

            # 알림이 있으면 로그
            if alerts:
                self.audit_logger.log_security_event(
                    event_type="system_health_alert",
                    severity="medium",
                    details={
                        "alerts": alerts,
                        "system_status": status,
                        "scheduled": True
                    }
                )
                logger.warning(f"시스템 상태 알림: {alerts}")

        except Exception as e:
            logger.error(f"시간별 상태 체크 실패: {e}")

    async def _security_monitoring(self):
        """보안 이벤트 모니터링"""
        try:
            # 최근 10분간 보안 이벤트 조회
            from datetime import timedelta

            recent_time = datetime.now(self.seoul_tz) - timedelta(minutes=10)

            # 보안 로그 파일에서 최근 이벤트 확인
            security_events = self.audit_logger.search_audit_logs({
                "start_date": recent_time,
                "operation": "security"
            }, limit=50)

            # 임계 이벤트 패턴 분석
            critical_events = []
            suspicious_patterns = []

            for event in security_events:
                # 크리티컬 이벤트
                if event.get("severity") == "critical":
                    critical_events.append(event)

                # 의심스러운 패턴 (동일 IP에서 반복 실패)
                if not event.get("success") and event.get("client_ip"):
                    ip_failures = [e for e in security_events
                                 if e.get("client_ip") == event.get("client_ip")
                                 and not e.get("success")]

                    if len(ip_failures) >= 5:  # 5회 이상 실패
                        suspicious_patterns.append({
                            "pattern": "repeated_failures",
                            "client_ip": event.get("client_ip"),
                            "failure_count": len(ip_failures)
                        })

            # 발견된 패턴이 있으면 알림
            if critical_events or suspicious_patterns:
                self.audit_logger.log_security_event(
                    event_type="security_monitoring_alert",
                    severity="high",
                    details={
                        "critical_events": len(critical_events),
                        "suspicious_patterns": suspicious_patterns,
                        "monitoring_period_minutes": 10,
                        "scheduled": True
                    }
                )

                logger.warning(f"보안 모니터링 알림: 크리티컬 {len(critical_events)}개, 의심 패턴 {len(suspicious_patterns)}개")

        except Exception as e:
            logger.error(f"보안 모니터링 실패: {e}")

    async def run_manual_job(self, job_id: str) -> Dict:
        """수동 작업 실행"""
        try:
            if job_id == "draft_cleanup":
                result = await self._daily_draft_cleanup()
                return {"success": True, "job": "draft_cleanup", "result": result}

            elif job_id == "storage_check":
                result = await self._weekly_storage_check()
                return {"success": True, "job": "storage_check", "result": result}

            elif job_id == "log_cleanup":
                result = await self._monthly_log_cleanup()
                return {"success": True, "job": "log_cleanup", "result": result}

            else:
                return {"success": False, "error": f"알 수 없는 작업: {job_id}"}

        except Exception as e:
            logger.error(f"수동 작업 실행 실패 {job_id}: {e}")
            return {"success": False, "error": str(e)}


# 글로벌 스케줄러 인스턴스
_scheduler_instance: Optional[FileSystemScheduler] = None

def get_scheduler() -> Optional[FileSystemScheduler]:
    """스케줄러 인스턴스 가져오기"""
    return _scheduler_instance

def init_scheduler(config: Dict, db: Database):
    """스케줄러 초기화"""
    global _scheduler_instance

    try:
        _scheduler_instance = FileSystemScheduler(config)
        _scheduler_instance.start(db)
        logger.info("파일 시스템 스케줄러 초기화 완료")

    except Exception as e:
        logger.error(f"스케줄러 초기화 실패: {e}")
        raise

def shutdown_scheduler():
    """스케줄러 종료"""
    global _scheduler_instance

    if _scheduler_instance:
        try:
            _scheduler_instance.stop()
            _scheduler_instance = None
            logger.info("파일 시스템 스케줄러 종료 완료")

        except Exception as e:
            logger.error(f"스케줄러 종료 실패: {e}")
