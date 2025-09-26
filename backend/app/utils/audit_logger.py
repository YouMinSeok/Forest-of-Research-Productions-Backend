"""
감사 로그 최소셋 시스템
- sha256_full, size_bytes, mime_detected 기록
- storage_path, uploaded_by, created_at 추적
- 감사 로그 스키마 표준화
- 사고 시 추적/복구 지원
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
from pathlib import Path

import pytz
from bson import ObjectId
from pymongo.database import Database

logger = logging.getLogger(__name__)

class AuditLogger:
    """감사 로그 관리자"""

    def __init__(self, log_base_dir: str = "logs"):
        self.log_base_dir = log_base_dir
        self.seoul_tz = pytz.timezone('Asia/Seoul')

        # 로그 디렉터리 생성
        os.makedirs(log_base_dir, exist_ok=True)

        # 로그 파일 권한 설정
        try:
            os.chmod(log_base_dir, 0o750)  # rwxr-x---
        except OSError:
            pass  # Windows에서는 제한적

    def log_file_audit(self, operation: str, file_data: Dict,
                      user_data: Dict, success: bool,
                      error_message: Optional[str] = None,
                      additional_context: Optional[Dict] = None) -> str:
        """
        파일 감사 로그 기록 (최소셋)

        필수 감사 정보:
        - sha256_full: 파일 내용 SHA-256 전체 해시
        - size_bytes: 파일 크기 (바이트)
        - mime_detected: 실제 감지된 MIME 타입
        - storage_path: 저장 경로
        - uploaded_by: 업로드 사용자 ID
        - created_at: 생성 시간
        """
        timestamp = datetime.now(self.seoul_tz)

        # 감사 로그 항목 (표준화된 스키마)
        audit_entry = {
            # === 필수 감사 정보 (최소셋) ===
            "audit_id": str(ObjectId()),  # 고유 감사 ID
            "timestamp": timestamp.isoformat(),
            "timestamp_unix": int(timestamp.timestamp()),
            "operation": operation,  # upload, download, delete, modify
            "success": success,

            # === 파일 무결성 정보 ===
            "sha256_full": file_data.get("sha256_full"),  # 전체 해시
            "sha256_short": file_data.get("sha256_full", "")[:8],  # 짧은 해시
            "size_bytes": file_data.get("size_bytes", 0),  # 파일 크기
            "mime_detected": file_data.get("mime_detected"),  # 실제 MIME
            "mime_declared": file_data.get("mime_declared"),  # 선언된 MIME

            # === 저장소 정보 ===
            "storage_path": file_data.get("storage_path"),  # 물리적 경로
            "storage_type": "local_filesystem",  # 저장소 유형
            "file_exists": os.path.exists(file_data.get("storage_path", "")) if file_data.get("storage_path") else False,

            # === 사용자 추적 정보 ===
            "uploaded_by": user_data.get("user_id"),  # 업로드 사용자
            "user_name": user_data.get("username"),
            "user_role": user_data.get("role"),

            # === 파일 메타데이터 ===
            "created_at": timestamp.isoformat(),  # 감사 로그 생성 시간
            "file_created_at": file_data.get("file_created_at"),  # 파일 생성 시간
            "original_filename": file_data.get("original_filename"),
            "safe_filename": file_data.get("safe_filename"),
            "file_extension": Path(file_data.get("original_filename", "")).suffix.lower(),

            # === 연관 정보 ===
            "attachment_id": file_data.get("attachment_id"),
            "post_id": file_data.get("post_id"),
            "board_id": file_data.get("board_id"),

            # === 네트워크 정보 ===
            "client_ip": user_data.get("client_ip", "unknown"),
            "user_agent": user_data.get("user_agent"),

            # === 보안 정보 ===
            "security_scan_passed": file_data.get("security_scan_passed", False),
            "virus_scan_result": file_data.get("virus_scan_result"),
            "quarantine_status": file_data.get("quarantine_status", "none"),

            # === 오류 정보 ===
            "error_message": error_message if not success else None,
            "error_code": file_data.get("error_code") if not success else None,

            # === 추가 컨텍스트 ===
            "additional_context": additional_context or {}
        }

        # 로그 기록
        self._write_audit_log(audit_entry)

        # 크리티컬 이벤트는 별도 로그
        if not success or operation in ["delete", "quarantine"]:
            self._write_critical_log(audit_entry)

        return audit_entry["audit_id"]

    def log_access_audit(self, operation: str, resource_data: Dict,
                        user_data: Dict, success: bool,
                        access_method: str = "unknown") -> str:
        """접근 감사 로그 (다운로드, 조회 등)"""
        timestamp = datetime.now(self.seoul_tz)

        access_entry = {
            "audit_id": str(ObjectId()),
            "timestamp": timestamp.isoformat(),
            "timestamp_unix": int(timestamp.timestamp()),
            "audit_type": "access",
            "operation": operation,  # download, view, list, search
            "success": success,

            # 접근 대상
            "resource_type": resource_data.get("resource_type", "file"),
            "resource_id": resource_data.get("resource_id"),
            "attachment_id": resource_data.get("attachment_id"),
            "post_id": resource_data.get("post_id"),

            # 접근 방법
            "access_method": access_method,  # token, direct, api
            "access_token_used": resource_data.get("token_used", False),
            "permission_level": resource_data.get("permission_level"),

            # 사용자 정보
            "accessed_by": user_data.get("user_id"),
            "user_name": user_data.get("username"),
            "user_role": user_data.get("role"),
            "client_ip": user_data.get("client_ip"),
            "user_agent": user_data.get("user_agent"),

            # 파일 정보 (다운로드의 경우)
            "file_path": resource_data.get("file_path"),
            "file_size": resource_data.get("file_size"),
            "mime_type": resource_data.get("mime_type"),

            # 결과
            "bytes_transferred": resource_data.get("bytes_transferred"),
            "transfer_duration_ms": resource_data.get("transfer_duration_ms"),

            "created_at": timestamp.isoformat()
        }

        self._write_access_log(access_entry)
        return access_entry["audit_id"]

    def log_security_event(self, event_type: str, severity: str,
                          details: Dict, user_data: Optional[Dict] = None) -> str:
        """보안 이벤트 로그"""
        timestamp = datetime.now(self.seoul_tz)

        security_entry = {
            "audit_id": str(ObjectId()),
            "timestamp": timestamp.isoformat(),
            "timestamp_unix": int(timestamp.timestamp()),
            "audit_type": "security",
            "event_type": event_type,  # upload_blocked, virus_detected, unauthorized_access
            "severity": severity,  # low, medium, high, critical

            # 이벤트 상세
            "details": details,
            "threat_level": self._assess_threat_level(event_type, details),

            # 사용자 정보 (있는 경우)
            "user_id": user_data.get("user_id") if user_data else None,
            "client_ip": user_data.get("client_ip") if user_data else "unknown",
            "user_agent": user_data.get("user_agent") if user_data else None,

            # 대응 필요성
            "requires_action": severity in ["high", "critical"],
            "action_taken": details.get("action_taken"),

            "created_at": timestamp.isoformat()
        }

        # 보안 이벤트는 별도 파일에 기록
        self._write_security_log(security_entry)

        # 크리티컬 이벤트는 즉시 알림 (실제 환경에서는 SIEM 연동)
        if severity == "critical":
            self._trigger_security_alert(security_entry)

        return security_entry["audit_id"]

    def search_audit_logs(self, filters: Dict, limit: int = 100) -> List[Dict]:
        """감사 로그 검색 (사고 조사용)"""
        try:
            results = []

            # 날짜 범위 필터
            start_date = filters.get("start_date")
            end_date = filters.get("end_date")

            # 로그 파일들 스캔
            log_files = self._get_log_files_in_range(start_date, end_date)

            for log_file in log_files:
                if len(results) >= limit:
                    break

                file_results = self._search_log_file(log_file, filters)
                results.extend(file_results)

            # 결과 정렬 (최신순)
            results.sort(key=lambda x: x.get("timestamp_unix", 0), reverse=True)

            return results[:limit]

        except Exception as e:
            logger.error(f"감사 로그 검색 실패: {e}")
            return []

    def generate_audit_report(self, period_days: int = 30) -> Dict:
        """감사 보고서 생성"""
        try:
            end_date = datetime.now(self.seoul_tz)
            start_date = end_date - timedelta(days=period_days)

            # 기간 내 로그 수집
            logs = self.search_audit_logs({
                "start_date": start_date,
                "end_date": end_date
            }, limit=10000)

            # 통계 분석
            report = {
                "report_period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "days": period_days
                },
                "summary": {
                    "total_events": len(logs),
                    "successful_operations": len([l for l in logs if l.get("success")]),
                    "failed_operations": len([l for l in logs if not l.get("success")]),
                    "unique_users": len(set(l.get("uploaded_by") or l.get("accessed_by") for l in logs if l.get("uploaded_by") or l.get("accessed_by"))),
                    "total_files_processed": len([l for l in logs if l.get("audit_type") != "access"]),
                    "total_bytes_processed": sum(l.get("size_bytes", 0) for l in logs)
                },
                "operations": self._analyze_operations(logs),
                "security_events": self._analyze_security_events(logs),
                "top_users": self._analyze_top_users(logs),
                "file_types": self._analyze_file_types(logs),
                "error_analysis": self._analyze_errors(logs)
            }

            return report

        except Exception as e:
            logger.error(f"감사 보고서 생성 실패: {e}")
            return {"error": str(e)}

    def _write_audit_log(self, entry: Dict):
        """감사 로그 파일 기록"""
        try:
            # 날짜별 로그 파일
            date_str = datetime.now(self.seoul_tz).strftime("%Y%m%d")
            log_file = os.path.join(self.log_base_dir, f"audit_{date_str}.log")

            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

            # 파일 권한 설정
            try:
                os.chmod(log_file, 0o640)  # rw-r-----
            except OSError:
                pass

        except Exception as e:
            logger.error(f"감사 로그 기록 실패: {e}")

    def _write_critical_log(self, entry: Dict):
        """크리티컬 이벤트 로그"""
        try:
            critical_file = os.path.join(self.log_base_dir, "critical_events.log")

            with open(critical_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        except Exception as e:
            logger.error(f"크리티컬 로그 기록 실패: {e}")

    def _write_access_log(self, entry: Dict):
        """접근 로그 기록"""
        try:
            date_str = datetime.now(self.seoul_tz).strftime("%Y%m%d")
            access_file = os.path.join(self.log_base_dir, f"access_{date_str}.log")

            with open(access_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        except Exception as e:
            logger.error(f"접근 로그 기록 실패: {e}")

    def _write_security_log(self, entry: Dict):
        """보안 이벤트 로그"""
        try:
            security_file = os.path.join(self.log_base_dir, "security_events.log")

            with open(security_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        except Exception as e:
            logger.error(f"보안 로그 기록 실패: {e}")

    def _assess_threat_level(self, event_type: str, details: Dict) -> str:
        """위협 수준 평가"""
        high_threat_events = [
            "virus_detected", "malware_uploaded", "unauthorized_admin_access",
            "mass_file_deletion", "suspicious_download_pattern"
        ]

        medium_threat_events = [
            "unauthorized_access", "upload_blocked", "token_abuse",
            "unusual_file_type", "repeated_failed_attempts"
        ]

        if event_type in high_threat_events:
            return "high"
        elif event_type in medium_threat_events:
            return "medium"
        else:
            return "low"

    def _trigger_security_alert(self, entry: Dict):
        """크리티컬 보안 알림 (실제 환경에서는 SIEM/알림 시스템 연동)"""
        try:
            # 현재는 로그만 기록
            alert_file = os.path.join(self.log_base_dir, "security_alerts.log")

            alert_entry = {
                "alert_timestamp": datetime.now(self.seoul_tz).isoformat(),
                "alert_id": str(ObjectId()),
                "original_event": entry,
                "alert_level": "CRITICAL",
                "requires_immediate_action": True
            }

            with open(alert_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_entry, ensure_ascii=False) + "\n")

            logger.critical(f"보안 알림 발생: {entry.get('event_type')}")

        except Exception as e:
            logger.error(f"보안 알림 생성 실패: {e}")

    def _get_log_files_in_range(self, start_date: datetime, end_date: datetime) -> List[str]:
        """날짜 범위 내 로그 파일 목록"""
        log_files = []

        try:
            # None 체크
            if start_date is None or end_date is None:
                logger.warning("start_date 또는 end_date가 None입니다.")
                return log_files

            current_date = start_date
            while current_date <= end_date:
                date_str = current_date.strftime("%Y%m%d")
                audit_file = os.path.join(self.log_base_dir, f"audit_{date_str}.log")
                access_file = os.path.join(self.log_base_dir, f"access_{date_str}.log")

                if os.path.exists(audit_file):
                    log_files.append(audit_file)
                if os.path.exists(access_file):
                    log_files.append(access_file)

                current_date += timedelta(days=1)

        except Exception as e:
            logger.error(f"로그 파일 목록 생성 실패: {e}")

        return log_files

    def _search_log_file(self, log_file: str, filters: Dict) -> List[Dict]:
        """개별 로그 파일 검색"""
        results = []

        try:
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())

                        # 필터 적용
                        if self._matches_filters(entry, filters):
                            results.append(entry)

                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.error(f"로그 파일 검색 실패 {log_file}: {e}")

        return results

    def _matches_filters(self, entry: Dict, filters: Dict) -> bool:
        """로그 항목이 필터와 일치하는지 확인"""
        # 사용자 ID 필터
        if filters.get("user_id"):
            if entry.get("uploaded_by") != filters["user_id"] and entry.get("accessed_by") != filters["user_id"]:
                return False

        # 파일 해시 필터
        if filters.get("file_hash"):
            if filters["file_hash"] not in (entry.get("sha256_full", "") + entry.get("sha256_short", "")):
                return False

        # 작업 유형 필터
        if filters.get("operation"):
            if entry.get("operation") != filters["operation"]:
                return False

        # 성공/실패 필터
        if filters.get("success") is not None:
            if entry.get("success") != filters["success"]:
                return False

        return True

    def _analyze_operations(self, logs: List[Dict]) -> Dict:
        """작업 분석"""
        operations = {}
        for log in logs:
            op = log.get("operation", "unknown")
            operations[op] = operations.get(op, 0) + 1
        return operations

    def _analyze_security_events(self, logs: List[Dict]) -> Dict:
        """보안 이벤트 분석"""
        security_logs = [l for l in logs if l.get("audit_type") == "security"]
        events = {}
        for log in security_logs:
            event = log.get("event_type", "unknown")
            events[event] = events.get(event, 0) + 1
        return events

    def _analyze_top_users(self, logs: List[Dict]) -> List[Dict]:
        """상위 사용자 분석"""
        user_stats = {}
        for log in logs:
            user_id = log.get("uploaded_by") or log.get("accessed_by")
            if user_id:
                if user_id not in user_stats:
                    user_stats[user_id] = {"operations": 0, "bytes": 0}
                user_stats[user_id]["operations"] += 1
                user_stats[user_id]["bytes"] += log.get("size_bytes", 0)

        # 상위 10명
        sorted_users = sorted(user_stats.items(), key=lambda x: x[1]["operations"], reverse=True)[:10]
        return [{"user_id": k, **v} for k, v in sorted_users]

    def _analyze_file_types(self, logs: List[Dict]) -> Dict:
        """파일 타입 분석"""
        file_types = {}
        for log in logs:
            ext = log.get("file_extension", "unknown")
            file_types[ext] = file_types.get(ext, 0) + 1
        return file_types

    def _analyze_errors(self, logs: List[Dict]) -> List[Dict]:
        """오류 분석"""
        error_logs = [l for l in logs if not l.get("success")]
        error_types = {}

        for log in error_logs:
            error = log.get("error_message", "unknown")
            if error not in error_types:
                error_types[error] = {"count": 0, "latest": None}
            error_types[error]["count"] += 1
            error_types[error]["latest"] = log.get("timestamp")

        return [{"error": k, **v} for k, v in error_types.items()]
