"""
스토리지 하드닝 (NAS 보안 설정)
- 디렉터리 750, 파일 640 권한
- noexec,nodev,nosuid 마운트 옵션
- 실행 방지 로직
- 권한 오남용 차단
"""

import os
import stat
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

class StorageHardeningManager:
    """스토리지 보안 강화 관리자"""

    def __init__(self, base_upload_dir: str = "uploads"):
        self.base_upload_dir = base_upload_dir

        # 권한 설정
        self.DIRECTORY_PERMISSIONS = 0o750  # rwxr-x---
        self.FILE_PERMISSIONS = 0o640       # rw-r-----
        self.LOG_PERMISSIONS = 0o640        # rw-r-----

        # 금지된 실행 파일 확장자
        self.EXECUTABLE_EXTENSIONS = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
            '.sh', '.bash', '.zsh', '.ps1', '.msi', '.deb', '.rpm', '.dmg',
            '.app', '.ipa', '.apk', '.pkg', '.run', '.bin', '.dll', '.so'
        }

    def apply_storage_hardening(self) -> Dict:
        """스토리지 보안 강화 적용"""
        results = {
            "success": True,
            "actions_taken": [],
            "warnings": [],
            "errors": []
        }

        try:
            # 1. 기본 디렉터리 권한 설정
            self._secure_base_directories(results)

            # 2. 기존 파일들 권한 수정
            self._secure_existing_files(results)

            # 3. 실행 가능한 파일 검사 및 격리
            self._scan_and_quarantine_executables(results)

            # 4. 마운트 옵션 검사 (Linux만)
            if os.name == 'posix':
                self._check_mount_options(results)

            # 5. 디렉터리 구조 검증
            self._verify_directory_structure(results)

            logger.info(f"스토리지 하드닝 완료: {results}")

        except Exception as e:
            results["success"] = False
            results["errors"].append(f"스토리지 하드닝 실패: {str(e)}")
            logger.error(f"스토리지 하드닝 실패: {e}")

        return results

    def _secure_base_directories(self, results: Dict):
        """기본 디렉터리 보안 설정"""
        try:
            # 업로드 디렉터리 생성 및 권한 설정
            os.makedirs(self.base_upload_dir, exist_ok=True)
            os.chmod(self.base_upload_dir, self.DIRECTORY_PERMISSIONS)
            results["actions_taken"].append(f"기본 디렉터리 권한 설정: {self.base_upload_dir}")

            # 하위 디렉터리들
            subdirs = ["user", "secure_attachments", "quarantine", "temp"]
            for subdir in subdirs:
                dir_path = os.path.join(self.base_upload_dir, subdir)
                os.makedirs(dir_path, exist_ok=True)
                os.chmod(dir_path, self.DIRECTORY_PERMISSIONS)
                results["actions_taken"].append(f"하위 디렉터리 권한 설정: {subdir}")

            # 로그 디렉터리
            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            os.chmod(log_dir, self.DIRECTORY_PERMISSIONS)
            results["actions_taken"].append("로그 디렉터리 권한 설정")

        except OSError as e:
            if "Operation not permitted" in str(e):
                results["warnings"].append("권한 설정 실패 (Windows 또는 권한 부족)")
            else:
                results["errors"].append(f"디렉터리 보안 설정 실패: {str(e)}")

    def _secure_existing_files(self, results: Dict):
        """기존 파일들 권한 수정"""
        try:
            secured_files = 0
            secured_dirs = 0

            for root, dirs, files in os.walk(self.base_upload_dir):
                # 디렉터리 권한 수정
                try:
                    os.chmod(root, self.DIRECTORY_PERMISSIONS)
                    secured_dirs += 1
                except OSError:
                    pass

                # 파일 권한 수정
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        os.chmod(file_path, self.FILE_PERMISSIONS)
                        secured_files += 1
                    except OSError:
                        pass

            results["actions_taken"].append(f"파일 권한 수정: {secured_files}개 파일, {secured_dirs}개 디렉터리")

        except Exception as e:
            results["errors"].append(f"기존 파일 보안 설정 실패: {str(e)}")

    def _scan_and_quarantine_executables(self, results: Dict):
        """실행 가능한 파일 검사 및 격리"""
        try:
            quarantined_files = []
            quarantine_dir = os.path.join(self.base_upload_dir, "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)

            for root, dirs, files in os.walk(self.base_upload_dir):
                # quarantine 디렉터리는 건너뛰기
                if "quarantine" in root:
                    continue

                for file in files:
                    file_path = os.path.join(root, file)
                    file_ext = Path(file).suffix.lower()

                    # 위험한 확장자 검사
                    if file_ext in self.EXECUTABLE_EXTENSIONS:
                        quarantine_path = self._quarantine_file(file_path, quarantine_dir)
                        if quarantine_path:
                            quarantined_files.append(file_path)

                    # 실행 권한 검사 및 제거
                    elif self._has_execute_permission(file_path):
                        self._remove_execute_permission(file_path)
                        results["actions_taken"].append(f"실행 권한 제거: {file_path}")

            if quarantined_files:
                results["actions_taken"].append(f"위험한 파일 격리: {len(quarantined_files)}개")
                results["quarantined_files"] = quarantined_files

        except Exception as e:
            results["errors"].append(f"실행 파일 검사 실패: {str(e)}")

    def _quarantine_file(self, file_path: str, quarantine_dir: str) -> Optional[str]:
        """파일 격리"""
        try:
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, f"quarantined_{filename}")

            # 파일 이동
            os.rename(file_path, quarantine_path)

            # 격리된 파일 권한 제거
            os.chmod(quarantine_path, 0o000)  # 모든 권한 제거

            logger.warning(f"위험한 파일 격리: {file_path} -> {quarantine_path}")
            return quarantine_path

        except Exception as e:
            logger.error(f"파일 격리 실패 {file_path}: {e}")
            return None

    def _has_execute_permission(self, file_path: str) -> bool:
        """파일에 실행 권한이 있는지 확인"""
        try:
            file_stat = os.stat(file_path)
            return bool(file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        except OSError:
            return False

    def _remove_execute_permission(self, file_path: str):
        """파일의 실행 권한 제거"""
        try:
            current_permissions = os.stat(file_path).st_mode
            new_permissions = current_permissions & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            os.chmod(file_path, new_permissions)
        except OSError as e:
            logger.warning(f"실행 권한 제거 실패 {file_path}: {e}")

    def _check_mount_options(self, results: Dict):
        """마운트 옵션 검사 (Linux)"""
        try:
            # /proc/mounts에서 현재 마운트 옵션 확인
            upload_dir_abs = os.path.abspath(self.base_upload_dir)

            # 업로드 디렉터리가 위치한 마운트 포인트 찾기
            mount_point = self._find_mount_point(upload_dir_abs)

            if mount_point:
                mount_options = self._get_mount_options(mount_point)

                # 권장 보안 옵션 검사
                required_options = ["noexec", "nodev", "nosuid"]
                missing_options = []

                for option in required_options:
                    if option not in mount_options:
                        missing_options.append(option)

                if missing_options:
                    results["warnings"].append(
                        f"마운트 포인트 {mount_point}에 권장 보안 옵션 누락: {', '.join(missing_options)}"
                    )
                    results["mount_recommendations"] = {
                        "mount_point": mount_point,
                        "current_options": mount_options,
                        "missing_options": missing_options,
                        "recommended_command": f"mount -o remount,{','.join(missing_options)} {mount_point}"
                    }
                else:
                    results["actions_taken"].append(f"마운트 보안 옵션 확인 완료: {mount_point}")

        except Exception as e:
            results["warnings"].append(f"마운트 옵션 검사 실패: {str(e)}")

    def _find_mount_point(self, path: str) -> Optional[str]:
        """경로가 속한 마운트 포인트 찾기"""
        try:
            with open("/proc/mounts", "r") as f:
                mounts = f.readlines()

            # 가장 긴 매치를 찾기 (가장 구체적인 마운트 포인트)
            best_match = "/"
            best_length = 1

            for line in mounts:
                parts = line.split()
                if len(parts) >= 2:
                    mount_point = parts[1]
                    if path.startswith(mount_point) and len(mount_point) > best_length:
                        best_match = mount_point
                        best_length = len(mount_point)

            return best_match

        except Exception:
            return None

    def _get_mount_options(self, mount_point: str) -> List[str]:
        """마운트 포인트의 옵션 가져오기"""
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[1] == mount_point:
                        return parts[3].split(",")
            return []

        except Exception:
            return []

    def _verify_directory_structure(self, results: Dict):
        """디렉터리 구조 검증"""
        try:
            required_structure = {
                "user": "사용자별 파일 저장소",
                "secure_attachments": "보안 첨부파일",
                "quarantine": "격리된 파일들",
                "temp": "임시 파일"
            }

            for dirname, description in required_structure.items():
                dir_path = os.path.join(self.base_upload_dir, dirname)
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
                    os.chmod(dir_path, self.DIRECTORY_PERMISSIONS)
                    results["actions_taken"].append(f"누락된 디렉터리 생성: {dirname}")

                # 권한 검증
                if self._verify_directory_permissions(dir_path):
                    results["actions_taken"].append(f"디렉터리 권한 검증 완료: {dirname}")
                else:
                    results["warnings"].append(f"디렉터리 권한 불일치: {dirname}")

        except Exception as e:
            results["errors"].append(f"디렉터리 구조 검증 실패: {str(e)}")

    def _verify_directory_permissions(self, dir_path: str) -> bool:
        """디렉터리 권한 검증"""
        try:
            stat_info = os.stat(dir_path)
            current_permissions = stat_info.st_mode & 0o777
            return current_permissions == self.DIRECTORY_PERMISSIONS
        except OSError:
            return False

    def create_hardening_script(self) -> str:
        """하드닝 스크립트 생성 (Linux/NAS용)"""
        script_content = f"""#!/bin/bash
# 파일 업로드 스토리지 하드닝 스크립트
# 생성일: {datetime.now().isoformat()}

echo "=== 파일 업로드 스토리지 하드닝 시작 ==="

# 1. 디렉터리 권한 설정
echo "1. 디렉터리 권한 설정..."
find {self.base_upload_dir} -type d -exec chmod 750 {{}} \;

# 2. 파일 권한 설정
echo "2. 파일 권한 설정..."
find {self.base_upload_dir} -type f -exec chmod 640 {{}} \;

# 3. 실행 권한 제거
echo "3. 실행 권한 제거..."
find {self.base_upload_dir} -type f -executable -exec chmod -x {{}} \;

# 4. 위험한 파일 확장자 검사
echo "4. 위험한 파일 검사..."
DANGEROUS_EXTS="*.exe *.bat *.cmd *.com *.pif *.scr *.vbs *.js *.sh *.bash *.ps1"
for ext in $DANGEROUS_EXTS; do
    find {self.base_upload_dir} -name "$ext" -type f -exec echo "위험한 파일 발견: {{}}" \;
done

# 5. 마운트 옵션 확인 (예시)
echo "5. 마운트 옵션 확인..."
MOUNT_POINT=$(df {self.base_upload_dir} | tail -1 | awk '{{print $6}}')
echo "마운트 포인트: $MOUNT_POINT"

# 권장 마운트 옵션 (실제 적용 전 검토 필요)
echo "권장 마운트 옵션: noexec,nodev,nosuid"
echo "적용 명령어 (검토 후 사용): mount -o remount,noexec,nodev,nosuid $MOUNT_POINT"

# 6. 소유권 설정 (필요한 경우)
echo "6. 소유권 확인..."
echo "현재 업로드 디렉터리 소유권:"
ls -ld {self.base_upload_dir}

echo "=== 하드닝 완료 ==="
echo "주의: 마운트 옵션 변경은 시스템 전체에 영향을 줄 수 있습니다."
echo "변경 전 충분한 테스트를 수행하세요."
"""

        script_path = os.path.join(self.base_upload_dir, "..", "storage_hardening.sh")

        try:
            with open(script_path, "w") as f:
                f.write(script_content)

            # 스크립트 실행 권한 추가
            os.chmod(script_path, 0o750)

            logger.info(f"하드닝 스크립트 생성: {script_path}")
            return script_path

        except Exception as e:
            logger.error(f"하드닝 스크립트 생성 실패: {e}")
            return ""

    def get_security_status(self) -> Dict:
        """현재 보안 상태 조회"""
        try:
            status = {
                "overall_status": "unknown",
                "directory_permissions": "unknown",
                "file_permissions": "unknown",
                "executable_files": 0,
                "quarantined_files": 0,
                "mount_security": "unknown",
                "recommendations": []
            }

            # 디렉터리 권한 검사
            correct_dir_perms = 0
            total_dirs = 0

            for root, dirs, files in os.walk(self.base_upload_dir):
                total_dirs += 1
                if self._verify_directory_permissions(root):
                    correct_dir_perms += 1

            status["directory_permissions"] = f"{correct_dir_perms}/{total_dirs}"

            # 파일 권한 및 실행 파일 검사
            correct_file_perms = 0
            total_files = 0
            executable_count = 0

            for root, dirs, files in os.walk(self.base_upload_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    total_files += 1

                    try:
                        file_stat = os.stat(file_path)
                        current_perms = file_stat.st_mode & 0o777

                        if current_perms == self.FILE_PERMISSIONS:
                            correct_file_perms += 1

                        if self._has_execute_permission(file_path):
                            executable_count += 1

                    except OSError:
                        pass

            status["file_permissions"] = f"{correct_file_perms}/{total_files}"
            status["executable_files"] = executable_count

            # 격리된 파일 수
            quarantine_dir = os.path.join(self.base_upload_dir, "quarantine")
            if os.path.exists(quarantine_dir):
                status["quarantined_files"] = len(os.listdir(quarantine_dir))

            # 전체 상태 평가
            if correct_dir_perms == total_dirs and correct_file_perms == total_files and executable_count == 0:
                status["overall_status"] = "secure"
            elif executable_count > 0:
                status["overall_status"] = "warning"
                status["recommendations"].append("실행 가능한 파일이 발견되었습니다. 권한을 검토하세요.")
            else:
                status["overall_status"] = "needs_improvement"
                status["recommendations"].append("일부 파일/디렉터리 권한이 올바르지 않습니다.")

            return status

        except Exception as e:
            logger.error(f"보안 상태 조회 실패: {e}")
            return {"error": str(e)}

# 스케줄러용 함수
def run_daily_hardening_check(base_upload_dir: str = "uploads") -> Dict:
    """일일 하드닝 검사"""
    manager = StorageHardeningManager(base_upload_dir)
    return manager.get_security_status()

def apply_emergency_hardening(base_upload_dir: str = "uploads") -> Dict:
    """응급 하드닝 적용"""
    manager = StorageHardeningManager(base_upload_dir)
    return manager.apply_storage_hardening()
