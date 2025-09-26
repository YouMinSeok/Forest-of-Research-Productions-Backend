import os
from typing import List, Optional, Dict, Any
from ..models.permission import PermissionType, UserRole
from ..models.user import User

class PermissionManager:

    # 기본 권한 설정
    DEFAULT_PERMISSIONS = {
        UserRole.ADMIN: [
            PermissionType.READ,
            PermissionType.WRITE,
            PermissionType.DELETE,
            PermissionType.ADMIN,
            PermissionType.MANAGE_USERS,
            PermissionType.MANAGE_BOARDS,
            PermissionType.MANAGE_BANNERS,
            PermissionType.MANAGE_RESEARCH
        ],
        UserRole.PROFESSOR: [
            PermissionType.READ,
            PermissionType.WRITE,
            PermissionType.MANAGE_RESEARCH,
            PermissionType.MANAGE_BOARDS
        ],
        UserRole.STUDENT: [
            PermissionType.READ,
            PermissionType.WRITE
        ],
        UserRole.GUEST: [
            PermissionType.READ
        ]
    }

    @staticmethod
    def create_safe_user(user_dict: Dict[str, Any]) -> User:
        """
        사용자 딕셔너리에서 안전하게 User 객체를 생성
        """
        try:
            user_email = user_dict.get("email", "")
            if not user_email or "@" not in user_email:
                user_email = "user@example.com"

            # role을 UserRole enum으로 안전하게 변환
            user_role = user_dict.get("role", "student")
            try:
                if isinstance(user_role, str):
                    user_role = UserRole(user_role.lower())
                elif not isinstance(user_role, UserRole):
                    user_role = UserRole.STUDENT
            except ValueError:
                user_role = UserRole.STUDENT

            return User(
                id=user_dict.get("id", ""),
                name=user_dict.get("name", "Unknown"),
                student_number=user_dict.get("student_number"),
                email=user_email,
                password="",
                role=user_role,
                permissions=user_dict.get("permissions", []),
                is_active=True,
                is_admin=user_dict.get("is_admin", False)
            )
        except Exception as e:
            # 실패 시 기본 사용자 객체 생성
            return User(
                id=user_dict.get("id", ""),
                name=user_dict.get("name", "Unknown"),
                student_number=None,
                email="user@example.com",
                password="",
                role=UserRole.STUDENT,
                permissions=[],
                is_active=True,
                is_admin=user_dict.get("is_admin", False)
            )

    @staticmethod
    def check_simple_permissions(user) -> Dict[str, bool]:
        """
        간단한 권한 체크를 위한 헬퍼 함수
        User 객체 또는 딕셔너리 모두 처리 가능
        """
        if not user:
            return {
                "is_admin": False,
                "has_manage_boards": False,
                "has_manage_users": False,
                "can_write": False,
                "can_read": True
            }

        # User 객체를 딕셔너리로 변환 (필요시)
        if hasattr(user, 'id'):  # User 객체인 경우
            user_dict = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
                "permissions": user.permissions,
                "is_admin": user.is_admin
            }
        else:  # 이미 딕셔너리인 경우
            user_dict = user

        is_admin = (
            user_dict.get("is_admin", False) or
            user_dict.get("role", "").lower() == "admin"
        )

        user_role = user_dict.get("role", "student").lower()
        has_manage_boards = user_role in ["admin", "professor"] or is_admin
        has_manage_users = user_role in ["admin"] or is_admin

        return {
            "is_admin": is_admin,
            "has_manage_boards": has_manage_boards,
            "has_manage_users": has_manage_users,
            "can_write": user_role in ["admin", "professor", "student"] or is_admin,
            "can_read": True  # 모든 사용자는 읽기 가능
        }

    @staticmethod
    def can_edit_post(user, post: Dict[str, Any]) -> bool:
        """
        게시글 수정 권한 확인
        user는 User 객체 또는 딕셔너리 모두 처리 가능
        """
        if not user or not post:
            return False

        # User 객체를 딕셔너리로 변환 (필요시)
        if hasattr(user, 'id'):  # User 객체인 경우
            user_dict = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
                "permissions": user.permissions,
                "is_admin": user.is_admin
            }
        else:  # 이미 딕셔너리인 경우
            user_dict = user

        is_author = (post.get("writer_id") == user_dict.get("id"))
        perms = PermissionManager.check_simple_permissions(user)

        return is_author or perms["has_manage_boards"] or perms["is_admin"]

    @staticmethod
    def can_delete_post(user, post: Dict[str, Any]) -> bool:
        """
        게시글 삭제 권한 확인
        user는 User 객체 또는 딕셔너리 모두 처리 가능
        """
        if not user or not post:
            return False

        # User 객체를 딕셔너리로 변환 (필요시)
        if hasattr(user, 'id'):  # User 객체인 경우
            user_dict = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
                "permissions": user.permissions,
                "is_admin": user.is_admin
            }
        else:  # 이미 딕셔너리인 경우
            user_dict = user

        is_author = (post.get("writer_id") == user_dict.get("id"))
        perms = PermissionManager.check_simple_permissions(user)

        return is_author or perms["has_manage_boards"] or perms["is_admin"]

    @staticmethod
    def can_comment_on_post(user, post: Dict[str, Any]) -> Dict[str, Any]:
        """
        댓글 작성 권한 확인 및 상세 정보 반환
        user는 User 객체 또는 딕셔너리 모두 처리 가능
        """
        if not user or not post:
            return {
                "can_comment": False,
                "reason": "로그인이 필요합니다.",
                "error_code": "LOGIN_REQUIRED"
            }

        # User 객체를 딕셔너리로 변환 (필요시)
        if hasattr(user, 'id'):  # User 객체인 경우
            user_dict = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
                "permissions": user.permissions,
                "is_admin": user.is_admin
            }
        else:  # 이미 딕셔너리인 경우
            user_dict = user

        is_author = (user_dict.get("id") == post.get("writer_id"))
        perms = PermissionManager.check_simple_permissions(user)

        # 1. 게시판 설정 우선 체크 - 댓글이 허용되지 않으면 모든 사용자 차단
        if not post.get("allow_comments", True):
            return {
                "can_comment": False,
                "reason": "이 게시글은 댓글을 허용하지 않습니다.",
                "error_code": "COMMENTS_DISABLED"
            }

        # 2. 비공개 게시글 체크 (댓글이 허용된 경우에만)
        if post.get("is_private", False):
            can_access_private = (
                is_author or
                perms["has_manage_boards"] or
                perms["is_admin"]
            )
            if not can_access_private:
                return {
                    "can_comment": False,
                    "reason": "비공개 게시글에는 작성자 또는 관리자만 댓글을 작성할 수 있습니다.",
                    "error_code": "PRIVATE_POST_ACCESS_DENIED"
                }

        # 3. 기본적으로 로그인된 사용자는 댓글 작성 가능 (게시판 설정이 허용하는 경우)
        return {
            "can_comment": True,
            "reason": "",
            "error_code": ""
        }

    @staticmethod
    def can_access_private_post(user, post: Dict[str, Any]) -> bool:
        """
        비공개 게시글 접근 권한 확인
        user는 User 객체 또는 딕셔너리 모두 처리 가능
        """
        if not post.get("is_private", False):
            return True

        if not user:
            return False

        # User 객체를 딕셔너리로 변환 (필요시)
        if hasattr(user, 'id'):  # User 객체인 경우
            user_dict = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
                "permissions": user.permissions,
                "is_admin": user.is_admin
            }
        else:  # 이미 딕셔너리인 경우
            user_dict = user

        is_author = (user_dict.get("id") == post.get("writer_id"))
        perms = PermissionManager.check_simple_permissions(user)

        return is_author or perms["has_manage_boards"] or perms["is_admin"]

    @staticmethod
    def is_admin_email(email: str) -> bool:
        """환경변수에서 설정한 어드민 이메일인지 확인"""
        admin_email = os.getenv("ADMIN_EMAIL")
        return email == admin_email

    @staticmethod
    def get_admin_credentials():
        """환경변수에서 어드민 계정 정보 가져오기"""
        return {
            "email": os.getenv("ADMIN_EMAIL"),
            "password": os.getenv("ADMIN_PASSWORD"),
            "name": os.getenv("ADMIN_NAME", "관리자")
        }

    @staticmethod
    def has_permission(user: User, permission: PermissionType) -> bool:
        """사용자가 특정 권한을 가지고 있는지 확인"""
        if user.is_admin:
            return True

        # 역할 기반 기본 권한 확인
        default_permissions = PermissionManager.DEFAULT_PERMISSIONS.get(user.role, [])
        if permission in default_permissions:
            return True

        # 개별 권한 확인
        return permission.value in user.permissions

    @staticmethod
    def can_manage_user(current_user: User, target_user: User) -> bool:
        """사용자 관리 권한 확인"""
        if current_user.is_admin:
            return True

        if not PermissionManager.has_permission(current_user, PermissionType.MANAGE_USERS):
            return False

        # 교수는 학생만 관리 가능
        if current_user.role == UserRole.PROFESSOR:
            return target_user.role == UserRole.STUDENT

        return False

    @staticmethod
    def get_user_permissions(user: User) -> List[PermissionType]:
        """사용자의 모든 권한 목록 반환"""
        if user.is_admin:
            return list(PermissionType)

        permissions = PermissionManager.DEFAULT_PERMISSIONS.get(user.role, [])

        # 개별 권한 추가
        for perm in user.permissions:
            try:
                permission_type = PermissionType(perm)
                if permission_type not in permissions:
                    permissions.append(permission_type)
            except ValueError:
                continue

        return permissions

    @staticmethod
    def add_permission(user: User, permission: PermissionType) -> User:
        """사용자에게 권한 추가"""
        if permission.value not in user.permissions:
            user.permissions.append(permission.value)
        return user

    @staticmethod
    def remove_permission(user: User, permission: PermissionType) -> User:
        """사용자에게서 권한 제거"""
        if permission.value in user.permissions:
            user.permissions.remove(permission.value)
        return user
