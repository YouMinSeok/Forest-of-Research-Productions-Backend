from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum

class PermissionType(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    MANAGE_USERS = "manage_users"
    MANAGE_BOARDS = "manage_boards"
    MANAGE_BANNERS = "manage_banners"
    MANAGE_RESEARCH = "manage_research"

class UserRole(str, Enum):
    ADMIN = "admin"
    PROFESSOR = "professor"
    STUDENT = "student"
    GUEST = "guest"

class Permission(BaseModel):
    id: Optional[str] = None
    name: str
    description: str
    permission_type: PermissionType
    created_at: datetime = datetime.utcnow()

class RolePermission(BaseModel):
    id: Optional[str] = None
    role_name: str
    permissions: List[str]  # permission IDs
    created_at: datetime = datetime.utcnow()
    updated_at: datetime = datetime.utcnow()

class UserRoleUpdate(BaseModel):
    user_id: str
    role: UserRole

class PermissionCheck(BaseModel):
    user_id: str
    permission_type: PermissionType
    resource_id: Optional[str] = None
