# app/models/user.py
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime
from .permission import UserRole

class UserCreate(BaseModel):
    name: str
    password: str
    email: EmailStr
    student_number: str  # 학번 필수로 추가
    role: UserRole = UserRole.STUDENT  # 기본값을 학생으로 설정

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: Optional[str] = None
    name: str
    student_number: Optional[str] = None
    email: EmailStr
    password: str
    role: UserRole
    permissions: List[str] = []  # 권한 리스트
    is_active: bool = False
    is_admin: bool = False  # 어드민 여부
    created_at: datetime = datetime.utcnow()
    last_login: Optional[datetime] = None

    @field_validator('email', mode='before')
    @classmethod
    def validate_email(cls, v):
        if not v or not isinstance(v, str) or '@' not in v:
            return 'user@example.com'
        return v

    @field_validator('student_number', mode='before')
    @classmethod
    def validate_student_number(cls, v):
        if v is None or v == '':
            return None
        return v

    class Config:
        from_attributes = True  # Pydantic V2: orm_mode → from_attributes

class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[UserRole] = None
    permissions: Optional[List[str]] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

class UserResponse(BaseModel):
    id: str
    name: str
    student_number: Optional[str]
    email: EmailStr
    role: UserRole
    permissions: List[str]
    is_active: bool
    is_admin: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True  # Pydantic V2: orm_mode → from_attributes

# 아이디 찾기용 스키마
class FindUsernameRequest(BaseModel):
    name: str
    student_number: str

# 비밀번호 찾기용 스키마
class PasswordResetRequest(BaseModel):
    name: str
    email: EmailStr
    student_number: str

# 인증번호 확인용 스키마
class VerifyResetCodeRequest(BaseModel):
    email: EmailStr
    code: str

# 새 비밀번호 설정용 스키마
class NewPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str
