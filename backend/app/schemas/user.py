# app/schemas/user.py
from pydantic import BaseModel, EmailStr, validator
import re

class UserCreate(BaseModel):
    name: str
    password: str
    email: EmailStr
    student_number: str  # 학번 추가
    role: str  # "student" 또는 "professor"

    @validator('name')
    def validate_name(cls, v):
        if not (2 <= len(v) <= 50):
            raise ValueError("이름은 2자 이상 50자 이하이어야 합니다.")
        if not re.match(r'^[A-Za-z가-힣\s]+$', v):
            raise ValueError("이름은 알파벳, 한글, 공백만 허용됩니다.")
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("비밀번호는 8자 이상이어야 합니다.")
        if not re.search(r'[A-Z]', v):
            raise ValueError("비밀번호에 최소 하나의 대문자가 필요합니다.")
        if not re.search(r'[a-z]', v):
            raise ValueError("비밀번호에 최소 하나의 소문자가 필요합니다.")
        if not re.search(r'[0-9]', v):
            raise ValueError("비밀번호에 최소 하나의 숫자가 필요합니다.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("비밀번호에 최소 하나의 특수문자가 필요합니다.")
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str
