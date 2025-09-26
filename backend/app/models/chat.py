# app/models/chat.py
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from bson import ObjectId

class ChatRoomCreate(BaseModel):
    user1_id: str
    user2_id: str
    user1_name: str
    user2_name: str

class ChatRoom(BaseModel):
    id: Optional[str] = Field(alias="_id")
    room_id: str  # 두 사용자 ID로 생성된 고유 방 ID (예: "user1_user2")
    user1_id: str
    user2_id: str
    user1_name: str
    user2_name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_message: Optional[str] = None
    last_message_at: Optional[datetime] = None

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}

# 그룹 채팅을 위한 새로운 모델들
class GroupChatRoomCreate(BaseModel):
    name: str
    memberIds: List[str]

class GroupChatRoom(BaseModel):
    id: Optional[str] = Field(alias="_id")
    room_id: str  # 그룹 고유 ID
    name: str  # 그룹 이름
    members: List[str]  # 멤버 ID 리스트
    member_names: List[str]  # 멤버 이름 리스트
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str  # 그룹 생성자 ID
    last_message: Optional[str] = None
    last_message_at: Optional[datetime] = None
    is_group: bool = True

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}

class ChatMessageCreate(BaseModel):
    room_id: str
    sender_id: str
    sender_name: str
    message: str

class ChatMessage(BaseModel):
    id: Optional[str] = Field(alias="_id")
    room_id: str
    sender_id: str
    sender_name: str
    message: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_read: bool = False

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}

class ChatRoomResponse(BaseModel):
    room_id: str
    other_user_id: str
    other_user_name: str
    last_message: Optional[str]
    last_message_at: Optional[datetime]
    unread_count: int

# 그룹 채팅방 응답 모델
class GroupChatRoomResponse(BaseModel):
    room_id: str
    name: str
    members: List[str]
    member_names: List[str]
    last_message: Optional[str]
    last_message_at: Optional[datetime]
    unread_count: int
    is_group: bool = True

# 멤버 검색을 위한 사용자 모델
class UserSearchResult(BaseModel):
    id: str
    name: str
    email: str
