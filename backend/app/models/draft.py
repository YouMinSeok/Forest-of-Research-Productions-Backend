from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from bson import ObjectId
import pytz

class DraftCreate(BaseModel):
    """임시저장 생성 요청"""
    board: str = Field(..., description="게시판 유형")
    title: str = Field("", description="제목 (빈 문자열 허용)")
    content: str = Field("", description="내용 (빈 문자열 허용)")
    category: Optional[str] = Field(None, description="카테고리")
    tags: List[str] = Field(default_factory=list, description="태그 목록")
    is_private: bool = Field(False, description="비공개 여부")
    metadata: Optional[Dict[str, Any]] = Field(None, description="추가 메타데이터")

class DraftUpdate(BaseModel):
    """임시저장 수정 요청"""
    title: Optional[str] = Field(None, description="제목")
    content: Optional[str] = Field(None, description="내용")
    category: Optional[str] = Field(None, description="카테고리")
    tags: Optional[List[str]] = Field(None, description="태그 목록")
    is_private: Optional[bool] = Field(None, description="비공개 여부")
    metadata: Optional[Dict[str, Any]] = Field(None, description="추가 메타데이터")

class DraftResponse(BaseModel):
    """임시저장 응답"""
    id: str = Field(..., description="임시저장 ID")
    board: str = Field(..., description="게시판 유형")
    title: str = Field(..., description="제목")
    content: str = Field(..., description="내용")
    category: Optional[str] = Field(None, description="카테고리")
    tags: List[str] = Field(default_factory=list, description="태그 목록")
    is_private: bool = Field(False, description="비공개 여부")
    writer_id: str = Field(..., description="작성자 ID")
    writer_name: str = Field(..., description="작성자 이름")
    created_at: datetime = Field(..., description="생성 시간")
    updated_at: datetime = Field(..., description="수정 시간")
    attachment_count: int = Field(0, description="첨부파일 개수")
    auto_save_enabled: bool = Field(True, description="자동저장 활성화")
    metadata: Optional[Dict[str, Any]] = Field(None, description="추가 메타데이터")

    class Config:
        json_encoders = {
            ObjectId: str,
            datetime: lambda v: v.isoformat() if v.tzinfo else v.replace(tzinfo=pytz.timezone('Asia/Seoul')).isoformat()
        }

class DraftListResponse(BaseModel):
    """임시저장 목록 응답"""
    drafts: List[DraftResponse] = Field(..., description="임시저장 목록")
    total_count: int = Field(..., description="전체 임시저장 개수")
    has_more: bool = Field(False, description="더 많은 데이터 존재 여부")

class DraftPublishRequest(BaseModel):
    """임시저장 게시글 발행 요청"""
    final_title: Optional[str] = Field(None, description="최종 제목 (없으면 draft 제목 사용)")
    final_content: Optional[str] = Field(None, description="최종 내용 (없으면 draft 내용 사용)")
    final_category: Optional[str] = Field(None, description="최종 카테고리")
    final_tags: Optional[List[str]] = Field(None, description="최종 태그")
    final_is_private: Optional[bool] = Field(None, description="최종 비공개 여부")

class AutoSaveRequest(BaseModel):
    """자동 저장 요청"""
    draft_id: str = Field(..., description="임시저장 ID")
    title: str = Field("", description="현재 제목")
    content: str = Field("", description="현재 내용")
    save_type: str = Field("auto", description="저장 유형 (auto/manual)")

class DraftStats(BaseModel):
    """임시저장 통계"""
    total_drafts: int = Field(0, description="총 임시저장 수")
    recent_drafts: int = Field(0, description="최근 7일 임시저장 수")
    total_attachments: int = Field(0, description="총 첨부파일 수")
    storage_used_mb: float = Field(0.0, description="사용된 저장공간 (MB)")
    oldest_draft_days: int = Field(0, description="가장 오래된 임시저장 (일)")
