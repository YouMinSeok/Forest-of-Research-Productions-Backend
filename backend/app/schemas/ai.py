"""
구름이 AI - 스키마 정의
강화된 AI 시스템을 위한 Pydantic 모델들
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class AIQueryRequest(BaseModel):
    """AI 쿼리 요청 모델"""
    message: str = Field(..., description="사용자 메시지", min_length=1, max_length=2000)
    conversation_id: Optional[str] = Field(None, description="대화 ID (없으면 새로 생성)")
    search_params: Optional[Dict[str, Any]] = Field(None, description="검색 매개변수")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "연구실의 최근 연구 성과에 대해 알려주세요",
                "conversation_id": "conv_1234567890_user123",
                "search_params": {
                    "n_results": 5,
                    "similarity_threshold": 0.7
                }
            }
        }

class QueryAnalysis(BaseModel):
    """쿼리 분석 결과 모델"""
    original_query: str = Field(..., description="원본 쿼리")
    cleaned_query: str = Field(..., description="정제된 쿼리")
    query_types: List[str] = Field(default_factory=list, description="쿼리 타입들")
    keywords: List[str] = Field(default_factory=list, description="추출된 키워드")
    complexity: str = Field("simple", description="쿼리 복잡도")
    requires_context: bool = Field(True, description="컨텍스트 필요 여부")
    language: str = Field("korean", description="언어")

class SystemInfo(BaseModel):
    """시스템 정보 모델"""
    model: str = Field(..., description="사용된 AI 모델")
    embedding_model: str = Field(..., description="임베딩 모델")
    conversation_memory: bool = Field(True, description="대화 기록 활성화 여부")
    vector_db_enabled: bool = Field(True, description="벡터 데이터베이스 활성화 여부")

class AIResponse(BaseModel):
    """AI 응답 모델"""
    message: str = Field(..., description="AI 응답 메시지")
    conversation_id: str = Field(..., description="대화 ID")
    timestamp: datetime = Field(..., description="응답 시간")
    source_references: List[str] = Field(default_factory=list, description="참고 자료")
    context_used: bool = Field(False, description="컨텍스트 사용 여부")
    query_analysis: Optional[QueryAnalysis] = Field(None, description="쿼리 분석 결과")
    processing_time: Optional[float] = Field(None, description="처리 시간 (초)")
    retrieved_documents: Optional[int] = Field(None, description="검색된 문서 수")
    system_info: Optional[SystemInfo] = Field(None, description="시스템 정보")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "연구실에서는 최근 AI 기반 데이터 분석 프로젝트를 진행하고 있습니다...",
                "conversation_id": "conv_1234567890_user123",
                "timestamp": "2024-01-15T10:30:00Z",
                "source_references": ["[연구자료] AI 프로젝트 진행 현황", "[공지사항] 2024년 연구 계획"],
                "context_used": True,
                "processing_time": 2.5,
                "retrieved_documents": 5
            }
        }

class FeedbackRequest(BaseModel):
    """피드백 요청 모델"""
    conversation_id: str = Field(..., description="대화 ID")
    turn_index: int = Field(..., description="대화 턴 인덱스", ge=0)
    score: int = Field(..., description="평점 (1-5)", ge=1, le=5)
    comment: Optional[str] = Field(None, description="피드백 코멘트", max_length=500)

    class Config:
        json_schema_extra = {
            "example": {
                "conversation_id": "conv_1234567890_user123",
                "turn_index": 0,
                "score": 4,
                "comment": "유용한 정보였습니다. 더 구체적인 예시가 있었으면 좋겠어요."
            }
        }

class PersonalityChangeRequest(BaseModel):
    """AI 성격 변경 요청 모델"""
    personality_type: str = Field(..., description="변경할 성격 타입")

    class Config:
        json_schema_extra = {
            "example": {
                "personality_type": "friendly_helper"
            }
        }

class SyncRequest(BaseModel):
    """데이터 동기화 요청 모델"""
    sync_type: str = Field("incremental", description="동기화 타입 (incremental/full)")
    force_sync: bool = Field(False, description="강제 동기화 여부")

    class Config:
        json_schema_extra = {
            "example": {
                "sync_type": "incremental",
                "force_sync": False
            }
        }

class ConversationTurn(BaseModel):
    """대화 턴 모델"""
    user_message: str = Field(..., description="사용자 메시지")
    ai_response: str = Field(..., description="AI 응답")
    timestamp: datetime = Field(..., description="시간")
    query_analysis: Optional[Dict[str, Any]] = Field(None, description="쿼리 분석")
    context_used: bool = Field(False, description="컨텍스트 사용 여부")
    source_references: List[str] = Field(default_factory=list, description="참고 자료")
    feedback_score: Optional[int] = Field(None, description="피드백 점수")
    feedback_comment: Optional[str] = Field(None, description="피드백 코멘트")

class ConversationHistory(BaseModel):
    """대화 기록 모델"""
    conversation_id: str = Field(..., description="대화 ID")
    history: List[ConversationTurn] = Field(default_factory=list, description="대화 턴들")
    total_turns: int = Field(0, description="총 대화 턴 수")

class VectorDBStats(BaseModel):
    """벡터 데이터베이스 통계 모델"""
    document_count: int = Field(0, description="문서 수")
    collection_name: str = Field("", description="컬렉션 이름")

class SystemStatus(BaseModel):
    """시스템 상태 모델"""
    is_initialized: bool = Field(False, description="초기화 여부")
    initialization_error: Optional[str] = Field(None, description="초기화 오류")
    config: Dict[str, Any] = Field(default_factory=dict, description="시스템 설정")
    components: Dict[str, bool] = Field(default_factory=dict, description="컴포넌트 상태")
    vector_db_stats: Optional[Dict[str, VectorDBStats]] = Field(None, description="벡터 DB 통계")
    conversation_stats: Optional[Dict[str, Any]] = Field(None, description="대화 통계")
    sync_stats: Optional[Dict[str, Any]] = Field(None, description="동기화 통계")
    timestamp: datetime = Field(..., description="상태 조회 시간")

class SyncResult(BaseModel):
    """동기화 결과 모델"""
    sync_type: str = Field(..., description="동기화 타입")
    duration_seconds: float = Field(..., description="소요 시간 (초)")
    posts_processed: int = Field(0, description="처리된 게시글 수")
    comments_processed: int = Field(0, description="처리된 댓글 수")
    posts_skipped: int = Field(0, description="스킵된 게시글 수")
    errors: int = Field(0, description="오류 수")
    success_rate: float = Field(0.0, description="성공률")

class KnowledgeBasePost(BaseModel):
    """지식베이스 게시글 모델 (하위 호환성)"""
    id: str = Field(..., description="게시글 ID")
    title: str = Field(..., description="제목")
    content: str = Field(..., description="내용")
    writer: str = Field(..., description="작성자")
    board: str = Field(..., description="게시판")
    date: str = Field(..., description="작성일")
    views: int = Field(0, description="조회수")
    likes: int = Field(0, description="좋아요 수")
    similarity_score: Optional[float] = Field(None, description="유사도 점수")

class KnowledgeBaseSummary(BaseModel):
    """지식베이스 요약 모델 (하위 호환성)"""
    total_posts: int = Field(0, description="총 게시글 수")
    total_comments: int = Field(0, description="총 댓글 수")
    board_stats: List[Dict[str, Any]] = Field(default_factory=list, description="게시판별 통계")

class AIError(BaseModel):
    """AI 오류 모델"""
    error_code: str = Field(..., description="오류 코드")
    error_message: str = Field(..., description="오류 메시지")
    timestamp: datetime = Field(..., description="오류 발생 시간")
    context: Optional[Dict[str, Any]] = Field(None, description="오류 컨텍스트")

# 응답 래퍼 모델들
class APIResponse(BaseModel):
    """기본 API 응답 모델"""
    success: bool = Field(True, description="성공 여부")
    message: str = Field("", description="응답 메시지")
    data: Optional[Any] = Field(None, description="응답 데이터")
    error: Optional[AIError] = Field(None, description="오류 정보")
    timestamp: datetime = Field(default_factory=datetime.now, description="응답 시간")

class SuggestionsResponse(BaseModel):
    """제안 응답 모델"""
    suggestions: List[str] = Field(default_factory=list, description="제안 질문들")

class StatusResponse(BaseModel):
    """상태 응답 모델"""
    status: str = Field(..., description="상태")
    message: Optional[str] = Field(None, description="상태 메시지")
    timestamp: datetime = Field(..., description="조회 시간")
    details: Optional[SystemStatus] = Field(None, description="상세 상태")

class SyncResponse(BaseModel):
    """동기화 응답 모델"""
    message: str = Field(..., description="응답 메시지")
    sync_type: str = Field(..., description="동기화 타입")
    status: str = Field(..., description="상태")
    result: Optional[SyncResult] = Field(None, description="동기화 결과")

class FeedbackResponse(BaseModel):
    """피드백 응답 모델"""
    message: str = Field(..., description="응답 메시지")
    success: bool = Field(True, description="성공 여부")

class PersonalityChangeResponse(BaseModel):
    """성격 변경 응답 모델"""
    message: str = Field(..., description="응답 메시지")
    personality_type: str = Field(..., description="변경된 성격 타입")
    success: bool = Field(True, description="성공 여부")
