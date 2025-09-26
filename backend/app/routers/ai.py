"""
구름이 AI - 강화된 AI API 라우터
새로운 벡터 데이터베이스 기반 RAG 시스템 사용
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import StreamingResponse
from app.core.database import get_database
from app.schemas.ai import AIQueryRequest, AIResponse
from app.utils.auth_middleware import get_current_user
from app.models.user import User
from datetime import datetime
import logging
import os
import json
from typing import List, Dict, Any, Optional

# 새로운 AI 시스템 import
from app.services.ai_client import get_ai_client, AIServiceClient, check_ai_service_health

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["ai"])

def get_fallback_response(message: str) -> str:
    """AI 시스템이 초기화되지 않았을 때 폴백 응답 제공"""
    message_lower = message.lower().strip()

    # 인사말
    if any(greeting in message_lower for greeting in ['안녕', 'hello', 'hi', '반가워', '처음']):
        return "안녕하세요! 연구실 구름이 AI입니다. 현재 AI 시스템이 일시적으로 제한되고 있어서 기본 응답만 제공할 수 있습니다. 곧 정상 서비스로 복구될 예정입니다."

    # 도움 요청
    elif any(help_word in message_lower for help_word in ['도움', 'help', '뭐', '무엇', '어떻게']):
        return "현재 AI 서비스가 일시적으로 제한되고 있습니다. 연구실 관련 질문이나 도움이 필요하시면 잠시 후 다시 시도해 주세요."

    # 연구실 관련
    elif any(research_word in message_lower for research_word in ['연구실', '연구', 'research', '논문', '실험']):
        return "연구실 관련 정보를 제공하고 싶지만, 현재 AI 시스템이 일시적으로 제한되고 있습니다. 시스템 복구 후 더 자세한 정보를 제공해드릴 수 있습니다."

    # 기타
    else:
        return f"'{message}'에 대한 질문을 받았습니다. 현재 AI 시스템이 일시적으로 제한되고 있어서 자세한 답변을 드리기 어렵습니다. 시스템 복구 후 다시 질문해 주세요."

@router.post("/chat", response_model=AIResponse)
async def chat_with_ai(
    request: AIQueryRequest,
    current_user: User = Depends(get_current_user),
    db = Depends(get_database)
):
    """구름이 AI와 채팅 (강화된 RAG 시스템)"""
    try:
        # AI 서비스 상태 확인
        ai_service_available = await check_ai_service_health()

        # 사용자 ID 추출
        try:
            user_id = current_user.id or current_user.name or "anonymous"
        except AttributeError:
            user_id = "anonymous"

        if not ai_service_available:
            # AI 서비스가 연결되지 않았을 때 폴백 응답
            logger.warning("AI 서비스가 연결되지 않음 - 폴백 응답 제공")

            # 간단한 폴백 응답
            fallback_message = get_fallback_response(request.message)

            return AIResponse(
                message=fallback_message,
                conversation_id=request.conversation_id or f"fallback_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=datetime.now(),
                source_references=[],
                context_used=False,
                query_analysis=None,
                processing_time=0.0,
                retrieved_documents=0,
                system_info=None
            )

        # AI 서비스와 마이크로서비스 통신으로 채팅 처리
        async with AIServiceClient() as ai_client:
            # 사용자 컨텍스트 준비
            context = {
                "user_id": user_id,
                "user_role": getattr(current_user, 'role', 'user'),
                "conversation_id": request.conversation_id,
                "search_params": getattr(request, 'search_params', None)
            }

            result = await ai_client.process_chat(
                message=request.message,
                context=context,
                user_id=user_id,
                session_id=request.conversation_id
            )

        # 에러 체크 및 응답 구성
        return AIResponse(
            message=result.get("response", "응답 생성에 실패했습니다."),
            conversation_id=request.conversation_id,
            timestamp=datetime.now(),
            source_references=result.get("sources", []),
            context_used=result.get("context_used", False),
            query_analysis=result.get("query_analysis", {}),
            processing_time=result.get("processing_time", 0),
            retrieved_documents=result.get("retrieved_documents", 0),
            system_info=result.get("system_info", None)
        )

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"AI 채팅 API 오류: {e}")
        logger.error(f"오류 상세: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI 서비스 오류가 발생했습니다: {str(e)}"
        )

@router.post("/chat/stream")
async def chat_with_ai_stream(
    request: AIQueryRequest,
    current_user: User = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    구름이 AI와 채팅 (스트리밍, Server-Sent Events)
    """
    async def event_generator():
        try:
            ai_service_available = await check_ai_service_health()
            try:
                user_id = current_user.id or current_user.name or "anonymous"
            except AttributeError:
                user_id = "anonymous"

            if not ai_service_available:
                # 폴백 메시지 스트리밍
                fallback_message = get_fallback_response(request.message)
                data = {
                    "message": fallback_message,
                    "conversation_id": request.conversation_id or f"fallback_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    "timestamp": datetime.now().isoformat(),
                    "source_references": [],
                    "context_used": False,
                    "query_analysis": None,
                    "processing_time": 0.0,
                    "retrieved_documents": 0,
                    "system_info": None,
                    "done": True
                }
                yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
                return

            # AI 서비스와 통신 (스트리밍 대신 일반 응답 사용)
            async with AIServiceClient() as ai_client:
                context = {
                    "user_id": user_id,
                    "user_role": getattr(current_user, 'role', 'user'),
                    "conversation_id": request.conversation_id,
                    "search_params": getattr(request, 'search_params', None)
                }

                result = await ai_client.process_chat(
                    message=request.message,
                    context=context,
                    user_id=user_id,
                    session_id=request.conversation_id
                )

                # 응답을 스트리밍 형식으로 반환
                response_data = {
                    "message": result.get("response", "응답 생성에 실패했습니다."),
                    "conversation_id": request.conversation_id,
                    "timestamp": datetime.now().isoformat(),
                    "source_references": result.get("sources", []),
                    "context_used": result.get("context_used", False),
                    "query_analysis": result.get("query_analysis", {}),
                    "processing_time": result.get("processing_time", 0),
                    "retrieved_documents": len(result.get("sources", [])),
                    "system_info": result.get("metadata", {}),
                    "done": True
                }
                yield f"data: {json.dumps(response_data, ensure_ascii=False)}\n\n"
        except Exception as e:
            logger.error(f"AI 스트리밍 채팅 오류: {e}")
            error_data = {"error": str(e), "done": True}
            yield f"data: {json.dumps(error_data, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "POST, OPTIONS"
        }
    )

@router.post("/feedback")
async def add_feedback(
    conversation_id: str,
    turn_index: int,
    score: int,
    comment: str = "",
    current_user: dict = Depends(get_current_user)
):
    """AI 응답에 대한 피드백 추가"""
    try:
        # 점수 유효성 검사
        if not 1 <= score <= 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="점수는 1-5 사이여야 합니다."
            )

        # 현재 마이크로서비스에서는 피드백 기능을 임시로 비활성화
        # TODO: AI 서비스에 피드백 API 추가 후 활성화
        logger.info(f"피드백 수신: conversation_id={conversation_id}, score={score}, comment={comment}")

        # 임시로 성공 응답 반환
        success = True
            conversation_id=conversation_id,
            turn_index=turn_index,
            score=score,
            comment=comment
        )

        if success:
            return {"message": "피드백이 추가되었습니다.", "success": True}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="피드백 추가에 실패했습니다."
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"피드백 추가 오류: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="피드백 처리 중 오류가 발생했습니다."
        )

@router.get("/suggestions")
async def get_ai_suggestions(
    current_user: dict = Depends(get_current_user)
):
    """AI 질문 제안"""
    try:
        ai_system = await get_ai_system()
        if not ai_system:
            # AI 시스템이 없어도 기본 제안은 제공
            return {
                "suggestions": [
                    "연구실의 최근 연구 성과에 대해 알려주세요",
                    "논문 작성 시 주의사항이 있나요?",
                    "연구실 규정에 대해 궁금합니다",
                    "최근 게시된 연구자료를 요약해주세요",
                    "학술 일정을 확인하고 싶습니다"
                ]
            }

        try:
            user_id = current_user.id or current_user.name or "anonymous"
        except AttributeError:
            user_id = "anonymous"
        suggestions = await ai_system.get_suggestions(user_id=user_id)

        return {"suggestions": suggestions}

    except Exception as e:
        logger.error(f"AI 제안 생성 오류: {e}")
        # 에러가 발생해도 기본 제안은 제공
        return {
            "suggestions": [
                "연구실의 최근 연구 성과에 대해 알려주세요",
                "논문 작성 시 주의사항이 있나요?",
                "연구실 규정에 대해 궁금합니다"
            ]
        }

@router.get("/status")
async def get_ai_status(
    current_user: dict = Depends(get_current_user)
):
    """AI 시스템 상태 조회"""
    try:
        ai_system = await get_ai_system()
        if not ai_system:
            return {
                "status": "not_initialized",
                "message": "AI 시스템이 초기화되지 않았습니다.",
                "timestamp": datetime.now().isoformat()
            }

        status = await ai_system.get_system_status()
        return status

    except Exception as e:
        logger.error(f"AI 상태 조회 오류: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI 시스템 상태 조회 중 오류가 발생했습니다."
        )

@router.post("/sync")
async def sync_board_data(
    sync_type: str = "incremental",
    background_tasks: BackgroundTasks = BackgroundTasks(),
    current_user: dict = Depends(get_current_user)
):
    """게시판 데이터 동기화"""
    try:
        # 관리자 권한 확인 (선택사항)
        try:
            user_role = current_user.role
        except AttributeError:
            user_role = "user"
        if user_role not in ["admin", "moderator"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="동기화 권한이 없습니다."
            )

        ai_system = await get_ai_system()
        if not ai_system:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI 시스템이 초기화되지 않았습니다."
            )

        # 동기화 타입 검증
        if sync_type not in ["incremental", "full"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="동기화 타입은 'incremental' 또는 'full'이어야 합니다."
            )

        # 백그라운드에서 동기화 실행
        if sync_type == "full":
            # 전체 동기화는 시간이 오래 걸리므로 백그라운드에서 실행
            background_tasks.add_task(ai_system.sync_board_data, sync_type)
            return {
                "message": "전체 동기화가 백그라운드에서 시작되었습니다.",
                "sync_type": sync_type,
                "status": "started"
            }
        else:
            # 증분 동기화는 바로 실행
            result = await ai_system.sync_board_data(sync_type)
            return {
                "message": "동기화가 완료되었습니다.",
                "sync_type": sync_type,
                "result": result
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"동기화 오류: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="동기화 중 오류가 발생했습니다."
        )

@router.post("/personality")
async def change_ai_personality(
    personality_type: str,
    current_user: dict = Depends(get_current_user)
):
    """AI 성격 변경"""
    try:
        ai_system = await get_ai_system()
        if not ai_system:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI 시스템이 초기화되지 않았습니다."
            )

        # 사용 가능한 성격 타입
        available_types = ["research_assistant", "specialized_researcher", "friendly_helper"]
        if personality_type not in available_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"사용 가능한 성격 타입: {', '.join(available_types)}"
            )

        success = await ai_system.change_personality(personality_type)

        if success:
            return {
                "message": f"AI 성격이 '{personality_type}'로 변경되었습니다.",
                "personality_type": personality_type,
                "success": True
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="성격 변경에 실패했습니다."
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"성격 변경 오류: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="성격 변경 중 오류가 발생했습니다."
        )

@router.get("/knowledge-base/stats")
async def get_knowledge_base_stats(
    current_user: dict = Depends(get_current_user)
):
    """지식베이스 통계 조회"""
    try:
        ai_system = await get_ai_system()
        if not ai_system:
            return {
                "error": "AI 시스템이 초기화되지 않았습니다.",
                "stats": {}
            }

        if ai_system.vector_db:
            stats = await ai_system.vector_db.get_collection_stats()
            return {"stats": stats}
        else:
            return {"error": "벡터 데이터베이스가 초기화되지 않았습니다.", "stats": {}}

    except Exception as e:
        logger.error(f"지식베이스 통계 조회 오류: {e}")
        return {"error": str(e), "stats": {}}

@router.get("/conversation/history/{conversation_id}")
async def get_conversation_history(
    conversation_id: str,
    max_turns: int = 10,
    current_user: dict = Depends(get_current_user)
):
    """대화 기록 조회"""
    try:
        ai_system = await get_ai_system()
        if not ai_system or not ai_system.conversation_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="대화 관리 시스템이 초기화되지 않았습니다."
            )

        history = await ai_system.conversation_manager.get_conversation_context(
            conversation_id=conversation_id,
            max_turns=max_turns
        )

        return {
            "conversation_id": conversation_id,
            "history": history,
            "total_turns": len(history)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"대화 기록 조회 오류: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="대화 기록 조회 중 오류가 발생했습니다."
        )

# 하위 호환성을 위한 기존 엔드포인트들
@router.get("/knowledge-base/posts")
async def get_knowledge_base_posts(
    query: str = "",
    limit: int = 10,
    current_user: dict = Depends(get_current_user)
):
    """지식베이스 게시글 검색 (하위 호환성)"""
    try:
        ai_system = await get_ai_system()
        if not ai_system or not ai_system.vector_db:
            return {"posts": [], "message": "AI 시스템이 초기화되지 않았습니다."}

        if query:
            results = await ai_system.vector_db.search_similar_content(
                query=query,
                collection_type="board_posts",
                n_results=limit
            )
        else:
            # 최근 게시글 조회 (임시 구현)
            results = await ai_system.vector_db.search_similar_content(
                query="최근",
                collection_type="board_posts",
                n_results=limit
            )

        # 결과 포맷 변환
        posts = []
        for result in results:
            metadata = result.get("metadata", {})
            posts.append({
                "id": metadata.get("post_id", ""),
                "title": metadata.get("title", ""),
                "content": result.get("content", "")[:500],
                "writer": metadata.get("writer", ""),
                "board": metadata.get("board", ""),
                "date": metadata.get("date", ""),
                "views": metadata.get("views", 0),
                "likes": metadata.get("likes", 0),
                "similarity_score": 1 - result.get("distance", 0)
            })

        return {"posts": posts}

    except Exception as e:
        logger.error(f"지식베이스 검색 오류: {e}")
        return {"posts": [], "error": str(e)}

@router.get("/knowledge-base/summary")
async def get_knowledge_base_summary(
    current_user: dict = Depends(get_current_user)
):
    """지식베이스 요약 정보 (하위 호환성)"""
    try:
        ai_system = await get_ai_system()
        if not ai_system:
            return {
                "summary": {"total_posts": 0, "total_comments": 0, "board_stats": []},
                "recent_comments": []
            }

        # 시스템 상태에서 통계 추출
        status = await ai_system.get_system_status()
        vector_stats = status.get("vector_db_stats", {})

        summary = {
            "total_posts": vector_stats.get("board_posts", {}).get("document_count", 0),
            "total_comments": vector_stats.get("comments", {}).get("document_count", 0),
            "board_stats": []
        }

        return {
            "summary": summary,
            "recent_comments": []  # 추후 구현
        }

    except Exception as e:
        logger.error(f"지식베이스 요약 오류: {e}")
        return {
            "summary": {"total_posts": 0, "total_comments": 0, "board_stats": []},
            "recent_comments": []
        }
