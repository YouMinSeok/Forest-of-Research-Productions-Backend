from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from typing import Dict, Any, List, Optional
import logging
import httpx
import json
import asyncio

from app.services.ai_client import get_ai_client, AIServiceClient
from app.utils.auth_middleware import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/chat")
async def chat_proxy(
    request: Request,
    ai_client: AIServiceClient = Depends(get_ai_client),
    current_user = Depends(get_current_user)
):
    """채팅 요청을 AI 서비스로 프록시"""
    try:
        body = await request.json()
        message = body.get("message", "")
        context = body.get("context", {})

        # 사용자 정보를 컨텍스트에 추가 (User 객체 처리)
        user_id = str(current_user.id) if hasattr(current_user, 'id') else None
        user_role = getattr(current_user, 'role', 'user') if hasattr(current_user, 'role') else 'user'

        context["user_id"] = user_id
        context["user_role"] = user_role

        async with ai_client as client:
            result = await client.process_chat(
                message=message,
                context=context,
                user_id=user_id,
                session_id=body.get("session_id")
            )

        return JSONResponse(content=result)

    except Exception as e:
        logger.error(f"Error in chat proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Chat service error: {str(e)}")

@router.post("/chat/stream")
async def chat_stream_proxy(
    request: Request,
    current_user: Dict = Depends(get_current_user)
):
    """스트리밍 채팅 요청을 AI 서비스로 프록시"""
    try:
        body = await request.json()
        message = body.get("message", "")
        conversation_id = body.get("conversation_id")

        # AI 서비스로 스트리밍 요청 전달
        async def generate_stream():
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    async with client.stream(
                        "POST",
                        "http://ai-service:8001/api/v1/chat/stream",
                        json={
                            "message": message,
                            "user_id": getattr(current_user, 'id', None),
                            "conversation_id": conversation_id
                        },
                        headers={"Content-Type": "application/json"}
                    ) as response:
                        if response.status_code != 200:
                            yield f"data: {json.dumps({'error': f'AI service error: {response.status_code}'})}\n\n"
                            return

                        async for chunk in response.aiter_text():
                            if chunk:
                                yield chunk

            except Exception as e:
                logger.error(f"Stream error: {e}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return StreamingResponse(
            generate_stream(),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*"
            }
        )

    except Exception as e:
        logger.error(f"Error in chat stream proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Chat stream service error: {str(e)}")

@router.get("/suggestions")
async def suggestions_proxy(
    current_user: Dict = Depends(get_current_user)
):
    """AI 제안을 AI 서비스에서 가져오기"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "http://ai-service:8001/api/v1/suggestions",
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                return JSONResponse(content=response.json())
            else:
                # AI 서비스가 응답하지 않으면 기본 제안 반환
                return JSONResponse(content={
                    "suggestions": [
                        "연구실에 대해 알려주세요",
                        "최근 연구 동향은 어떤가요?",
                        "논문 작성에 도움을 받을 수 있나요?",
                        "실험 데이터 분석 방법을 알려주세요",
                        "연구실 규칙은 무엇인가요?"
                    ]
                })

    except Exception as e:
        logger.error(f"Error getting suggestions: {e}")
        # 오류 시 기본 제안 반환
        return JSONResponse(content={
            "suggestions": [
                "연구실에 대해 알려주세요",
                "최근 연구 동향은 어떤가요?",
                "논문 작성에 도움을 받을 수 있나요?",
                "실험 데이터 분석 방법을 알려주세요",
                "연구실 규칙은 무엇인가요?"
            ]
        })

@router.post("/search")
async def search_proxy(
    request: Request,
    ai_client: AIServiceClient = Depends(get_ai_client),
    current_user: Dict = Depends(get_current_user)
):
    """검색 요청을 AI 서비스로 프록시"""
    try:
        body = await request.json()
        query = body.get("query", "")
        limit = body.get("limit", 5)
        filters = body.get("filters", {})

        # 사용자별 필터링 추가 (권한에 따라)
        if getattr(current_user, 'role', 'user') != "admin":
            filters["user_accessible"] = True

        async with ai_client as client:
            result = await client.search_documents(
                query=query,
                limit=limit,
                filters=filters
            )

        return JSONResponse(content=result)

    except Exception as e:
        logger.error(f"Error in search proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Search service error: {str(e)}")

@router.post("/embeddings")
async def embeddings_proxy(
    request: Request,
    ai_client: AIServiceClient = Depends(get_ai_client),
    current_user = Depends(get_current_user)
):
    """임베딩 요청을 AI 서비스로 프록시"""
    try:
        # 관리자만 직접 임베딩 생성 가능
        user_role = getattr(current_user, 'role', 'user') if hasattr(current_user, 'role') else 'user'
        if user_role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        body = await request.json()
        texts = body.get("texts", [])

        async with ai_client as client:
            result = await client.generate_embeddings(texts)

        return JSONResponse(content=result)

    except Exception as e:
        logger.error(f"Error in embeddings proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Embeddings service error: {str(e)}")

@router.post("/documents")
async def add_documents_proxy(
    request: Request,
    ai_client: AIServiceClient = Depends(get_ai_client),
    current_user = Depends(get_current_user)
):
    """문서 추가 요청을 AI 서비스로 프록시"""
    try:
        # 관리자만 문서 추가 가능
        user_role = getattr(current_user, 'role', 'user') if hasattr(current_user, 'role') else 'user'
        if user_role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        body = await request.json()
        documents = body.get("documents", [])

        # 문서에 메타데이터 추가
        user_id = str(current_user.id) if hasattr(current_user, 'id') else None
        for doc in documents:
            doc["metadata"] = doc.get("metadata", {})
            doc["metadata"]["added_by"] = user_id
            doc["metadata"]["added_at"] = "current_timestamp"  # 실제 타임스탬프로 교체

        async with ai_client as client:
            result = await client.add_documents(documents)

        return JSONResponse(content=result)

    except Exception as e:
        logger.error(f"Error in add documents proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Document service error: {str(e)}")

@router.post("/rag")
async def rag_proxy(
    request: Request,
    ai_client: AIServiceClient = Depends(get_ai_client),
    current_user = Depends(get_current_user)
):
    """RAG 요청을 AI 서비스로 프록시"""
    try:
        body = await request.json()
        question = body.get("question", "")
        context_limit = body.get("context_limit", 5)
        include_sources = body.get("include_sources", True)
        temperature = body.get("temperature", 0.7)

        async with ai_client as client:
            result = await client.rag_query(
                question=question,
                context_limit=context_limit,
                include_sources=include_sources,
                temperature=temperature
            )

        return JSONResponse(content=result)

    except Exception as e:
        logger.error(f"Error in RAG proxy: {e}")
        raise HTTPException(status_code=500, detail=f"RAG service error: {str(e)}")

@router.get("/health")
async def ai_service_health(
    ai_client: AIServiceClient = Depends(get_ai_client)
):
    """AI 서비스 상태 확인"""
    try:
        async with ai_client as client:
            result = await client.health_check()

        return JSONResponse(content={
            "status": "healthy",
            "ai_service": result,
            "proxy": "operational"
        })

    except Exception as e:
        logger.error(f"AI service health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "proxy": "operational"
            }
        )
