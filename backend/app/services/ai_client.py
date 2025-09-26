"""
AI Microservice HTTP 클라이언트
백엔드에서 분리된 AI 서비스와 HTTP 통신
"""

import httpx
import os
import logging
from typing import Dict, Any, Optional, List
from app.core.config import settings

logger = logging.getLogger(__name__)

class AIServiceClient:
    """AI 마이크로서비스와 통신하는 HTTP 클라이언트"""

    def __init__(self, ai_service_url: str = None):
        # 환경 변수에서 AI 서비스 URL 가져오기
        self.ai_service_url = ai_service_url or os.getenv("AI_SERVICE_URL", "http://ai-service:8001")
        self.timeout = 30.0
        self.client = None

        logger.info(f"AI Service Client initialized with URL: {self.ai_service_url}")

    async def __aenter__(self):
        """비동기 컨텍스트 매니저 진입"""
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            headers={"Content-Type": "application/json"}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """비동기 컨텍스트 매니저 종료"""
        if self.client:
            await self.client.aclose()

    async def health_check(self) -> Dict[str, Any]:
        """AI 서비스 헬스체크"""
        try:
            response = await self.client.get(f"{self.ai_service_url}/health")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"AI Service health check failed: {e}")
            raise Exception(f"AI Service unavailable: {e}")

    async def process_chat(
        self,
        message: str,
        context: Dict[str, Any] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """채팅 메시지 처리"""
        try:
            payload = {
                "message": message,
                "context": context or {},
                "user_id": user_id,
                "session_id": session_id
            }

            response = await self.client.post(
                f"{self.ai_service_url}/api/v1/chat",
                json=payload
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"AI Service chat request failed: {e.response.status_code} - {e.response.text}")
            raise Exception(f"Chat processing failed: {e.response.text}")
        except Exception as e:
            logger.error(f"AI Service chat error: {e}")
            raise Exception(f"Chat service error: {e}")

    async def search_documents(
        self,
        query: str,
        filters: Dict[str, Any] = None,
        limit: int = 10
    ) -> Dict[str, Any]:
        """문서 검색"""
        try:
            payload = {
                "query": query,
                "filters": filters or {},
                "limit": limit
            }

            response = await self.client.post(
                f"{self.ai_service_url}/api/v1/search",
                json=payload
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"AI Service search request failed: {e.response.status_code} - {e.response.text}")
            raise Exception(f"Search processing failed: {e.response.text}")
        except Exception as e:
            logger.error(f"AI Service search error: {e}")
            raise Exception(f"Search service error: {e}")

    async def create_embeddings(
        self,
        texts: List[str],
        metadata: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """텍스트 임베딩 생성"""
        try:
            payload = {
                "texts": texts,
                "metadata": metadata or []
            }

            response = await self.client.post(
                f"{self.ai_service_url}/api/v1/embeddings",
                json=payload
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"AI Service embeddings request failed: {e.response.status_code} - {e.response.text}")
            raise Exception(f"Embeddings processing failed: {e.response.text}")
        except Exception as e:
            logger.error(f"AI Service embeddings error: {e}")
            raise Exception(f"Embeddings service error: {e}")

    async def rag_query(
        self,
        question: str,
        context: Dict[str, Any] = None,
        include_sources: bool = True
    ) -> Dict[str, Any]:
        """RAG 기반 질의응답"""
        try:
            payload = {
                "question": question,
                "context": context or {},
                "include_sources": include_sources
            }

            response = await self.client.post(
                f"{self.ai_service_url}/api/v1/rag",
                json=payload
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"AI Service RAG request failed: {e.response.status_code} - {e.response.text}")
            raise Exception(f"RAG processing failed: {e.response.text}")
        except Exception as e:
            logger.error(f"AI Service RAG error: {e}")
            raise Exception(f"RAG service error: {e}")


# 전역 AI 클라이언트 인스턴스
_ai_client_instance = None

async def get_ai_client() -> AIServiceClient:
    """AI 클라이언트 인스턴스 반환 (의존성 주입용)"""
    global _ai_client_instance
    if _ai_client_instance is None:
        _ai_client_instance = AIServiceClient()
    return _ai_client_instance

async def check_ai_service_health() -> bool:
    """AI 서비스 상태 확인"""
    try:
        async with AIServiceClient() as client:
            await client.health_check()
            return True
    except Exception as e:
        logger.error(f"AI Service health check failed: {e}")
        return False
