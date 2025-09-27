# app/main.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.routers import (
    auth, research, board, activity, chat, websocket_native,
    attachment, banner, admin, ai_proxy, secure_attachment,
    enterprise_attachment, draft, google_oauth
)
from app.core.config import settings
from app.core.database import (
    connect_to_mongo, close_mongo_connection,
    get_connection_status, get_database_stats
)
import logging
import time
import traceback
import sys
import os
import tempfile
from typing import Dict, Any
import json
import psutil
import asyncio
from logging.handlers import RotatingFileHandler

# -------------------------
# 로그 디렉토리/핸들러 설정
# -------------------------
if os.name == 'nt':  # Windows
    log_dir = os.path.join(tempfile.gettempdir(), 'research_board')
else:  # Linux/Unix
    log_dir = '/tmp'

os.makedirs(log_dir, exist_ok=True)
log_file_path = os.path.join(log_dir, 'research_board.log')

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING").upper()  # 기본값 WARNING
log_level = getattr(logging, LOG_LEVEL, logging.WARNING)

handlers = []
file_handler = RotatingFileHandler(
    log_file_path, maxBytes=50 * 1024 * 1024, backupCount=5, encoding='utf-8'
)
handlers.append(file_handler)

# 개발환경에서만 콘솔 출력
if os.getenv("ENVIRONMENT", "production") == "development":
    handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=handlers
)
logger = logging.getLogger(__name__)

if log_level <= logging.INFO:
    logger.info(f"📝 로그 파일 위치: {log_file_path}")
else:
    print(f"📝 로그 파일 위치: {log_file_path}")

# -------------------------
# FastAPI 앱 생성
# -------------------------
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    debug=settings.DEBUG,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
)

# -------------------------
# ✅ 미들웨어 순서 중요!
# 1) CORS → 2) GZip → (운영일 때) 3) TrustedHost
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,  # 쿠키 안 씀 (Authorization 헤더만)
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=86400,  # Preflight 24h
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # 운영 배포 시 실제 도메인으로 제한 권장
    )

# -------------------------
# 성능 모니터링 미들웨어
# -------------------------
@app.middleware("http")
async def performance_monitoring_middleware(request: Request, call_next):
    start_time = time.time()
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"📨 {request.method} {request.url.path} - 클라이언트: {request.client.host if request.client else 'unknown'}")

    try:
        response = await call_next(request)
        process_time = time.time() - start_time

        if process_time > 2.0:
            logger.warning(f"⏱️ 느린 응답 {request.method} {request.url.path} - {process_time:.3f}초")
        elif process_time > 1.0:
            logger.info(f"🐌 {request.method} {request.url.path} - {process_time:.3f}초 - 상태: {response.status_code}")
        else:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"✅ {request.method} {request.url.path} - {process_time:.3f}초 - 상태: {response.status_code}")

        response.headers["X-Process-Time"] = str(process_time)
        return response

    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"❌ {request.method} {request.url.path} - 오류: {str(e)} - {process_time:.3f}초")
        raise

# -------------------------
# 글로벌 예외 핸들러
# -------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = int(time.time() * 1000000) % 1000000  # 6자리
    logger.error(f"🚨 글로벌 예외 [ID: {error_id}] {request.method} {request.url.path}")
    logger.error(f"예외 타입: {type(exc).__name__}")
    logger.error(f"예외 메시지: {str(exc)}")
    logger.error(f"스택 트레이스:\n{traceback.format_exc()}")

    return JSONResponse(
        status_code=500,
        content={
            "error": "서버 내부 오류가 발생했습니다.",
            "error_id": error_id,
            "detail": str(exc) if settings.DEBUG else "문제가 지속되면 관리자에게 문의하세요."
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(f"⚠️ HTTP 예외 {request.method} {request.url.path} - 상태: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"⚠️ 검증 오류 {request.method} {request.url.path} - {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"error": "요청 데이터 형식이 올바르지 않습니다.", "details": exc.errors()}
    )

# -------------------------
# 라이프사이클
# -------------------------
@app.on_event("startup")
async def startup_event():
    logger.info("🚀 연구실 게시판 시스템 시작 중...")
    try:
        await connect_to_mongo()

        try:
            from app.core.database_setup import setup_chat_database
            await setup_chat_database()
            logger.info("✅ 채팅 데이터베이스 스키마 설정 완료!")
        except Exception as e:
            logger.warning(f"⚠️ 채팅 데이터베이스 스키마 설정 실패 (무시 가능): {e}")

        try:
            logger.info("🤖 AI 서비스는 별도 마이크로서비스(ai-service:8001)로 실행됩니다.")
        except Exception as e:
            logger.error(f"❌ AI 시스템 확인 실패: {e}")

        try:
            from app.utils.scheduler import init_scheduler
            from app.core.database import get_database

            logger.info("🔄 엔터프라이즈 파일 시스템 스케줄러 초기화 중...")

            scheduler_config = {
                "upload_dir": "uploads",
                "log_dir": "logs",
                "secret_key": os.getenv("FILE_SECRET_KEY", "enterprise-secret-key-2025"),
                "prevent_duplicates": True,
                "security_level": "high",
            }

            db = await get_database()
            init_scheduler(scheduler_config, db)
            logger.info("✅ 엔터프라이즈 파일 시스템 스케줄러 시작 완료!")

        except Exception as e:
            logger.error(f"❌ 엔터프라이즈 스케줄러 초기화 실패: {e}")
            logger.info("🔄 스케줄러 없이 기본 기능으로 계속 실행...")

        memory = psutil.virtual_memory()
        cpu_count = psutil.cpu_count()
        logger.info(f"💾 시스템 메모리: {memory.total / (1024**3):.1f}GB (사용률: {memory.percent}%)")
        logger.info(f"🔧 CPU 코어: {cpu_count}개")
        logger.info(f"🖥️ 운영체제: {os.name} ({sys.platform})")

        logger.info("✅ 연구실 게시판 시스템 시작 완료!")

    except Exception as e:
        logger.error(f"❌ 시스템 시작 실패: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("⏹️ 연구실 게시판 시스템 종료 중...")
    try:
        try:
            from app.utils.scheduler import shutdown_scheduler
            shutdown_scheduler()
            logger.info("✅ 엔터프라이즈 스케줄러 정리 완료!")
        except Exception as e:
            logger.warning(f"⚠️ 엔터프라이즈 스케줄러 정리 실패: {e}")

        logger.info("🤖 AI 서비스는 별도 컨테이너에서 관리됩니다.")
        await close_mongo_connection()
        logger.info("✅ 모든 연결이 안전하게 종료되었습니다.")
    except Exception as e:
        logger.error(f"❌ 종료 중 오류: {e}")

# -------------------------
# 상태/통계 엔드포인트
# -------------------------
@app.get("/api/health")
async def health_check():
    try:
        db_status = await get_connection_status()
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=1)
        disk_usage = psutil.disk_usage('/' if os.name != 'nt' else 'C:\\')

        return {
            "status": "healthy",
            "timestamp": time.time(),
            "database": db_status,
            "system": {
                "memory_usage_percent": memory.percent,
                "cpu_usage_percent": cpu_percent,
                "disk_usage_percent": (disk_usage.used / disk_usage.total) * 100,
                "platform": sys.platform,
                "log_file": log_file_path
            },
            "version": settings.API_VERSION
        }
    except Exception as e:
        logger.error(f"상태 확인 실패: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e), "timestamp": time.time()}
        )

@app.get("/api/system/stats")
async def system_stats():
    try:
        db_stats = await get_database_stats()
        memory = psutil.virtual_memory()
        cpu_times = psutil.cpu_times()
        boot_time = psutil.boot_time()
        return {
            "database": db_stats,
            "system": {
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                    "percent": memory.percent
                },
                "cpu": {
                    "percent": psutil.cpu_percent(interval=1),
                    "count": psutil.cpu_count(),
                    "times": {
                        "user": cpu_times.user,
                        "system": cpu_times.system,
                        "idle": cpu_times.idle
                    }
                },
                "boot_time": boot_time,
                "uptime": time.time() - boot_time,
                "platform": sys.platform,
                "log_file": log_file_path
            }
        }
    except Exception as e:
        logger.error(f"시스템 통계 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="시스템 통계를 가져올 수 없습니다.")

# -------------------------
# 라우터 등록 ("/api" prefix)
# -------------------------
app.include_router(auth.router,               prefix="/api/auth",              tags=["인증"])
app.include_router(research.router,           prefix="/api/research",          tags=["연구"])
app.include_router(board.router,              prefix="/api/board",             tags=["게시판"])
app.include_router(draft.router,              prefix="/api/draft",             tags=["임시저장"])
app.include_router(activity.router,           prefix="/api/activity",          tags=["활동"])
app.include_router(chat.router,               prefix="/api/chat",              tags=["채팅"])
app.include_router(attachment.router,         prefix="/api/attachment",        tags=["첨부파일"])
app.include_router(secure_attachment.router,  prefix="/api/secure-attachment", tags=["보안 첨부파일"])
app.include_router(enterprise_attachment.router, prefix="/api/enterprise-attachment", tags=["엔터프라이즈 첨부파일"])
app.include_router(banner.router,                                             tags=["배너"])
app.include_router(admin.router,               prefix="/api/admin",             tags=["관리"])
app.include_router(ai_proxy.router,            prefix="/api/ai",                tags=["AI"])
app.include_router(google_oauth.router,                                       tags=["Google OAuth"])

# WebSocket 라우터
app.include_router(websocket_native.router, prefix="/ws", tags=["웹소켓"])

# -------------------------
# 루트 엔드포인트
# -------------------------
@app.get("/")
async def root():
    return {
        "message": "연구실 게시판 시스템 API",
        "version": settings.API_VERSION,
        "docs": "/api/docs" if settings.DEBUG else "문서 비활성화",
        "health": "/api/health",
        "stats": "/api/system/stats",
        "platform": sys.platform,
        "log_file": log_file_path
    }
