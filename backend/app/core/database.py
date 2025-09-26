from motor.motor_asyncio import AsyncIOMotorClient
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
import asyncio
import logging
import time
from typing import Optional

# 로깅 설정
# 로깅 레벨은 main.py에서 설정됨
logger = logging.getLogger(__name__)

# MongoDB 설정 - 대규모 연구실용 성능 최적화 (호환성 수정)
client = AsyncIOMotorClient(
    settings.MONGO_URI,
    maxPoolSize=200,         # 최대 연결 풀 크기 대폭 증가 (대규모 동시 접속 대응)
    minPoolSize=20,          # 최소 연결 풀 크기 증가
    maxIdleTimeMS=45000,     # 유휴 연결 최대 시간 (45초)
    connectTimeoutMS=15000,  # 연결 타임아웃 (15초)
    serverSelectionTimeoutMS=15000,  # 서버 선택 타임아웃 (15초)
    socketTimeoutMS=45000,   # 소켓 타임아웃 (45초)
    retryWrites=True,        # 쓰기 재시도 활성화
    retryReads=True,         # 읽기 재시도 활성화
    heartbeatFrequencyMS=10000,  # 하트비트 주기 (10초)
    compressors=['zlib'],    # 압축 활성화 (snappy 제거 - 설치 불필요)
    zlibCompressionLevel=6,   # 압축 레벨
    maxConnecting=10,        # 동시 연결 시도 제한
    waitQueueTimeoutMS=5000, # 대기열 타임아웃
    journal=True,            # 저널링 활성화 (데이터 안정성)
    w="majority",            # 쓰기 확인 수준 (안전성)
    # readConcern 제거 - pymongo 호환성 문제 해결
    readPreference="primaryPreferred"   # 읽기 선호도
)
db = client[settings.DATABASE_NAME]

# SQLAlchemy 설정 - 성능 최적화
DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 20  # SQLite 연결 타임아웃
    },
    pool_pre_ping=True,      # 연결 상태 사전 확인
    pool_recycle=3600,       # 1시간마다 연결 재활용
    echo=False               # SQL 로깅 비활성화 (운영환경)
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 연결 상태 추적
_connection_health = {
    "mongodb": {"status": "unknown", "last_check": 0},
    "sqlite": {"status": "unknown", "last_check": 0}
}

async def check_mongodb_health() -> bool:
    """MongoDB 연결 상태 확인"""
    try:
        # 빠른 ping 테스트
        await asyncio.wait_for(client.admin.command("ping"), timeout=5.0)
        _connection_health["mongodb"]["status"] = "healthy"
        _connection_health["mongodb"]["last_check"] = time.time()
        return True
    except Exception as e:
        logger.error(f"MongoDB 연결 상태 불량: {e}")
        _connection_health["mongodb"]["status"] = "unhealthy"
        _connection_health["mongodb"]["last_check"] = time.time()
        return False

def check_sqlite_health() -> bool:
    """SQLite 연결 상태 확인"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        _connection_health["sqlite"]["status"] = "healthy"
        _connection_health["sqlite"]["last_check"] = time.time()
        return True
    except Exception as e:
        logger.error(f"SQLite 연결 상태 불량: {e}")
        _connection_health["sqlite"]["status"] = "unhealthy"
        _connection_health["sqlite"]["last_check"] = time.time()
        return False

async def get_connection_status():
    """전체 데이터베이스 연결 상태 반환"""
    current_time = time.time()

    # 5분 이상 된 체크는 다시 실행
    if current_time - _connection_health["mongodb"]["last_check"] > 300:
        await check_mongodb_health()

    if current_time - _connection_health["sqlite"]["last_check"] > 300:
        check_sqlite_health()

    return _connection_health

# 데이터베이스 테이블 생성
def create_tables():
    """모든 SQLAlchemy 테이블 생성"""
    try:
        # 모든 모델을 import하여 Base.metadata에 등록
        from app.models.banner import Banner
        Base.metadata.create_all(bind=engine)
        logger.info("✅ SQLAlchemy 테이블 생성 완료!")
    except Exception as e:
        logger.error(f"❌ SQLAlchemy 테이블 생성 실패: {e}")
        raise

# SQLAlchemy 의존성 주입 - 에러 핸들링 강화
def get_db():
    """데이터베이스 세션 의존성 주입 (에러 핸들링 강화)"""
    db_session = None
    try:
        db_session = SessionLocal()
        yield db_session
    except Exception as e:
        logger.error(f"데이터베이스 세션 오류: {e}")
        if db_session:
            db_session.rollback()
        raise
    finally:
        if db_session:
            db_session.close()

async def create_indexes():
    """MongoDB 인덱스 생성 - 백그라운드 및 안전 모드"""
    try:
        db = await get_database()
        logger.info("MongoDB 인덱스 생성 시작...")

        # 인덱스 생성을 안전하게 처리하는 헬퍼 함수
        async def safe_create_index(collection_name, index_spec, **kwargs):
            try:
                await db[collection_name].create_index(index_spec, **kwargs)
                logger.debug(f"✅ {collection_name} 인덱스 생성 성공: {kwargs.get('name', 'unnamed')}")
            except Exception as e:
                # 텍스트 인덱스 중복 에러 처리 (MongoDB는 컬렉션당 하나의 텍스트 인덱스만 허용)
                if "only one text index per collection allowed" in str(e):
                    logger.debug(f"ℹ️ {collection_name} 텍스트 인덱스 이미 존재, 생략: {kwargs.get('name', 'unnamed')}")
                # 인덱스 이름 충돌인 경우 기존 인덱스 삭제 후 재생성 시도
                elif ("IndexKeySpecsConflict" in str(e) or "same name" in str(e).lower()) and kwargs.get('name'):
                    try:
                        logger.info(f"🔄 {collection_name} 충돌 인덱스 삭제 후 재생성: {kwargs['name']}")
                        await db[collection_name].drop_index(kwargs['name'])
                        await db[collection_name].create_index(index_spec, **kwargs)
                        logger.info(f"✅ {collection_name} 인덱스 재생성 성공: {kwargs['name']}")
                    except Exception as retry_error:
                        logger.warning(f"⚠️ {collection_name} 인덱스 재생성 실패: {retry_error}")
                # 인덱스가 이미 존재하거나 기타 충돌하는 경우 무시
                elif ("already exists" in str(e) or
                      "IndexOptionsConflict" in str(e) or
                      "IndexKeySpecsConflict" in str(e) or
                      "same name" in str(e).lower()):
                    logger.debug(f"ℹ️ {collection_name} 인덱스 이미 존재 또는 충돌: {kwargs.get('name', 'unnamed')}")
                else:
                    logger.warning(f"⚠️ {collection_name} 인덱스 생성 실패: {e}")

        # board 컬렉션 인덱스 - 게시판 성능 최적화
        await safe_create_index("board", [
            ("board", 1),
            ("is_private", 1),
            ("created_at", -1)
        ], name="board_privacy_date", background=True)

        # 텍스트 인덱스는 아래에서 한 번만 생성 (MongoDB 제한: 컬렉션당 하나의 텍스트 인덱스만 허용)

        # 기본 인덱스들 - 백그라운드 생성으로 서비스 중단 방지
        await safe_create_index("board", [("post_number", -1)], name="post_number_desc", background=True)
        await safe_create_index("board", [("created_at", -1)], name="created_at_desc", background=True)
        await safe_create_index("board", [("writer", 1)], name="writer_index", background=True)
        await safe_create_index("board", [("is_private", 1)], name="privacy_index", background=True)

        # 조회수 정렬용 인덱스 (인기 글 조회)
        await safe_create_index("board", [
            ("board", 1),
            ("view_count", -1)
        ], name="board_view_count", background=True)

        # 검색용 텍스트 인덱스 - 한국어 최적화
        await safe_create_index("board", [
            ("title", "text"),
            ("content", "text"),
            ("writer", "text")
        ], name="board_text_search_index", background=True)

        # comments 컬렉션 인덱스 - 댓글 수 조회 최적화
        await safe_create_index("comments", [("post_id", 1)], name="comments_post_id", background=True)
        await safe_create_index("comments", [("created_at", -1)], name="comments_date", background=True)
        await safe_create_index("comments", [
            ("post_id", 1),
            ("created_at", -1)
        ], name="comments_post_date", background=True)

        # attachments 컬렉션 인덱스 - 첨부파일 수 조회 최적화
        await safe_create_index("attachments", [("post_id", 1)], name="attachments_post_id", background=True)
        await safe_create_index("attachments", [("uploaded_at", -1)], name="attachments_date", background=True)

        # users 컬렉션 인덱스 - 사용자 관리 최적화 (유니크 인덱스 안전 처리)
        await safe_create_index("users", [("email", 1)], unique=True, name="users_email_unique", background=True)
        await safe_create_index("users", [("username", 1)], name="users_username", background=True)
        await safe_create_index("users", [("created_at", -1)], name="users_date", background=True)
        await safe_create_index("users", [("last_login", -1)], name="users_last_login", background=True)

        # chat 관련 인덱스 - 실시간 채팅 성능 개선
        await safe_create_index("chat_rooms", [("participants", 1)], name="chat_participants", background=True)
        await safe_create_index("chat_messages", [
            ("room_id", 1),
            ("timestamp", -1)
        ], name="chat_room_time", background=True)
        await safe_create_index("chat_messages", [("sender_id", 1)], name="chat_sender", background=True)

        # 활동 로그 인덱스 - 사용자 활동 추적
        await safe_create_index("activity_logs", [
            ("user_id", 1),
            ("timestamp", -1)
        ], name="activity_user_time", background=True)
        await safe_create_index("activity_logs", [("action", 1)], name="activity_action", background=True)

        logger.info("✅ MongoDB 인덱스 생성 완료!")

    except Exception as e:
        logger.error(f"⚠️ 인덱스 생성 중 오류 (무시 가능): {e}")

async def connect_to_mongo():
    """MongoDB 연결 및 초기화 (복구 메커니즘 포함)"""
    max_retries = 3  # 재시도 횟수 줄임
    retry_delay = 1  # 초기 딜레이 줄임

    for attempt in range(max_retries):
        try:
            # MongoDB 연결 테스트
            await asyncio.wait_for(client.admin.command("ping"), timeout=10.0)
            logger.info("✅ MongoDB 연결 성공!")

            # 연결 상태 업데이트
            _connection_health["mongodb"]["status"] = "healthy"
            _connection_health["mongodb"]["last_check"] = time.time()

            # 인덱스 생성 (백그라운드)
            try:
                await create_indexes()
            except Exception as index_error:
                logger.warning(f"인덱스 생성 중 일부 오류 (무시 가능): {index_error}")

            # SQLAlchemy 테이블 생성
            create_tables()

            # SQLite 상태 확인
            check_sqlite_health()

            return True

        except Exception as e:
            logger.error(f"❌ MongoDB 연결 시도 {attempt + 1}/{max_retries} 실패: {e}")
            if attempt < max_retries - 1:
                logger.info(f"⏳ {retry_delay}초 후 재시도...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # 지수 백오프
            else:
                logger.error("❌ MongoDB 연결 최종 실패! 로컬 모드로 실행됩니다.")
                # MongoDB 없이도 SQLite로 기본 동작 가능
                create_tables()
                check_sqlite_health()
                return False

async def close_mongo_connection():
    """MongoDB 연결 종료"""
    try:
        client.close()
        logger.info("✅ MongoDB 연결 종료!")
    except Exception as e:
        logger.error(f"MongoDB 연결 종료 중 오류: {e}")

# 데이터베이스 의존성 주입 (비동기)
async def get_database():
    """MongoDB 데이터베이스 반환"""
    # 연결 상태 확인
    if not await check_mongodb_health():
        logger.warning("MongoDB 연결 상태 불량, 재연결 시도...")
        # 자동 재연결 로직은 motor가 처리

    return db

# 성능 모니터링을 위한 함수들
async def get_database_stats():
    """데이터베이스 성능 통계 조회"""
    try:
        stats = {}

        # MongoDB 통계 (연결 상태 확인 후)
        if await check_mongodb_health():
            try:
                mongo_stats = await db.command("dbStats")
                stats["mongodb"] = {
                    "collections": mongo_stats.get("collections", 0),
                    "dataSize": mongo_stats.get("dataSize", 0),
                    "indexSize": mongo_stats.get("indexSize", 0),
                    "objects": mongo_stats.get("objects", 0)
                }

                # 컬렉션별 문서 수
                stats["collections"] = {}
                for collection_name in ["board", "comments", "attachments", "users", "chat_rooms", "chat_messages"]:
                    try:
                        count = await db[collection_name].count_documents({})
                        stats["collections"][collection_name] = count
                    except Exception:
                        stats["collections"][collection_name] = 0
            except Exception as e:
                logger.warning(f"MongoDB 통계 조회 실패: {e}")
                stats["mongodb"] = {"error": "연결 불가"}
        else:
            stats["mongodb"] = {"error": "연결 불가"}

        return stats

    except Exception as e:
        logger.error(f"데이터베이스 통계 조회 실패: {e}")
        return {"error": str(e)}
