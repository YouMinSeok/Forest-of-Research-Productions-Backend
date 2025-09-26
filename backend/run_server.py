#!/usr/bin/env python3
"""
채팅 서버 실행 스크립트
Socket.IO 포함된 FastAPI 서버를 실행합니다.
"""

import uvicorn
import asyncio
from app.main import app

async def check_database_connection():
    """데이터베이스 연결 확인"""
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        from app.core.config import settings

        client = AsyncIOMotorClient(settings.MONGO_URI)
        db = client[settings.DATABASE_NAME]

        # 연결 테스트
        await client.admin.command("ping")

        # 컬렉션 확인
        collections = await db.list_collection_names()
        print(f"📁 사용 가능한 컬렉션: {collections}")

        # 사용자 수 확인
        if "users" in collections:
            user_count = await db.users.count_documents({})
            print(f"👥 등록된 사용자 수: {user_count}")

        # 채팅방 수 확인
        if "chat_rooms" in collections:
            room_count = await db.chat_rooms.count_documents({})
            print(f"💬 생성된 채팅방 수: {room_count}")

        # 메시지 수 확인
        if "chat_messages" in collections:
            message_count = await db.chat_messages.count_documents({})
            print(f"📝 저장된 메시지 수: {message_count}")

        client.close()
        return True

    except Exception as e:
        print(f"❌ 데이터베이스 연결 실패: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Socket.IO 채팅 서버 시작 중...")
    print("=" * 60)

    # 데이터베이스 연결 확인
    print("🔍 데이터베이스 상태 확인 중...")
    db_ok = asyncio.run(check_database_connection())

    if not db_ok:
        print("❌ 데이터베이스 연결에 문제가 있습니다.")
        print("MongoDB가 실행 중인지 확인해주세요.")
        exit(1)

    print("\n✅ 데이터베이스 연결 확인 완료!")
    print("📊 서버 주소: http://localhost:8080")
    print("💬 Socket.IO 엔드포인트: ws://localhost:8080/socket.io/")
    print("📋 API 문서: http://localhost:8080/docs")
    print("\n채팅 기능을 테스트하려면:")
    print("1. 두 개의 브라우저 창을 열어주세요")
    print("2. 다른 계정으로 로그인해주세요")
    print("3. 게시글에서 '💬 1:1 채팅' 버튼을 클릭해주세요")
    print("4. 실시간 채팅을 즐겨보세요! 🎉")
    print("5. 서버 로그를 보면서 데이터 저장 상태를 확인하세요! 📊\n")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        log_level="info",
        reload=False  # Socket.IO에서는 reload=False 권장
    )
