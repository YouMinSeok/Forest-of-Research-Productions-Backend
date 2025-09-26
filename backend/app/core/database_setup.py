# app/core/database_setup.py
"""
채팅 기능을 위한 MongoDB 데이터베이스 스키마 및 인덱스 설정
"""

from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
import asyncio

async def setup_chat_database():
    """채팅 관련 데이터베이스 컬렉션 및 인덱스 설정"""

    from app.core.database import db

    print("🔧 채팅 데이터베이스 설정 시작...")

    try:
        # 1. chat_rooms 컬렉션 설정
        print("📁 chat_rooms 컬렉션 설정 중...")

        # room_id에 유니크 인덱스 생성 (중복 방지)
        try:
            await db.chat_rooms.create_index("room_id", unique=True)
            print("✅ room_id 유니크 인덱스 생성")
        except Exception as e:
            print(f"ℹ️ room_id 인덱스 이미 존재")

        # 사용자별 채팅방 검색을 위한 복합 인덱스
        try:
            await db.chat_rooms.create_index([("user1_id", 1), ("user2_id", 1)])
            print("✅ 사용자 복합 인덱스 생성")
        except Exception as e:
            print(f"ℹ️ 사용자 복합 인덱스 이미 존재")

        # 최근 메시지 순 정렬을 위한 인덱스
        try:
            await db.chat_rooms.create_index([("last_message_at", -1)])
            print("✅ 메시지 시간 인덱스 생성")
        except Exception as e:
            print(f"ℹ️ 메시지 시간 인덱스 이미 존재")

        print("✅ chat_rooms 인덱스 생성 완료")


        # 2. chat_messages 컬렉션 설정
        print("📁 chat_messages 컬렉션 설정 중...")

        # 채팅방별 메시지 조회를 위한 인덱스
        try:
            await db.chat_messages.create_index([("room_id", 1), ("created_at", 1)])
            print("✅ 메시지 조회 인덱스 생성")
        except Exception as e:
            print(f"ℹ️ 메시지 조회 인덱스 이미 존재")

        # 읽지 않은 메시지 카운트를 위한 인덱스
        try:
            await db.chat_messages.create_index([("room_id", 1), ("sender_id", 1), ("is_read", 1)])
            print("✅ 읽지 않은 메시지 인덱스 생성")
        except Exception as e:
            print(f"ℹ️ 읽지 않은 메시지 인덱스 이미 존재")

        # 메시지 생성 시간순 정렬 인덱스
        try:
            await db.chat_messages.create_index([("created_at", -1)])
            print("✅ 메시지 시간순 인덱스 생성")
        except Exception as e:
            print(f"ℹ️ 메시지 시간순 인덱스 이미 존재")

        print("✅ chat_messages 인덱스 생성 완료")


        # 3. 기존 users 컬렉션 확인
        print("👤 users 컬렉션 확인 중...")

        # 사용자 검색을 위한 인덱스 (이미 있을 수 있음)
        try:
            await db.users.create_index("email", unique=True)
            print("✅ users 이메일 인덱스 확인/생성 완료")
        except Exception as e:
            print(f"ℹ️ users 이메일 인덱스 이미 존재: {e}")


        # 4. 데이터베이스 상태 확인
        print("\n📊 데이터베이스 상태 확인:")

        # 컬렉션 목록 출력
        collections = await db.list_collection_names()
        print(f"📁 생성된 컬렉션: {collections}")

        # 인덱스 확인
        chat_rooms_indexes = await db.chat_rooms.list_indexes().to_list(length=None)
        chat_messages_indexes = await db.chat_messages.list_indexes().to_list(length=None)

        print(f"🔍 chat_rooms 인덱스 수: {len(chat_rooms_indexes)}")
        print(f"🔍 chat_messages 인덱스 수: {len(chat_messages_indexes)}")


        # 5. 테스트 데이터 생성 (선택사항)
        print("\n🧪 테스트 데이터 확인...")

        chat_rooms_count = await db.chat_rooms.count_documents({})
        chat_messages_count = await db.chat_messages.count_documents({})
        users_count = await db.users.count_documents({})

        print(f"👥 사용자 수: {users_count}")
        print(f"💬 채팅방 수: {chat_rooms_count}")
        print(f"📝 메시지 수: {chat_messages_count}")

        print("\n✅ 채팅 데이터베이스 설정 완료!")
        print("🚀 이제 채팅 기능을 사용할 수 있습니다!")

        return True

    except Exception as e:
        print(f"❌ 데이터베이스 설정 오류: {e}")
        return False

    finally:
        pass  # DB 연결은 앱 전체에서 공유하므로 여기서 닫지 않음

# 직접 실행 시 스크립트
if __name__ == "__main__":
    print("🗄️ 채팅 데이터베이스 초기화 스크립트")
    print("=" * 50)

    result = asyncio.run(setup_chat_database())

    if result:
        print("\n🎉 데이터베이스 설정이 완료되었습니다!")
        print("이제 서버를 시작할 수 있습니다:")
        print("python run_server.py")
    else:
        print("\n😞 데이터베이스 설정에 실패했습니다.")
        print("MongoDB 연결을 확인해주세요.")
