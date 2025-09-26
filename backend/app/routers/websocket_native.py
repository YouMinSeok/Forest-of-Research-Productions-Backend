# app/routers/websocket_native.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from typing import Dict, List
import json
import jwt
from datetime import datetime
import pytz
from app.core.database import db
from app.core.config import settings
import weakref
import logging

# 로거 설정 (프로덕션 최적화)
logger = logging.getLogger(__name__)

router = APIRouter()

# 서울 타임존
seoul_tz = pytz.timezone('Asia/Seoul')

# 연결된 클라이언트들 관리 - 메모리 누수 방지 최적화
class ConnectionManager:
    def __init__(self):
        # room_id -> List[WebSocket] - 강한 참조 유지
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # websocket -> user_info - WeakKeyDictionary로 메모리 누수 방지
        self.user_connections: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        # 연결 통계 (디버깅용)
        self.stats = {
            "total_connections": 0,
            "total_disconnections": 0,
            "cleanup_count": 0
        }

    async def connect(self, websocket: WebSocket, room_id: str, user_info: dict):
        try:
            await websocket.accept()

            if room_id not in self.active_connections:
                self.active_connections[room_id] = []

            self.active_connections[room_id].append(websocket)
            self.user_connections[websocket] = {
                "user_id": user_info["id"],
                "user_name": user_info["name"],
                "room_id": room_id,
                "connected_at": datetime.now(seoul_tz)
            }

            self.stats["total_connections"] += 1

            # 운영환경에서는 로깅 최소화 - WARNING 레벨 이상만 출력
            if logger.isEnabledFor(logging.INFO):
                print(f"✅ WebSocket 연결: {user_info['name']} -> {room_id}")

        except Exception as e:
            logger.error(f"WebSocket 연결 실패: {e}")
            raise

    def disconnect(self, websocket: WebSocket):
        """안전한 연결 해제 - 완전한 정리"""
        try:
            user_info = self.user_connections.get(websocket)
            if user_info:
                room_id = user_info["room_id"]

                # 방에서 WebSocket 제거
                if room_id in self.active_connections:
                    try:
                        self.active_connections[room_id].remove(websocket)
                        # 빈 방 제거
                        if not self.active_connections[room_id]:
                            del self.active_connections[room_id]
                    except ValueError:
                        # 이미 제거된 경우 무시
                        pass

                # WeakKeyDictionary에서 제거 (명시적)
                if websocket in self.user_connections:
                    del self.user_connections[websocket]

                self.stats["total_disconnections"] += 1

                # 운영환경에서는 로깅 최소화
                if logger.isEnabledFor(logging.INFO):
                    print(f"❌ WebSocket 연결 해제: {user_info['user_name']}")

        except Exception as e:
            # 연결 해제 중 오류는 경고만 하고 계속 진행
            logger.warning(f"연결 해제 중 오류 (무시됨): {e}")
            self.stats["cleanup_count"] += 1

    async def send_to_room(self, room_id: str, message: dict):
        """방의 모든 사용자에게 메시지 전송 - 실패한 연결 자동 정리"""
        if room_id not in self.active_connections:
            return

        connections = self.active_connections[room_id].copy()  # 복사본으로 안전하게 순회
        failed_connections = []

        for connection in connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                # 실패한 연결은 나중에 일괄 정리
                failed_connections.append(connection)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"메시지 전송 실패: {e}")

        # 실패한 연결들 정리
        for failed_conn in failed_connections:
            self.disconnect(failed_conn)

    async def send_typing_status(self, room_id: str, sender_websocket: WebSocket, typing_data: dict):
        """타이핑 상태 전송 - 실패한 연결 자동 정리"""
        if room_id not in self.active_connections:
            return

        connections = self.active_connections[room_id].copy()
        failed_connections = []

        for connection in connections:
            if connection != sender_websocket:  # 본인 제외
                try:
                    await connection.send_text(json.dumps(typing_data))
                except Exception as e:
                    failed_connections.append(connection)
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"타이핑 상태 전송 실패: {e}")

        # 실패한 연결들 정리
        for failed_conn in failed_connections:
            self.disconnect(failed_conn)

    def get_stats(self):
        """연결 통계 반환"""
        active_count = sum(len(conns) for conns in self.active_connections.values())
        return {
            **self.stats,
            "active_connections": active_count,
            "active_rooms": len(self.active_connections)
        }

    async def cleanup_all(self):
        """모든 연결 강제 정리 (서버 종료시)"""
        try:
            for room_connections in self.active_connections.values():
                for websocket in list(room_connections):
                    self.disconnect(websocket)
            self.active_connections.clear()
            logger.info("모든 WebSocket 연결 정리 완료")
        except Exception as e:
            logger.error(f"연결 정리 중 오류: {e}")

manager = ConnectionManager()

async def get_user_from_token(token: str):
    """JWT 토큰에서 사용자 정보 추출"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        user_name: str = payload.get("name")

        if not user_id or not user_name:
            return None

        return {"id": user_id, "name": user_name}
    except jwt.PyJWTError:
        return None

@router.websocket("/chat/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str):
    # 토큰 확인
    token = None
    if "authorization" in websocket.headers:
        auth_header = websocket.headers["authorization"]
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    # 쿼리 파라미터에서도 토큰 확인
    query_params = websocket.query_params
    if not token and "token" in query_params:
        token = query_params["token"]

    if not token:
        await websocket.close(code=4001, reason="No token provided")
        return

    # 사용자 인증
    user_info = await get_user_from_token(token)
    if not user_info:
        await websocket.close(code=4002, reason="Invalid token")
        return

    # 채팅방 권한 확인 (개인 채팅방과 그룹 채팅방 모두 확인)
    room = await db["chat_rooms"].find_one({"room_id": room_id})
    group_room = None

    if not room:
        # 개인 채팅방이 없으면 그룹 채팅방 확인
        group_room = await db["group_chat_rooms"].find_one({"room_id": room_id})
        if not group_room:
            await websocket.close(code=4003, reason="Room not found")
            return

    # 권한 확인
    if room:
        # 개인 채팅방 권한 확인
        if user_info["id"] not in [room["user1_id"], room["user2_id"]]:
            await websocket.close(code=4004, reason="Access denied")
            return
    elif group_room:
        # 그룹 채팅방 권한 확인
        if user_info["id"] not in group_room["members"]:
            await websocket.close(code=4004, reason="Access denied")
            return

    # 연결 수락
    await manager.connect(websocket, room_id, user_info)

    # 채팅방 참가 알림
    await manager.send_to_room(room_id, {
        "type": "user_joined",
        "user_id": user_info["id"],
        "user_name": user_info["name"]
    })

    try:
        while True:
            # 메시지 수신
            data = await websocket.receive_text()
            message_data = json.loads(data)

            message_type = message_data.get("type")

            if message_type == "send_message":
                await handle_send_message(room_id, user_info, message_data)

            elif message_type == "typing_start":
                await manager.send_typing_status(room_id, websocket, {
                    "type": "user_typing",
                    "user_id": user_info["id"],
                    "user_name": user_info["name"],
                    "typing": True
                })

            elif message_type == "typing_stop":
                await manager.send_typing_status(room_id, websocket, {
                    "type": "user_typing",
                    "user_id": user_info["id"],
                    "user_name": user_info["name"],
                    "typing": False
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        # 채팅방 나감 알림
        await manager.send_to_room(room_id, {
            "type": "user_left",
            "user_id": user_info["id"],
            "user_name": user_info["name"]
        })

async def handle_send_message(room_id: str, user_info: dict, message_data: dict):
    """메시지 전송 처리"""
    message_text = message_data.get("message", "").strip()

    if not message_text:
        return

    # 데이터베이스에 메시지 저장
    message_doc = {
        "room_id": room_id,
        "sender_id": user_info["id"],
        "sender_name": user_info["name"],
        "message": message_text,
        "created_at": datetime.now(seoul_tz),
        "is_read": False
    }

    result = await db["chat_messages"].insert_one(message_doc)
    message_doc["_id"] = str(result.inserted_id)

    # 메시지 저장 로깅 - DEBUG 레벨만
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"💬 메시지 저장: {user_info['name']} -> {room_id}: {message_text[:50]}...")

    # 채팅방의 마지막 메시지 업데이트
    await db["chat_rooms"].update_one(
        {"room_id": room_id},
        {
            "$set": {
                "last_message": message_text,
                "last_message_at": datetime.now(seoul_tz)
            }
        }
    )

    # 채팅방의 모든 사용자에게 메시지 전송
    await manager.send_to_room(room_id, {
        "type": "new_message",
        "id": message_doc["_id"],
        "room_id": room_id,
        "sender_id": user_info["id"],
        "sender_name": user_info["name"],
        "message": message_text,
        "created_at": message_doc["created_at"].isoformat(),
        "is_read": False
    })
