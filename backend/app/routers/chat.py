# app/routers/chat.py
from fastapi import APIRouter, HTTPException, Depends
from app.core.database import get_database
from app.models.chat import ChatRoomCreate, ChatRoom, ChatMessageCreate, ChatMessage, ChatRoomResponse, GroupChatRoomCreate, GroupChatRoom, GroupChatRoomResponse, UserSearchResult
from app.utils.security import get_current_user
from bson import ObjectId
from datetime import datetime
from typing import List
import pytz
import uuid

router = APIRouter()

# 서울 타임존 객체 생성
seoul_tz = pytz.timezone('Asia/Seoul')

def create_room_id(user1_id: str, user2_id: str) -> str:
    """두 사용자 ID로 고유한 방 ID 생성 (작은 ID를 앞에)"""
    users = sorted([user1_id, user2_id])
    return f"{users[0]}_{users[1]}"

@router.post("/room/create")
async def create_or_get_chat_room(
    request_data: dict,
    db=Depends(get_database),
    current_user=Depends(get_current_user)
):
    """채팅방 생성 또는 기존 방 조회"""
    try:
        current_user_id = current_user.id
        current_user_name = current_user.name

        target_user_id = request_data.get("target_user_id")
        target_user_name = request_data.get("target_user_name")

        if not target_user_id or not target_user_name:
            raise HTTPException(status_code=400, detail="대상 사용자 정보가 필요합니다.")

        # 자기 자신과는 채팅할 수 없음
        if current_user_id == target_user_id:
            raise HTTPException(status_code=400, detail="자기 자신과는 채팅할 수 없습니다.")

        # 방 ID 생성
        room_id = create_room_id(current_user_id, target_user_id)

        # 기존 채팅방 확인
        existing_room = await db["chat_rooms"].find_one({"room_id": room_id})

        if existing_room:
            print(f"🔍 기존 채팅방 발견: {room_id}")
            print(f"📊 기존 방 데이터: {existing_room}")
            return {"room_id": room_id, "status": "existing"}

        # 새 채팅방 생성
        chat_room_data = {
            "room_id": room_id,
            "user1_id": min(current_user_id, target_user_id),
            "user2_id": max(current_user_id, target_user_id),
            "user1_name": current_user_name if current_user_id < target_user_id else target_user_name,
            "user2_name": target_user_name if current_user_id < target_user_id else current_user_name,
            "created_at": datetime.now(seoul_tz),
            "last_message": None,
            "last_message_at": None
        }

        result = await db["chat_rooms"].insert_one(chat_room_data)

        print(f"✅ 새 채팅방 생성됨: {room_id}")
        print(f"📊 저장된 데이터: {chat_room_data}")
        print(f"🔑 MongoDB Document ID: {result.inserted_id}")

        return {
            "room_id": room_id,
            "status": "created",
            "_id": str(result.inserted_id)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"채팅방 생성 실패: {str(e)}")

@router.get("/rooms")
async def get_user_chat_rooms(
    db=Depends(get_database),
    current_user=Depends(get_current_user)
) -> List[ChatRoomResponse]:
    """사용자의 채팅방 목록 조회"""
    try:
        user_id = current_user.id

        # 사용자가 참여한 채팅방 조회
        rooms = await db["chat_rooms"].find({
            "$or": [
                {"user1_id": user_id},
                {"user2_id": user_id}
            ]
        }).sort("last_message_at", -1).to_list(length=None)

        room_responses = []
        for room in rooms:
            # 상대방 정보 결정
            if room["user1_id"] == user_id:
                other_user_id = room["user2_id"]
                other_user_name = room["user2_name"]
            else:
                other_user_id = room["user1_id"]
                other_user_name = room["user1_name"]

            # 읽지 않은 메시지 수 조회
            unread_count = await db["chat_messages"].count_documents({
                "room_id": room["room_id"],
                "sender_id": {"$ne": user_id},
                "is_read": False
            })

            room_responses.append(ChatRoomResponse(
                room_id=room["room_id"],
                other_user_id=other_user_id,
                other_user_name=other_user_name,
                last_message=room.get("last_message"),
                last_message_at=room.get("last_message_at"),
                unread_count=unread_count
            ))

        return room_responses

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"채팅방 목록 조회 실패: {str(e)}")

@router.get("/room/{room_id}/messages")
async def get_chat_messages(
    room_id: str,
    skip: int = 0,
    limit: int = 50,
    db=Depends(get_database),
    current_user=Depends(get_current_user)
):
    """채팅방의 메시지 조회"""
    try:
        user_id = current_user.id

        # 채팅방 권한 확인 (개인 채팅방과 그룹 채팅방 모두 확인)
        room = await db["chat_rooms"].find_one({"room_id": room_id})
        group_room = None

        if not room:
            # 개인 채팅방이 없으면 그룹 채팅방 확인
            group_room = await db["group_chat_rooms"].find_one({"room_id": room_id})
            if not group_room:
                raise HTTPException(status_code=404, detail="채팅방을 찾을 수 없습니다.")

        # 권한 확인
        if room:
            # 개인 채팅방 권한 확인
            if user_id not in [room["user1_id"], room["user2_id"]]:
                raise HTTPException(status_code=403, detail="이 채팅방에 접근할 권한이 없습니다.")
        elif group_room:
            # 그룹 채팅방 권한 확인
            if user_id not in group_room["members"]:
                raise HTTPException(status_code=403, detail="이 그룹 채팅방에 접근할 권한이 없습니다.")

        # 메시지 조회 (최신순)
        messages = await db["chat_messages"].find({
            "room_id": room_id
        }).sort("created_at", -1).skip(skip).limit(limit).to_list(length=None)

        print(f"📥 메시지 조회: {room_id} -> {len(messages)}개 메시지 발견")

        # 시간순으로 정렬 (오래된 것부터)
        messages.reverse()

        # 메시지를 읽음으로 표시 (상대방이 보낸 메시지만)
        await db["chat_messages"].update_many(
            {
                "room_id": room_id,
                "sender_id": {"$ne": user_id},
                "is_read": False
            },
            {"$set": {"is_read": True}}
        )

        # ObjectId를 문자열로 변환
        for message in messages:
            if "_id" in message:
                message["_id"] = str(message["_id"])

        return messages

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"메시지 조회 실패: {str(e)}")

@router.post("/room/{room_id}/message")
async def send_message(
    room_id: str,
    message_data: dict,
    db=Depends(get_database),
    current_user=Depends(get_current_user)
):
    """메시지 전송"""
    try:
        user_id = current_user.id
        user_name = current_user["name"]
        message = message_data.get("message", "").strip()

        if not message:
            raise HTTPException(status_code=400, detail="메시지 내용이 비어있습니다.")

        # 채팅방 권한 확인 (개인 채팅방과 그룹 채팅방 모두 확인)
        room = await db["chat_rooms"].find_one({"room_id": room_id})
        group_room = None

        if not room:
            # 개인 채팅방이 없으면 그룹 채팅방 확인
            group_room = await db["group_chat_rooms"].find_one({"room_id": room_id})
            if not group_room:
                raise HTTPException(status_code=404, detail="채팅방을 찾을 수 없습니다.")

        # 권한 확인
        if room:
            # 개인 채팅방 권한 확인
            if user_id not in [room["user1_id"], room["user2_id"]]:
                raise HTTPException(status_code=403, detail="이 채팅방에 접근할 권한이 없습니다.")
        elif group_room:
            # 그룹 채팅방 권한 확인
            if user_id not in group_room["members"]:
                raise HTTPException(status_code=403, detail="이 그룹 채팅방에 접근할 권한이 없습니다.")

        # 메시지 저장
        message_doc = {
            "room_id": room_id,
            "sender_id": user_id,
            "sender_name": user_name,
            "message": message,
            "created_at": datetime.now(seoul_tz),
            "is_read": False
        }

        result = await db["chat_messages"].insert_one(message_doc)

        # 채팅방의 마지막 메시지 업데이트 (개인 채팅방 또는 그룹 채팅방)
        if room:
            await db["chat_rooms"].update_one(
                {"room_id": room_id},
                {
                    "$set": {
                        "last_message": message,
                        "last_message_at": datetime.now(seoul_tz)
                    }
                }
            )
        elif group_room:
            await db["group_chat_rooms"].update_one(
                {"room_id": room_id},
                {
                    "$set": {
                        "last_message": message,
                        "last_message_at": datetime.now(seoul_tz)
                    }
                }
            )

        message_doc["_id"] = str(result.inserted_id)

        return message_doc

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"메시지 전송 실패: {str(e)}")

# ============= 그룹 채팅 관련 API =============

@router.post("/groups/create")
async def create_group_chat(
    group_data: GroupChatRoomCreate,
    db=Depends(get_database),
    current_user=Depends(get_current_user)
):
    """그룹 채팅방 생성"""
    try:
        current_user_id = current_user.id
        current_user_name = current_user.name

        # 멤버 수 제한 확인 (최대 5명)
        if len(group_data.memberIds) > 5:
            raise HTTPException(status_code=400, detail="그룹 채팅은 최대 5명까지만 참여할 수 있습니다.")

        # 현재 사용자가 멤버 목록에 포함되어 있는지 확인
        if current_user_id not in group_data.memberIds:
            raise HTTPException(status_code=400, detail="그룹 생성자는 반드시 멤버에 포함되어야 합니다.")

        # 고유한 그룹 ID 생성
        group_room_id = f"group_{uuid.uuid4().hex[:12]}"

        # 멤버 정보 조회
        member_names = []
        for member_id in group_data.memberIds:
            user = await db["users"].find_one({"_id": ObjectId(member_id)})
            if user:
                member_names.append(user["name"])
            else:
                member_names.append("알 수 없는 사용자")

        # 그룹 채팅방 생성
        group_room_data = {
            "room_id": group_room_id,
            "name": group_data.name,
            "members": group_data.memberIds,
            "member_names": member_names,
            "created_at": datetime.now(seoul_tz),
            "created_by": current_user_id,
            "last_message": None,
            "last_message_at": None,
            "is_group": True
        }

        result = await db["group_chat_rooms"].insert_one(group_room_data)

        print(f"✅ 새 그룹 채팅방 생성됨: {group_room_id}")
        print(f"📊 저장된 데이터: {group_room_data}")

        return {
            "room_id": group_room_id,
            "name": group_data.name,
            "members": group_data.memberIds,
            "member_names": member_names,
            "status": "created",
            "_id": str(result.inserted_id)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"그룹 채팅방 생성 실패: {str(e)}")

@router.get("/groups")
async def get_user_group_chats(
    db=Depends(get_database),
    current_user=Depends(get_current_user)
) -> List[GroupChatRoomResponse]:
    """사용자가 참여한 그룹 채팅방 목록 조회"""
    try:
        user_id = current_user.id

        # 사용자가 참여한 그룹 채팅방 조회
        groups = await db["group_chat_rooms"].find({
            "members": user_id
        }).sort("last_message_at", -1).to_list(length=None)

        group_responses = []
        for group in groups:
            # 읽지 않은 메시지 수 조회
            unread_count = await db["chat_messages"].count_documents({
                "room_id": group["room_id"],
                "sender_id": {"$ne": user_id},
                "is_read": False
            })

            group_responses.append(GroupChatRoomResponse(
                room_id=group["room_id"],
                name=group["name"],
                members=group["members"],
                member_names=group["member_names"],
                last_message=group.get("last_message"),
                last_message_at=group.get("last_message_at"),
                unread_count=unread_count,
                is_group=True
            ))

        return group_responses

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"그룹 채팅방 목록 조회 실패: {str(e)}")

# ============= 사용자 검색 API =============

@router.get("/users/search")
async def search_users(
    q: str,
    db=Depends(get_database),
    current_user=Depends(get_current_user)
) -> List[UserSearchResult]:
    """멤버 검색 (이름 또는 이메일로)"""
    try:
        if len(q.strip()) < 2:
            return []

        # 이름 또는 이메일로 검색
        query = {
            "$or": [
                {"name": {"$regex": q, "$options": "i"}},
                {"email": {"$regex": q, "$options": "i"}}
            ]
        }

        users = await db["users"].find(query).limit(20).to_list(length=None)

        user_results = []
        for user in users:
            user_results.append(UserSearchResult(
                id=str(user["_id"]),
                name=user["name"],
                email=user["email"]
            ))

        return user_results

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"사용자 검색 실패: {str(e)}")

# ============= 통합 채팅방 목록 조회 =============

@router.get("/rooms/all")
async def get_all_chat_rooms(
    db=Depends(get_database),
    current_user=Depends(get_current_user)
):
    """1대1 채팅방과 그룹 채팅방을 모두 조회"""
    try:
        user_id = current_user.id

        # 1대1 채팅방 조회
        individual_rooms = await get_user_chat_rooms(db, current_user)

        # 그룹 채팅방 조회
        group_rooms = await get_user_group_chats(db, current_user)

        # 모든 채팅방을 하나의 리스트로 합치고 마지막 메시지 시간순으로 정렬
        all_rooms = []

        for room in individual_rooms:
            all_rooms.append({
                "room_id": room.room_id,
                "name": room.other_user_name,
                "is_group": False,
                "last_message": room.last_message,
                "last_message_at": room.last_message_at,
                "unread_count": room.unread_count,
                "other_user_id": room.other_user_id,
                "other_user_name": room.other_user_name
            })

        for room in group_rooms:
            all_rooms.append({
                "room_id": room.room_id,
                "name": room.name,
                "is_group": True,
                "last_message": room.last_message,
                "last_message_at": room.last_message_at,
                "unread_count": room.unread_count,
                "members": room.members,
                "member_names": room.member_names
            })

        # 마지막 메시지 시간순으로 정렬 - timezone 문제 해결
        def get_sort_key(room):
            last_msg_at = room["last_message_at"]
            if last_msg_at is None:
                # None인 경우 최소값 반환 (timezone-aware)
                return datetime.min.replace(tzinfo=pytz.UTC)

            # datetime이 timezone-naive인 경우 seoul_tz로 localize
            if last_msg_at.tzinfo is None:
                try:
                    return seoul_tz.localize(last_msg_at)
                except:
                    # localize 실패시 UTC로 처리
                    return pytz.UTC.localize(last_msg_at)

            # 이미 timezone-aware인 경우 그대로 반환
            return last_msg_at

        all_rooms.sort(key=get_sort_key, reverse=True)

        return all_rooms

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"전체 채팅방 목록 조회 실패: {str(e)}")
