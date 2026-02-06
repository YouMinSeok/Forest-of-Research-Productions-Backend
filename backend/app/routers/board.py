# app/routers/board.py
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import Response
from app.core.database import get_database
from bson import ObjectId
from datetime import datetime, timedelta
import pytz  # 타임존 처리를 위한 라이브러리
import json
import os  # 파일 삭제를 위한 import
import logging  # 로깅 추가
from app.utils.auth_middleware import get_current_user, get_current_user_optional, require_permission
from app.models.permission import PermissionType, UserRole
from pymongo import ReturnDocument

# 로거 설정
logger = logging.getLogger(__name__)

router = APIRouter()

# 서울 타임존 객체 생성
seoul_tz = pytz.timezone('Asia/Seoul')

# ===== 게시글 관련 엔드포인트 =====

@router.post("/create")
async def create_post(post: dict, db=Depends(get_database), user=Depends(get_current_user)):
    user_dict = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
        "permissions": user.permissions,
        "is_admin": user.is_admin
    }

    from app.utils.permissions import PermissionManager
    from app.models.permission import PermissionType

    if not PermissionManager.has_permission(user, PermissionType.WRITE):
        raise HTTPException(
            status_code=403,
            detail="게시글 작성 권한이 없습니다."
        )

    if "board" not in post:
        raise HTTPException(status_code=400, detail="게시판 유형(board)이 필요합니다.")
    if "title" not in post or "content" not in post:
        raise HTTPException(status_code=400, detail="제목과 내용은 필수입니다.")

    post["writer"] = user_dict["name"]
    post["writer_id"] = user_dict["id"]
    # ISO 형식 대신 UTC 타임스탬프 형식으로 변경
    seoul_time = datetime.now(seoul_tz)
    post["date"] = seoul_time.strftime("%Y-%m-%d %H:%M:%S")
    post["views"] = 0
    post["likes"] = 0
    post["prefix"] = post.get("prefix", "")

    post["is_private"] = post.get("is_private", False)
    post["allow_comments"] = post.get("allow_comments", True)

    counter_key = f"{post['board']}_post_number"

    counter = await db["counters"].find_one_and_update(
        {"_id": counter_key},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    post_number = counter["seq"] if counter else 1
    post["post_number"] = post_number

    collection = db["board"]
    result = await collection.insert_one(post)
    new_post = await collection.find_one({"_id": result.inserted_id})
    if not new_post:
        raise HTTPException(status_code=404, detail="생성된 게시글을 찾을 수 없습니다.")

    new_post["id"] = str(new_post["_id"])
    del new_post["_id"]

    try:
        board_name = post['board']
        print(f"🔄 '{board_name}' 게시판 캐시 무효화 시작")

        if hasattr(list_posts, '_cache'):
            keys_to_delete = [
                key for key in list_posts._cache.keys()
                if key.startswith(f"board_list:{board_name}:")
            ]
            for key in keys_to_delete:
                del list_posts._cache[key]
                print(f"  🗑️ 캐시 삭제: {key}")

            all_keys_to_delete = [
                key for key in list_posts._cache.keys()
                if key.startswith("board_list:all:")
            ]
            for key in all_keys_to_delete:
                del list_posts._cache[key]
                print(f"  🗑️ 전체 캐시 삭제: {key}")

        print(f"✅ '{board_name}' 게시판 캐시 무효화 완료")
    except Exception as e:
        print(f"❌ 캐시 무효화 오류: {e}")
        pass

    return new_post

# ===== Draft Post 시스템 =====

@router.post("/draft")
async def create_draft_post(
    draft_data: dict,
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    user_dict = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
        "permissions": user.permissions,
        "is_admin": user.is_admin
    }

    from app.utils.permissions import PermissionManager
    from app.models.permission import PermissionType

    if not PermissionManager.has_permission(user, PermissionType.WRITE):
        raise HTTPException(
            status_code=403,
            detail="게시글 작성 권한이 없습니다."
        )

    if "board" not in draft_data:
        raise HTTPException(status_code=400, detail="게시판 유형(board)이 필요합니다.")

    draft_post = {
        "board": draft_data["board"],
        "title": "",
        "content": "",
        "writer": user_dict["name"],
        "writer_id": user_dict["id"],
        "date": datetime.now(seoul_tz).isoformat(),
        "status": "draft",
        "views": 0,
        "likes": 0,
        "prefix": "",
        "is_private": draft_data.get("is_private", False),
        "allow_comments": draft_data.get("allow_comments", True),
        "created_at": datetime.now(seoul_tz).isoformat(),
        "updated_at": datetime.now(seoul_tz).isoformat()
    }

    collection = db["board"]
    result = await collection.insert_one(draft_post)

    if not result.inserted_id:
        raise HTTPException(status_code=500, detail="Draft 게시글 생성 실패")

    return {
        "post_id": str(result.inserted_id),
        "status": "draft",
        "message": "임시 게시글이 생성되었습니다."
    }

@router.options("/{post_id}/publish")
async def options_publish(post_id: str):
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age": "86400"
        }
    )

@router.patch("/{post_id}/publish")
async def publish_draft_post(
    post_id: str,
    post_data: dict,
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """Draft 게시글을 발행 상태로 변경"""

    import logging
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"📤 Draft 발행 시작: {post_id}, 사용자: {user.name}")
        logger.info(f"📋 발행 데이터: {post_data}")

        try:
            post_oid = ObjectId(post_id)
        except Exception as e:
            logger.error(f"❌ 잘못된 ObjectId: {post_id} - {str(e)}")
            raise HTTPException(status_code=400, detail="유효하지 않은 게시글 ID입니다.")

        # 기존 draft 조회
        collection = db["board"]
        draft_post = await collection.find_one({"_id": post_oid, "status": "draft"})

        if not draft_post:
            logger.error(f"❌ Draft 게시글 없음: {post_id}")
            raise HTTPException(status_code=404, detail="Draft 게시글을 찾을 수 없습니다.")

        # 작성자 확인
        if draft_post["writer_id"] != user.id:
            logger.error(f"❌ 권한 없음: draft={draft_post['writer_id']}, user={user.id}")
            raise HTTPException(status_code=403, detail="본인이 작성한 게시글만 발행할 수 있습니다.")

        # 제목과 내용 검증
        if not post_data.get("title", "").strip():
            logger.error("❌ 제목 누락")
            raise HTTPException(status_code=400, detail="제목은 필수입니다.")
        if not post_data.get("content", "").strip():
            logger.error("❌ 내용 누락")
            raise HTTPException(status_code=400, detail="내용은 필수입니다.")

        # 게시글 번호 생성 (발행 시점에 생성)
        counter_key = f"{draft_post['board']}_post_number"
        logger.info(f"🔢 카운터 업데이트: {counter_key}")

        counter = await db["counters"].find_one_and_update(
            {"_id": counter_key},
            {"$inc": {"seq": 1}},
            upsert=True,
            return_document=ReturnDocument.AFTER
        )
        post_number = counter["seq"] if counter else 1
        logger.info(f"✅ 게시글 번호: {post_number}")

        # Draft를 Published로 업데이트
        update_data = {
            "title": post_data["title"],
            "content": post_data["content"],
            "prefix": post_data.get("prefix", ""),
            "second_prefix": post_data.get("second_prefix", ""),
            "tags": post_data.get("tags", []),
            "is_private": post_data.get("is_private", False),
            "allow_comments": post_data.get("allow_comments", True),
            "status": "published",
            "post_number": post_number,
            "date": datetime.now(seoul_tz).strftime("%Y-%m-%d %H:%M:%S"),
            "published_at": datetime.now(seoul_tz).strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": datetime.now(seoul_tz).strftime("%Y-%m-%d %H:%M:%S")
        }

        logger.info(f"📝 업데이트 데이터: {update_data}")

        result = await collection.update_one(
            {"_id": post_oid},
            {"$set": update_data}
        )

        if result.modified_count == 0:
            logger.error(f"❌ 업데이트 실패: modified_count={result.modified_count}")
            raise HTTPException(status_code=500, detail="게시글 발행 실패")

        logger.info(f"✅ 게시글 발행 성공: {post_number}")

        # 캐시 무효화
        try:
            board_name = draft_post['board']
            logger.info(f"🔄 '{board_name}' 게시판 캐시 무효화 시작")

            if hasattr(list_posts, '_cache'):
                keys_to_delete = [
                    key for key in list_posts._cache.keys()
                    if key.startswith(f"board_list:{board_name}:")
                ]
                for key in keys_to_delete:
                    del list_posts._cache[key]

                all_keys_to_delete = [
                    key for key in list_posts._cache.keys()
                    if key.startswith("board_list:all:")
                ]
                for key in all_keys_to_delete:
                    del list_posts._cache[key]

            logger.info(f"✅ '{board_name}' 게시판 캐시 무효화 완료")
        except Exception as e:
            logger.warning(f"⚠️ 캐시 무효화 오류: {e}")

        return {
            "post_id": post_id,
            "status": "published",
            "post_number": post_number,
            "message": "게시글이 성공적으로 발행되었습니다."
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ 예상치 못한 오류: {type(e).__name__}: {str(e)}")
        logger.error(f"❌ 스택 트레이스: ", exc_info=True)
        raise HTTPException(status_code=500, detail=f"게시글 발행 중 오류가 발생했습니다: {str(e)}")

@router.delete("/{post_id}/draft")
async def delete_draft_post(
    post_id: str,
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    """Draft 게시글 삭제 (첨부파일도 함께 삭제)"""

    try:
        post_oid = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 게시글 ID입니다.")

    collection = db["board"]
    draft_post = await collection.find_one({"_id": post_oid, "status": "draft"})

    if not draft_post:
        raise HTTPException(status_code=404, detail="Draft 게시글을 찾을 수 없습니다.")

    if draft_post["writer_id"] != user.id:
        raise HTTPException(status_code=403, detail="본인이 작성한 게시글만 삭제할 수 있습니다.")

    total_deleted_attachments = 0

    try:
        # 1. 새로운 고급 파일 시스템의 첨부파일 삭제
        new_attachments_collection = db["attachments"]
        new_attachments = await new_attachments_collection.find({"post_id": post_id}).to_list(None)

        if new_attachments:
            from app.utils.advanced_file_manager import AdvancedFileManager
            file_manager = AdvancedFileManager(base_upload_dir="uploads")

            for attachment in new_attachments:
                try:
                    # 파일 시스템에서 삭제
                    file_path = attachment.get("file_path")
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)
                        logger.info(f"Draft 첨부파일 삭제: {file_path}")

                    # 데이터베이스에서 삭제
                    await new_attachments_collection.delete_one({"_id": attachment["_id"]})
                    total_deleted_attachments += 1

                except Exception as e:
                    logger.error(f"새 시스템 첨부파일 삭제 실패: {attachment.get('original_filename')}, 오류: {e}")

            # 빈 디렉터리 정리
            if new_attachments:
                try:
                    first_attachment = new_attachments[0]
                    dir_path = first_attachment.get("directory_path")
                    if dir_path:
                        file_manager.cleanup_empty_directories(dir_path)
                except Exception as e:
                    logger.warning(f"디렉터리 정리 실패: {e}")

            logger.info(f"새 시스템 첨부파일 {len(new_attachments)}개 삭제 완료")

        # 2. 기존 보안 첨부파일 시스템의 파일들도 삭제 (호환성)
        secure_attachments_collection = db["secure_attachments"]
        secure_attachments = await secure_attachments_collection.find({"post_id": post_id}).to_list(None)

        for attachment in secure_attachments:
            try:
                file_path = attachment.get("file_path")
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"기존 시스템 첨부파일 삭제: {file_path}")

                await secure_attachments_collection.delete_one({"_id": attachment["_id"]})
                total_deleted_attachments += 1

            except Exception as e:
                logger.error(f"기존 시스템 첨부파일 삭제 실패: {e}")

        logger.info(f"🗑️ Draft {post_id}의 총 첨부파일 {total_deleted_attachments}개 삭제 완료")

    except Exception as e:
        logger.error(f"❌ 첨부파일 삭제 오류: {e}")
        # 첨부파일 삭제 실패해도 게시글은 삭제 진행

    # Draft 게시글 삭제
    result = await collection.delete_one({"_id": post_oid})

    if result.deleted_count == 0:
        raise HTTPException(status_code=500, detail="Draft 게시글 삭제 실패")

    logger.info(f"Draft 게시글 삭제 완료 - ID: {post_id}, 작성자: {user.name}")

    return {
        "message": "Draft 게시글이 성공적으로 삭제되었습니다.",
        "deleted_attachments": total_deleted_attachments,
        "post_id": post_id
    }

@router.get("/drafts")
async def list_user_drafts(
    db=Depends(get_database),
    user=Depends(get_current_user)
):
    collection = db["board"]
    drafts = await collection.find({
        "writer_id": user.id,
        "status": "draft"
    }).sort("created_at", -1).to_list(None)

    for draft in drafts:
        draft["id"] = str(draft["_id"])
        del draft["_id"]

    return {
        "drafts": drafts,
        "count": len(drafts)
    }

@router.get("/")
async def list_posts(
    category: str = None,
    page: int = 1,
    limit: int = 20,
    db=Depends(get_database),
    user=Depends(get_current_user_optional)
):
    page = max(1, page)
    limit = min(50, max(10, limit))
    skip = (page - 1) * limit

    cache_key = f"board_list:{category or 'all'}:{page}:{limit}:{user.id if user else 'anonymous'}"

    try:
        import time
        current_time = time.time()

        if not hasattr(list_posts, '_cache'):
            list_posts._cache = {}

        cached_data = list_posts._cache.get(cache_key)
        if cached_data and (current_time - cached_data['timestamp']) < 10:
            return cached_data['data']
    except:
        pass

    collection = db["board"]

    filter_query = {}

    filter_query["$or"] = [
        {"status": {"$ne": "draft"}},
        {"status": {"$exists": False}}
    ]

    if category and category.strip():
        exact_category = category.strip()
        filter_query["board"] = exact_category
        print(f"🔍 정확한 게시판 필터링: '{exact_category}' (Draft 제외)")

        total_count = await collection.count_documents(filter_query)
        print(f"📊 '{exact_category}' 게시판 총 게시물 수: {total_count}")
    else:
        print("🔍 전체 게시판 조회")

    posts_cursor = collection.find(
        filter_query,
        {
            "_id": 1,
            "title": 1,
            "content": 1,
            "writer": 1,
            "writer_id": 1,
            "board": 1,
            "subcategory": 1,
            "post_number": 1,
            "date": 1,
            "is_private": 1,
            "prefix": 1,
            "views": 1,
            "likes": 1
        }
    ).sort("post_number", -1).skip(skip).limit(limit)

    posts = await posts_cursor.to_list(limit)

    total_count = await collection.count_documents(filter_query)

    post_ids = [str(post["_id"]) for post in posts]

    import asyncio
    comment_pipeline = [
        {"$match": {"post_id": {"$in": post_ids}}},
        {"$group": {"_id": "$post_id", "count": {"$sum": 1}}}
    ]
    attachment_pipeline = [
        {"$match": {"post_id": {"$in": post_ids}}},
        {"$group": {"_id": "$post_id", "count": {"$sum": 1}}}
    ]

    comment_counts_task = db["comments"].aggregate(comment_pipeline).to_list(None)
    attachment_counts_task = db["attachments"].aggregate(attachment_pipeline).to_list(None)

    comment_counts, attachment_counts = await asyncio.gather(
        comment_counts_task,
        attachment_counts_task
    )

    comment_count_map = {item["_id"]: item["count"] for item in comment_counts}
    attachment_count_map = {item["_id"]: item["count"] for item in attachment_counts}

    from app.utils.permissions import PermissionManager

    # 작성자들의 role 정보를 한번에 조회
    writer_ids = [post.get("writer_id") for post in posts if post.get("writer_id")]
    users_collection = db["users"]

    writer_roles = {}
    if writer_ids:
        try:
            writer_oids = [ObjectId(writer_id) for writer_id in writer_ids if writer_id]
            writers_info = await users_collection.find(
                {"_id": {"$in": writer_oids}},
                {"_id": 1, "role": 1, "is_admin": 1}
            ).to_list(None)

            for writer in writers_info:
                writer_id_str = str(writer["_id"])
                writer_roles[writer_id_str] = {
                    "role": writer.get("role", "student"),
                    "is_admin": writer.get("is_admin", False)
                }
        except Exception as e:
            print(f"작성자 role 조회 오류: {e}")

    filtered_posts = []
    for post in posts:
        if category and post.get("board") != category:
            print(f"⚠️ 게시판 불일치 발견: 요청({category}) vs 실제({post.get('board')}) - 게시물 제외")
            continue

        if post.get("is_private", False):
            can_see_private = PermissionManager.can_access_private_post(user, post) if user else False

            if can_see_private:
                post["id"] = str(post["_id"])
                # 비공개 게시글이지만 접근 권한이 있는 경우 작성자 role 정보 추가
                writer_id = post.get("writer_id")
                if writer_id and writer_id in writer_roles:
                    post["writer_role"] = writer_roles[writer_id]["role"]
                    post["writer_is_admin"] = writer_roles[writer_id]["is_admin"]
                else:
                    post["writer_role"] = "student"
                    post["writer_is_admin"] = False
            else:
                post["id"] = str(post["_id"])
                post["title"] = "🔒 비공개 게시글입니다"
                post["content"] = "비공개 게시글입니다."
                post["prefix"] = ""
                post["writer"] = "비공개"
                # 비공개 게시글의 경우 작성자 role 정보 숨김
                post["writer_role"] = "guest"
                post["writer_is_admin"] = False
        else:
            post["id"] = str(post["_id"])
            # 작성자 role 정보 추가
            writer_id = post.get("writer_id")
            if writer_id and writer_id in writer_roles:
                post["writer_role"] = writer_roles[writer_id]["role"]
                post["writer_is_admin"] = writer_roles[writer_id]["is_admin"]
            else:
                post["writer_role"] = "student"
                post["writer_is_admin"] = False

        post["commentCount"] = comment_count_map.get(post["id"], 0)
        attachment_count = attachment_count_map.get(post["id"], 0)
        post["attachmentCount"] = attachment_count
        post["hasAttachment"] = attachment_count > 0

        del post["_id"]
        filtered_posts.append(post)

    response_data = {
        "posts": filtered_posts,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total_count,
            "totalPages": (total_count + limit - 1) // limit,
            "hasNext": skip + limit < total_count,
            "hasPrev": page > 1
        }
    }

    try:
        import time
        if hasattr(list_posts, '_cache'):
            list_posts._cache[cache_key] = {
                'data': response_data,
                'timestamp': time.time()
            }
    except:
        pass

    return response_data

@router.get("/{post_id}")
async def get_post(post_id: str, db=Depends(get_database), user=Depends(get_current_user_optional)):
    collection = db["board"]
    try:
        oid = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 post_id입니다.")
    post = await collection.find_one({"_id": oid})
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")

    if post.get("status") == "draft":
        if not user:
            raise HTTPException(status_code=403, detail="임시저장 게시글입니다. 로그인이 필요합니다.")

        from app.utils.permissions import PermissionManager
        user_dict = {"id": user.id, "role": user.role.value if hasattr(user.role, 'value') else str(user.role), "is_admin": user.is_admin}
        is_author = (user_dict.get("id") == post.get("writer_id"))
        perms = PermissionManager.check_simple_permissions(user)

        if not (is_author or perms["has_manage_boards"] or perms["is_admin"]):
            raise HTTPException(status_code=403, detail="임시저장 게시글입니다. 작성자 또는 관리자만 접근할 수 있습니다.")

    from app.utils.permissions import PermissionManager

    if post.get("is_private", False):
        if not user:
            raise HTTPException(status_code=403, detail="비공개 게시글입니다. 로그인이 필요합니다.")

        if not PermissionManager.can_access_private_post(user, post):
            raise HTTPException(status_code=403, detail="비공개 게시글입니다. 작성자 또는 관리자만 볼 수 있습니다.")

    post["id"] = str(post["_id"])
    del post["_id"]

    # 작성자의 role 정보 추가
    writer_id = post.get("writer_id")
    if writer_id:
        users_collection = db["users"]
        try:
            writer_oid = ObjectId(writer_id)
            writer_info = await users_collection.find_one({"_id": writer_oid}, {"role": 1, "is_admin": 1})
            if writer_info:
                post["writer_role"] = writer_info.get("role", "student")
                post["writer_is_admin"] = writer_info.get("is_admin", False)
        except Exception as e:
            # writer_id 조회 실패 시 기본값 설정
            post["writer_role"] = "student"
            post["writer_is_admin"] = False
    else:
        # writer_id가 없는 경우 기본값
        post["writer_role"] = "student"
        post["writer_is_admin"] = False

    comment_count = await db["comments"].count_documents({"post_id": post_id})
    post["commentCount"] = comment_count

    attachment_count = await db["attachments"].count_documents({"post_id": post_id})
    post["attachmentCount"] = attachment_count
    post["hasAttachment"] = attachment_count > 0

    return post

@router.put("/{post_id}")
async def update_post(post_id: str, update_data: dict, db=Depends(get_database), user=Depends(get_current_user)):
    collection = db["board"]
    try:
        oid = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 post_id입니다.")
    post = await collection.find_one({"_id": oid})
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")

    user_dict = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
        "permissions": user.permissions,
        "is_admin": user.is_admin
    }

    from app.utils.permissions import PermissionManager

    if not PermissionManager.can_edit_post(user, post):
        raise HTTPException(status_code=403, detail="게시글을 수정할 권한이 없습니다.")

    allowed_fields = ["title", "content", "prefix", "tags", "is_private", "allow_comments"]
    filtered_update = {k: v for k, v in update_data.items() if k in allowed_fields}

    await collection.update_one({"_id": oid}, {"$set": filtered_update})
    return {"message": "게시글이 수정되었습니다."}

@router.delete("/{post_id}")
async def delete_post(post_id: str, db=Depends(get_database), user=Depends(get_current_user)):
    collection = db["board"]
    try:
        oid = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 post_id입니다.")
    post = await collection.find_one({"_id": oid})
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")

    user_dict = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
        "permissions": user.permissions,
        "is_admin": user.is_admin
    }

    from app.utils.permissions import PermissionManager

    if not PermissionManager.can_delete_post(user, post):
        raise HTTPException(status_code=403, detail="게시글을 삭제할 권한이 없습니다.")

    await collection.delete_one({"_id": oid})

    comments_collection = db["comments"]
    deleted_comments = await comments_collection.delete_many({"post_id": post_id})

    likes_collection = db["post_likes"]
    deleted_likes = await likes_collection.delete_many({"post_id": post_id})

    views_collection = db["post_views"]
    deleted_views = await views_collection.delete_many({"post_id": post_id})

    attachments_collection = db["attachments"]
    attachments = await attachments_collection.find({"post_id": post_id}).to_list(length=100)

    import os
    for attachment in attachments:
        file_path = attachment.get("file_path")
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"첨부파일 삭제 오류: {e}")

    deleted_attachments = await attachments_collection.delete_many({"post_id": post_id})

    # 캐시 무효화 - 게시글 삭제 후 관련 캐시 제거
    try:
        board_name = post.get('board', 'unknown')
        logger.info(f"🔄 게시글 삭제 후 '{board_name}' 게시판 캐시 무효화 시작")

        # list_posts 함수의 캐시 무효화 (함수에 _cache 속성이 있는 경우)
        if hasattr(list_posts, '_cache'):
            keys_to_delete = [
                key for key in list_posts._cache.keys()
                if key.startswith(f"board_list:{board_name}:") or key.startswith("board_list:all:")
            ]
            for key in keys_to_delete:
                del list_posts._cache[key]
                logger.info(f"🧹 서버 캐시 삭제: {key}")

        logger.info(f"✅ 게시글 삭제 후 '{board_name}' 게시판 캐시 무효화 완료")
    except Exception as e:
        logger.warning(f"⚠️ 서버 캐시 무효화 오류 (삭제는 성공): {e}")

    print(f"게시글 삭제 완료 - post_id: {post_id}, 댓글: {deleted_comments.deleted_count}개, 좋아요: {deleted_likes.deleted_count}개, 조회수기록: {deleted_views.deleted_count}개, 첨부파일: {deleted_attachments.deleted_count}개")

    return {
        "message": "게시글과 관련 데이터가 모두 삭제되었습니다.",
        "deleted_counts": {
            "comments": deleted_comments.deleted_count,
            "likes": deleted_likes.deleted_count,
            "views": deleted_views.deleted_count,
            "attachments": deleted_attachments.deleted_count
        }
    }

# ===== 조회수 및 좋아요 엔드포인트 =====

VIEW_COOLDOWN = timedelta(minutes=5)

@router.post("/{post_id}/view")
async def increment_view(post_id: str, request: Request, db=Depends(get_database)):
    try:
        oid = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 post_id입니다.")

    user_id = None
    if hasattr(request.state, "user") and request.state.user:
        user_id = getattr(request.state.user, 'id', None)
    identifier = user_id or request.client.host

    now = datetime.utcnow()
    view_collection = db["post_views"]
    view_record = await view_collection.find_one({"post_id": post_id, "identifier": identifier})

    if view_record:
        last_view = view_record.get("last_view")
        if now - last_view < VIEW_COOLDOWN:
            return {"success": False, "reason": "cooldown"}
        else:
            await view_collection.update_one({"_id": view_record["_id"]}, {"$set": {"last_view": now}})
    else:
        await view_collection.insert_one({"post_id": post_id, "identifier": identifier, "last_view": now})

    board_collection = db["board"]
    result = await board_collection.update_one({"_id": oid}, {"$inc": {"views": 1}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    return {"success": True}

@router.post("/{post_id}/like")
async def toggle_like(post_id: str, request: Request, db=Depends(get_database), user=Depends(get_current_user_optional)):
    try:
        oid = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 post_id입니다.")

    if not user:
        return {
            "success": False,
            "message": "좋아요 기능을 사용하려면 로그인이 필요합니다.",
            "require_login": True,
            "likeStatus": "login_required"
        }

    user_id = user.id
    if not user_id:
        return {
            "success": False,
            "message": "사용자 정보가 올바르지 않습니다.",
            "require_login": True,
            "likeStatus": "user_error"
        }

    now = datetime.utcnow()

    like_collection = db["post_likes"]
    like_record = await like_collection.find_one({"post_id": post_id, "identifier": user_id})

    board_collection = db["board"]
    if like_record:
        await like_collection.delete_one({"_id": like_record["_id"]})
        await board_collection.update_one({"_id": oid}, {"$inc": {"likes": -1}})
        return {
            "success": True,
            "likeStatus": "unliked",
            "message": "좋아요를 취소했습니다."
        }
    else:
        await like_collection.insert_one({
            "post_id": post_id,
            "identifier": user_id,
            "liked_at": now
        })
        await board_collection.update_one({"_id": oid}, {"$inc": {"likes": 1}})
        return {
            "success": True,
            "likeStatus": "liked",
            "message": "좋아요를 눌렀습니다."
        }

# ===== 댓글 관련 엔드포인트 (게시판에 통합) =====

@router.post("/{post_id}/comments/create")
async def create_comment(post_id: str, comment: dict, db=Depends(get_database), user=Depends(get_current_user)):
    user_dict = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
        "permissions": user.permissions,
        "is_admin": user.is_admin
    }

    from app.utils.permissions import PermissionManager
    from app.models.permission import PermissionType

    if not PermissionManager.has_permission(user, PermissionType.WRITE):
        raise HTTPException(
            status_code=403,
            detail="댓글 작성 권한이 없습니다."
        )

    try:
        oid = ObjectId(post_id)
        post = await db["board"].find_one({"_id": oid})
        if not post:
            raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 post_id입니다.")

    comment_permission = PermissionManager.can_comment_on_post(user, post)
    if not comment_permission["can_comment"]:
        raise HTTPException(
            status_code=403,
            detail=comment_permission["reason"]
        )

    if "parent_comment_id" in comment and comment["parent_comment_id"]:
        try:
            parent_oid = ObjectId(comment["parent_comment_id"])
            parent_comment = await db["comments"].find_one({"_id": parent_oid, "post_id": post_id})
            if not parent_comment:
                raise HTTPException(status_code=404, detail="부모 댓글을 찾을 수 없습니다.")
        except Exception:
            raise HTTPException(status_code=400, detail="유효하지 않은 parent_comment_id입니다.")

    if "content" not in comment or not comment["content"].strip():
        raise HTTPException(status_code=400, detail="댓글 내용(content)이 필요합니다.")

    comment["post_id"] = post_id
    comment["writer"] = user_dict["name"]
    comment["writer_id"] = user_dict["id"]
    comment["date"] = datetime.now(seoul_tz).isoformat()
    comment["parent_comment_id"] = comment.get("parent_comment_id", None)

    result = await db["comments"].insert_one(comment)
    new_comment = await db["comments"].find_one({"_id": result.inserted_id})
    new_comment["id"] = str(new_comment["_id"])
    del new_comment["_id"]
    return new_comment

@router.get("/{post_id}/comments")
async def get_comments(post_id: str, db=Depends(get_database), user=Depends(get_current_user_optional)):
    try:
        oid = ObjectId(post_id)
        post = await db["board"].find_one({"_id": oid})
        if not post:
            raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 post_id입니다.")

    if post.get("is_private", False):
        if not user:
            raise HTTPException(status_code=403, detail="비공개 게시글의 댓글은 로그인이 필요합니다.")

        from app.utils.permissions import PermissionManager

        if not PermissionManager.can_access_private_post(user, post):
            raise HTTPException(status_code=403, detail="비공개 게시글의 댓글은 작성자 또는 관리자만 볼 수 있습니다.")

    comments_cursor = db["comments"].find({"post_id": post_id}).sort("date", 1)
    comments = await comments_cursor.to_list(length=100)

    comment_dict = {}
    root_comments = []

    for comment in comments:
        comment["id"] = str(comment["_id"])
        del comment["_id"]
        comment["replies"] = []
        comment_dict[comment["id"]] = comment

        parent_comment_id = comment.get("parent_comment_id", None)
        if parent_comment_id:
            if parent_comment_id in comment_dict:
                comment_dict[parent_comment_id]["replies"].append(comment)
        else:
            root_comments.append(comment)

    return root_comments

# ===== 통합 게시판 조회 API =====

@router.get("/all/recent")
async def get_all_recent_posts(limit: int = 50, db=Depends(get_database)):
    collection = db["board"]

    posts_cursor = collection.find({}).sort("date", -1).limit(limit)
    posts = await posts_cursor.to_list(limit)

    for post in posts:
        post["id"] = str(post["_id"])
        del post["_id"]

        comment_count = await db["comments"].count_documents({"post_id": post["id"]})
        post["commentCount"] = comment_count

        recent_reply_count = await db["comments"].count_documents({
            "post_id": post["id"],
            "parent_comment_id": {"$exists": True, "$ne": None},
            "date": {"$gte": (datetime.now(seoul_tz) - timedelta(days=3)).isoformat()}
        })
        post["hasRecentReplies"] = recent_reply_count > 0
        post["recentReplyCount"] = recent_reply_count

    return posts

@router.get("/all/by-category")
async def get_posts_by_category(db=Depends(get_database)):
    """새로운 게시판 구조에 맞게 카테고리별 게시글 조회"""
    collection = db["board"]

    # 새로운 게시판 구조
    # 랩실운영: 행정_제출서류, 회의_세미나자료, 비품_정산관리
    # 연구자산: 연구_참고자료, 논문_아카이브, 실험_데이터, 코드_저장소
    boards = [
        # 랩실운영
        "행정_제출서류",
        "회의_세미나자료",
        "비품_정산관리",
        # 연구자산
        "연구_참고자료",
        "논문_아카이브",
        "실험_데이터",
        "코드_저장소",
        # 기본 게시판
        "공지사항",
        "뉴스"
    ]

    result = {}

    for board_name in boards:
        query = {"board": board_name}

        posts_cursor = collection.find(query).sort("date", -1).limit(10)
        posts = await posts_cursor.to_list(10)

        for post in posts:
            post["id"] = str(post["_id"])
            del post["_id"]

            comment_count = await db["comments"].count_documents({"post_id": post["id"]})
            post["commentCount"] = comment_count

            recent_reply_count = await db["comments"].count_documents({
                "post_id": post["id"],
                "parent_comment_id": {"$exists": True, "$ne": None},
                "date": {"$gte": (datetime.now(seoul_tz) - timedelta(days=3)).isoformat()}
            })
            post["hasRecentReplies"] = recent_reply_count > 0

        result[board_name] = posts

    return result

# ===== 댓글 삭제 엔드포인트 =====

@router.delete("/{post_id}/comments/{comment_id}")
async def delete_comment(post_id: str, comment_id: str, db=Depends(get_database), user=Depends(get_current_user)):
    try:
        comment_oid = ObjectId(comment_id)
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 comment_id입니다.")

    comment = await db["comments"].find_one({"_id": comment_oid, "post_id": post_id})
    if not comment:
        raise HTTPException(status_code=404, detail="댓글을 찾을 수 없습니다.")

    from app.utils.permissions import PermissionManager

    is_author = (comment.get("writer_id") == user.id)
    perms = PermissionManager.check_simple_permissions(user)

    can_delete_comment = (is_author or perms["has_manage_boards"] or perms["is_admin"])

    if not can_delete_comment:
        raise HTTPException(status_code=403, detail="댓글을 삭제할 권한이 없습니다.")

    await db["comments"].delete_one({"_id": comment_oid})
    return {"message": "댓글이 삭제되었습니다."}

@router.put("/{post_id}/comments/{comment_id}")
async def update_comment(post_id: str, comment_id: str, comment_data: dict, db=Depends(get_database), user=Depends(get_current_user)):
    try:
        comment_oid = ObjectId(comment_id)
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 comment_id입니다.")

    # 기존 댓글 찾기
    comment = await db["comments"].find_one({"_id": comment_oid, "post_id": post_id})
    if not comment:
        raise HTTPException(status_code=404, detail="댓글을 찾을 수 없습니다.")

    from app.utils.permissions import PermissionManager

    # 댓글 작성자만 수정 가능
    is_author = (comment.get("writer_id") == user.id)
    if not is_author:
        raise HTTPException(status_code=403, detail="댓글을 수정할 권한이 없습니다. 작성자만 수정할 수 있습니다.")

    # 수정할 내용 검증
    if "content" not in comment_data or not comment_data["content"].strip():
        raise HTTPException(status_code=400, detail="댓글 내용은 필수입니다.")

    # 댓글 업데이트
    update_data = {
        "content": comment_data["content"].strip(),
        "modified_at": datetime.now(seoul_tz).isoformat(),
        "is_modified": True
    }

    # 이미지가 있는 경우 업데이트
    if "image" in comment_data:
        update_data["image"] = comment_data["image"]

    await db["comments"].update_one(
        {"_id": comment_oid},
        {"$set": update_data}
    )

    # 업데이트된 댓글 반환
    updated_comment = await db["comments"].find_one({"_id": comment_oid})
    updated_comment["id"] = str(updated_comment["_id"])
    del updated_comment["_id"]

    return updated_comment
