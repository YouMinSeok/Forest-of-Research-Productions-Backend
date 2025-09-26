from fastapi import APIRouter, Depends
from app.core.database import get_database

router = APIRouter()

@router.get("/test-db")
async def test_database_connection(db=Depends(get_database)):
    try:
        # 예시: "research" 컬렉션에서 최대 5개 문서 조회
        data = await db["research"].find().to_list(5)
        return {"message": "MongoDB 연결 성공!", "data": data}
    except Exception as e:
        return {"error": str(e)}
