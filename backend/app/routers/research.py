from fastapi import APIRouter
from app.schemas import research as research_schema

router = APIRouter()

@router.post("/create")
async def create_research(research: research_schema.ResearchCreate):
    # 실제 구현에서는 DB에 연구 프로젝트 생성 로직 추가
    return {"message": "Research project created", "research": research}
