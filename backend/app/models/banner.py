from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.sql import func
from app.core.database import Base

class Banner(Base):
    __tablename__ = "banners"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    image_url = Column(String(500), nullable=True)  # 이미지 URL
    image_file_path = Column(String(500), nullable=True)  # 업로드된 파일 경로
    link_url = Column(String(500), nullable=True)  # 클릭 시 이동할 링크
    background_color = Column(String(20), default="#f8f9fa")  # 배경색
    text_color = Column(String(20), default="#333333")  # 텍스트 색상
    button_color = Column(String(20), default="#007bff")  # 버튼 색상
    button_text = Column(String(50), default="자세히 보기")  # 버튼 텍스트
    is_active = Column(Boolean, default=True)  # 활성화 여부
    display_order = Column(Integer, default=0)  # 표시 순서
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
