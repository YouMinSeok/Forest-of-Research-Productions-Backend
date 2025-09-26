from pydantic import BaseModel, HttpUrl
from typing import Optional
from datetime import datetime

class BannerBase(BaseModel):
    title: str
    description: str
    image_url: Optional[str] = None
    link_url: Optional[str] = None
    background_color: str = "#f8f9fa"
    text_color: str = "#333333"
    button_color: str = "#007bff"
    button_text: str = "자세히 보기"
    is_active: bool = True
    display_order: int = 0

class BannerCreate(BannerBase):
    pass

class BannerUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    link_url: Optional[str] = None
    background_color: Optional[str] = None
    text_color: Optional[str] = None
    button_color: Optional[str] = None
    button_text: Optional[str] = None
    is_active: Optional[bool] = None
    display_order: Optional[int] = None

class Banner(BannerBase):
    id: int
    image_file_path: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
