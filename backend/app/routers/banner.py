from fastapi import APIRouter, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import os
import uuid
import shutil
from PIL import Image
from app.core.database import get_db
from app.models.banner import Banner
from app.schemas.banner import Banner as BannerSchema, BannerCreate, BannerUpdate
from app.utils.auth_middleware import get_current_user, require_permission
from app.models.permission import PermissionType

router = APIRouter(prefix="/api/banner", tags=["banner"])

# 이미지 업로드 디렉토리
BANNER_UPLOAD_DIR = "uploads/banners"
os.makedirs(BANNER_UPLOAD_DIR, exist_ok=True)

# 허용되는 이미지 확장자
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

def save_banner_image(file: UploadFile) -> str:
    """배너 이미지 파일을 저장하고 파일 경로를 반환합니다."""
    # 파일 확장자 검증
    file_extension = os.path.splitext(file.filename)[1].lower()
    if file_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"지원하지 않는 파일 형식입니다. 허용되는 형식: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # 고유한 파일명 생성
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = os.path.join(BANNER_UPLOAD_DIR, unique_filename)

    # 파일 저장
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 이미지 최적화 (선택사항)
    try:
        with Image.open(file_path) as img:
            # 이미지 크기가 너무 크면 리사이즈
            if img.width > 1920 or img.height > 1080:
                img.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
                img.save(file_path, optimize=True, quality=85)
    except Exception:
        pass  # 이미지 최적화 실패시 원본 파일 유지

    return file_path

@router.get("/", response_model=List[BannerSchema])
def get_banners(
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """배너 목록을 조회합니다."""
    query = db.query(Banner)
    if active_only:
        query = query.filter(Banner.is_active == True)

    banners = query.order_by(Banner.display_order.asc(), Banner.created_at.desc()).all()
    return banners

@router.get("/{banner_id}", response_model=BannerSchema)
def get_banner(banner_id: int, db: Session = Depends(get_db)):
    """특정 배너를 조회합니다."""
    banner = db.query(Banner).filter(Banner.id == banner_id).first()
    if not banner:
        raise HTTPException(status_code=404, detail="배너를 찾을 수 없습니다.")
    return banner

@router.post("/", response_model=BannerSchema)
@require_permission(PermissionType.MANAGE_BANNERS)
def create_banner(
    title: str = Form(...),
    description: str = Form(...),
    image_url: Optional[str] = Form(None),
    link_url: Optional[str] = Form(None),
    background_color: str = Form("#f8f9fa"),
    text_color: str = Form("#333333"),
    button_color: str = Form("#007bff"),
    button_text: str = Form("자세히 보기"),
    is_active: bool = Form(True),
    display_order: int = Form(0),
    image_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """새 배너를 생성합니다."""

    # 이미지 파일 업로드 처리
    image_file_path = None
    if image_file and image_file.filename:
        image_file_path = save_banner_image(image_file)

    banner_data = {
        "title": title,
        "description": description,
        "image_url": image_url,
        "image_file_path": image_file_path,
        "link_url": link_url,
        "background_color": background_color,
        "text_color": text_color,
        "button_color": button_color,
        "button_text": button_text,
        "is_active": is_active,
        "display_order": display_order
    }

    db_banner = Banner(**banner_data)
    db.add(db_banner)
    db.commit()
    db.refresh(db_banner)

    return db_banner

@router.put("/{banner_id}", response_model=BannerSchema)
@require_permission(PermissionType.MANAGE_BANNERS)
def update_banner(
    banner_id: int,
    title: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    image_url: Optional[str] = Form(None),
    link_url: Optional[str] = Form(None),
    background_color: Optional[str] = Form(None),
    text_color: Optional[str] = Form(None),
    button_color: Optional[str] = Form(None),
    button_text: Optional[str] = Form(None),
    is_active: Optional[bool] = Form(None),
    display_order: Optional[int] = Form(None),
    image_file: Optional[UploadFile] = File(None),
    remove_image: bool = Form(False),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """배너를 수정합니다."""

    banner = db.query(Banner).filter(Banner.id == banner_id).first()
    if not banner:
        raise HTTPException(status_code=404, detail="배너를 찾을 수 없습니다.")

    # 기존 이미지 파일 삭제 처리
    if remove_image and banner.image_file_path:
        try:
            if os.path.exists(banner.image_file_path):
                os.remove(banner.image_file_path)
        except Exception:
            pass
        banner.image_file_path = None

    # 새 이미지 파일 업로드 처리
    if image_file and image_file.filename:
        # 기존 파일 삭제
        if banner.image_file_path:
            try:
                if os.path.exists(banner.image_file_path):
                    os.remove(banner.image_file_path)
            except Exception:
                pass

        banner.image_file_path = save_banner_image(image_file)

    # 필드 업데이트
    update_data = {}
    if title is not None:
        update_data["title"] = title
    if description is not None:
        update_data["description"] = description
    if image_url is not None:
        update_data["image_url"] = image_url
    if link_url is not None:
        update_data["link_url"] = link_url
    if background_color is not None:
        update_data["background_color"] = background_color
    if text_color is not None:
        update_data["text_color"] = text_color
    if button_color is not None:
        update_data["button_color"] = button_color
    if button_text is not None:
        update_data["button_text"] = button_text
    if is_active is not None:
        update_data["is_active"] = is_active
    if display_order is not None:
        update_data["display_order"] = display_order

    for key, value in update_data.items():
        setattr(banner, key, value)

    db.commit()
    db.refresh(banner)

    return banner

@router.delete("/{banner_id}")
@require_permission(PermissionType.MANAGE_BANNERS)
def delete_banner(
    banner_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """배너를 삭제합니다."""

    banner = db.query(Banner).filter(Banner.id == banner_id).first()
    if not banner:
        raise HTTPException(status_code=404, detail="배너를 찾을 수 없습니다.")

    # 이미지 파일 삭제
    if banner.image_file_path:
        try:
            if os.path.exists(banner.image_file_path):
                os.remove(banner.image_file_path)
        except Exception:
            pass

    db.delete(banner)
    db.commit()

    return {"message": "배너가 삭제되었습니다."}

@router.get("/image/{filename}")
def get_banner_image(filename: str):
    """배너 이미지를 제공합니다."""
    file_path = os.path.join(BANNER_UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="이미지를 찾을 수 없습니다.")

    return FileResponse(file_path)

@router.post("/reorder")
@require_permission(PermissionType.MANAGE_BANNERS)
def reorder_banners(
    banner_orders: List[dict],  # [{"id": 1, "display_order": 0}, ...]
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """배너 순서를 변경합니다."""

    for order_data in banner_orders:
        banner_id = order_data.get("id")
        display_order = order_data.get("display_order")

        banner = db.query(Banner).filter(Banner.id == banner_id).first()
        if banner:
            banner.display_order = display_order

    db.commit()

    return {"message": "배너 순서가 변경되었습니다."}
