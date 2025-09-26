# app/models/attachment.py
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class Attachment(BaseModel):
    id: Optional[str] = None
    post_id: str
    filename: str
    original_filename: str
    file_size: int
    file_type: str
    mime_type: str
    upload_date: datetime
    uploader_id: str
    file_path: str

class AttachmentCreate(BaseModel):
    filename: str
    original_filename: str
    file_size: int
    file_type: str
    mime_type: str

class AttachmentResponse(BaseModel):
    id: str
    filename: str
    original_filename: str
    file_size: int
    file_type: str
    mime_type: str
    upload_date: str
    uploader_id: str
