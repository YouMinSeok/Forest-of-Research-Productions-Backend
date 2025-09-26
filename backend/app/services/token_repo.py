# app/services/token_repo.py
from datetime import datetime
from pymongo import MongoClient
import os
from .secure_store import encrypt, decrypt

client = MongoClient(os.getenv("MONGO_URI"))
db = client[os.getenv("DATABASE_NAME", "research_forest")]
col = db["oauth_tokens"]

async def save_refresh_token(rt: str):
    """Refresh token을 암호화하여 저장합니다."""
    col.update_one(
        {"_id": "google-drive"},
        {"$set": {"refresh_token": encrypt(rt), "updated_at": datetime.utcnow()},
         "$setOnInsert": {"created_at": datetime.utcnow()}},
        upsert=True
    )

async def load_refresh_token() -> str | None:
    """저장된 refresh token을 복호화하여 반환합니다."""
    doc = col.find_one({"_id": "google-drive"})
    return decrypt(doc["refresh_token"]) if doc and "refresh_token" in doc else None
