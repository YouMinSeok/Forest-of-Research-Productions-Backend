# app/routers/google_oauth.py
import os
import json
import requests
from fastapi import APIRouter, HTTPException
from google_auth_oauthlib.flow import Flow
from app.services.token_repo import save_refresh_token

SCOPE = ["https://www.googleapis.com/auth/drive.file"]

def client_config():
    return {
        "web": {
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "project_id": "research-board",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "redirect_uris": [os.environ["GOOGLE_REDIRECT_URI"]],
            "javascript_origins": ["http://localhost"]
        }
    }

router = APIRouter(prefix="/api/google", tags=["google"])

@router.get("/start")
def start():
    """Google OAuth 인증 시작"""
    flow = Flow.from_client_config(
        client_config(),
        scopes=SCOPE,
        redirect_uri=os.environ["GOOGLE_REDIRECT_URI"],
    )
    auth_url, _ = flow.authorization_url(
        access_type="offline", prompt="consent", include_granted_scopes="true"
    )
    return {"auth_url": auth_url}

@router.get("/callback")
async def callback(code: str):
    """Google OAuth 콜백 처리"""
    # code → token 교환
    data = {
        "code": code,
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
        "redirect_uri": os.environ["GOOGLE_REDIRECT_URI"],
        "grant_type": "authorization_code",
    }
    r = requests.post("https://oauth2.googleapis.com/token", data=data, timeout=15)
    if r.status_code != 200:
        raise HTTPException(400, f"token exchange failed: {r.text}")
    payload = r.json()
    if "refresh_token" not in payload:
        raise HTTPException(400, "no refresh_token returned (prompt=consent, access_type=offline 확인)")

    await save_refresh_token(payload["refresh_token"])
    return {"ok": True, "message": "refresh_token 저장 완료"}
