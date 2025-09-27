# app/core/config.py
import os
from dotenv import load_dotenv

load_dotenv()  # .env 파일의 환경변수를 로드합니다.

class Settings:
    API_TITLE = os.getenv("API_TITLE", "My Research Platform API")
    API_VERSION = os.getenv("API_VERSION", "0.1.0")
    DEBUG = os.getenv("DEBUG", "True").lower() in ["true", "1", "yes"]

    # MongoDB 설정
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "research_forest")

    # JWT/암호화
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")

    # ⏱ 토큰 만료 설정 (추가)
    # 기본값: AT 120분(2시간), RT 30일
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))

    # AI 마이크로서비스 통신 설정
    AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-service:8001")

    # 이메일 제공자 선택 ("gmail" 또는 "naver")
    EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "gmail").lower()

    # SMTP 설정: 제공자에 따라 선택
    if EMAIL_PROVIDER == "naver":
        MAIL_USERNAME = os.getenv("NAVER_MAIL_USERNAME", "your-naver-email@naver.com")
        MAIL_PASSWORD = os.getenv("NAVER_MAIL_PASSWORD", "your-naver-password")
        MAIL_FROM = os.getenv("NAVER_MAIL_FROM", "your-naver-email@naver.com")
        MAIL_PORT = int(os.getenv("NAVER_MAIL_PORT", "465"))
        MAIL_SERVER = os.getenv("NAVER_MAIL_SERVER", "smtp.naver.com")
        MAIL_TLS = os.getenv("NAVER_MAIL_TLS", "False").lower() in ["true", "1", "yes"]
        MAIL_SSL = os.getenv("NAVER_MAIL_SSL", "True").lower() in ["true", "1", "yes"]
    else:
        MAIL_USERNAME = os.getenv("GMAIL_MAIL_USERNAME", "your-email@gmail.com")
        MAIL_PASSWORD = os.getenv("GMAIL_MAIL_PASSWORD", "your-gmail-app-password")
        MAIL_FROM = os.getenv("GMAIL_MAIL_FROM", "your-email@gmail.com")
        MAIL_PORT = int(os.getenv("GMAIL_MAIL_PORT", "587"))
        MAIL_SERVER = os.getenv("GMAIL_MAIL_SERVER", "smtp.gmail.com")
        MAIL_TLS = os.getenv("GMAIL_MAIL_TLS", "True").lower() in ["true", "1", "yes"]
        MAIL_SSL = os.getenv("GMAIL_MAIL_SSL", "False").lower() in ["true", "1", "yes"]

    # (과거 쿠키 기반 사용 여부 플래그였던 값 – 지금은 헤더 기반이라 실제로 사용 안 해도 무방)
    USE_CREDENTIALS = True

    # Google Drive API 설정
    GDRIVE_FOLDER_ID = os.getenv("GDRIVE_FOLDER_ID")
    GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

    # 서버 설정
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "8080"))
    HOST_IP = os.getenv("HOST_IP")

    # HOST_IP 환경변수가 설정되지 않은 경우 에러 발생
    if not HOST_IP:
        raise ValueError("HOST_IP 환경변수가 설정되지 않았습니다. .env 파일에서 HOST_IP를 설정해주세요.")

    # CORS 설정
    @property
    def CORS_ORIGINS(self):
        """
        우선순위:
        - .env의 CORS_ORIGINS (콤마로 구분)
        - 로컬 개발 기본 오리진 자동 추가
        - HOST_IP 기반 오리진 자동 추가
        - NETLIFY_SITE(= {서브도메인}) 지정 시 Netlify 도메인 자동 추가
        """
        base = os.getenv("CORS_ORIGINS", "")
        origins = [o.strip() for o in base.split(",") if o.strip()]

        # 로컬 기본 오리진들
        local_defaults = [
            "http://localhost",
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ]
        origins.extend(local_defaults)

        # 필요시 HTTPS 로컬도 허용 (프록시/로컬 인증서 환경)
        local_https = [
            "https://localhost",
            "https://localhost:3000",
            "https://127.0.0.1",
            "https://127.0.0.1:3000",
        ]
        origins.extend(local_https)

        # HOST_IP 기반 오리진들
        if self.HOST_IP:
            host_based = [
                f"http://{self.HOST_IP}",
                f"http://{self.HOST_IP}:3000",
                f"http://{self.HOST_IP}:3001",
                f"http://{self.HOST_IP}:5000",
                f"http://{self.HOST_IP}:8080",
            ]
            origins.extend(host_based)

        # Netlify 사이트 자동 추가
        # 예) NETLIFY_SITE=my-research-app -> https://my-research-app.netlify.app
        netlify_site = os.getenv("NETLIFY_SITE", "").strip()
        if netlify_site:
            origins.append(f"https://{netlify_site}.netlify.app")
            # 프리뷰 배포 도메인 프리픽스가 있는 경우 (예: preview--{site}.netlify.app)
            preview_prefix = os.getenv("NETLIFY_PREVIEW_PREFIX", "").strip()  # 예: "preview--"
            if preview_prefix:
                origins.append(f"https://{preview_prefix}{netlify_site}.netlify.app")

        # 중복 제거
        unique = sorted({o for o in origins if o})
        return unique


settings = Settings()
