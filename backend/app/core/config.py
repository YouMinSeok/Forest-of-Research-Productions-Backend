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

    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")

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
        cors_origins_str = os.getenv("CORS_ORIGINS", "http://localhost:3000")
        origins = [origin.strip() for origin in cors_origins_str.split(",")]

        # HOST_IP 기반 URL들을 동적으로 추가
        if self.HOST_IP:
            host_based_origins = [
                f"http://{self.HOST_IP}:3000",
                f"http://{self.HOST_IP}:3001",
                f"http://{self.HOST_IP}:5000",
                f"http://{self.HOST_IP}:8080"
            ]
            origins.extend(host_based_origins)

        # 중복 제거 및 빈 값 제거
        unique_origins = list(set([origin for origin in origins if origin.strip()]))
        return unique_origins

settings = Settings()
