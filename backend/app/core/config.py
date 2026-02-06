# app/core/config.py
import os
from dotenv import load_dotenv

load_dotenv()  # .env 파일의 환경변수를 로드합니다.


def _env_bool(key: str, default: str = "False") -> bool:
    """
    환경변수 bool 파서
    True 인식: true, 1, yes, y, on
    """
    v = os.getenv(key, default)
    return str(v).strip().lower() in ["true", "1", "yes", "y", "on"]


def _first_env(*keys: str, default: str | None = None) -> str | None:
    """
    여러 키를 순서대로 조회해서, 첫 번째로 값이 있는 것을 반환.
    """
    for k in keys:
        v = os.getenv(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return default


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

    # =========================================================
    # 이메일 제공자 선택 ("gmail" 또는 "naver")
    # =========================================================
    EMAIL_PROVIDER = (os.getenv("EMAIL_PROVIDER", "gmail") or "gmail").lower().strip()

    # =========================================================
    # SMTP 설정: "MAIL_* 우선" + "NAVER_/GMAIL_ 폴백"
    # - 네이버는 기본: 587 + STARTTLS(True) + SSL(False)
    # - 지메일은 기본: 587 + STARTTLS(True) + SSL(False)
    # =========================================================
    if EMAIL_PROVIDER == "naver":
        MAIL_USERNAME = _first_env("MAIL_USERNAME", "NAVER_MAIL_USERNAME", default="your-naver-email@naver.com")
        MAIL_PASSWORD = _first_env("MAIL_PASSWORD", "NAVER_MAIL_PASSWORD", default="your-naver-password")
        MAIL_FROM = _first_env("MAIL_FROM", "NAVER_MAIL_FROM", default=MAIL_USERNAME)

        # ✅ 중요: 네이버 기본 포트는 587을 권장 (STARTTLS)
        # (465를 기본으로 두면, 호스팅 env가 꼬일 때 465로 떨어져 EOF/SSL 오류가 납니다)
        MAIL_PORT = int(_first_env("MAIL_PORT", "NAVER_MAIL_PORT", default="587") or "587")
        MAIL_SERVER = _first_env("MAIL_SERVER", "NAVER_MAIL_SERVER", default="smtp.naver.com")

        # ✅ 587이면 STARTTLS=True / SSL=False가 정석
        # 환경변수로 덮어쓰고 싶으면 MAIL_TLS/MAIL_SSL 또는 NAVER_MAIL_TLS/NAVER_MAIL_SSL 넣으면 됨
        _tls_default = "True"
        _ssl_default = "False"
        MAIL_TLS = _env_bool("MAIL_TLS", _tls_default) if os.getenv("MAIL_TLS") is not None else _env_bool("NAVER_MAIL_TLS", _tls_default)
        MAIL_SSL = _env_bool("MAIL_SSL", _ssl_default) if os.getenv("MAIL_SSL") is not None else _env_bool("NAVER_MAIL_SSL", _ssl_default)

    else:
        # gmail (기본)
        MAIL_USERNAME = _first_env("MAIL_USERNAME", "GMAIL_MAIL_USERNAME", default="your-email@gmail.com")
        MAIL_PASSWORD = _first_env("MAIL_PASSWORD", "GMAIL_MAIL_PASSWORD", default="your-gmail-app-password")
        MAIL_FROM = _first_env("MAIL_FROM", "GMAIL_MAIL_FROM", default=MAIL_USERNAME)

        MAIL_PORT = int(_first_env("MAIL_PORT", "GMAIL_MAIL_PORT", default="587") or "587")
        MAIL_SERVER = _first_env("MAIL_SERVER", "GMAIL_MAIL_SERVER", default="smtp.gmail.com")

        _tls_default = "True"
        _ssl_default = "False"
        MAIL_TLS = _env_bool("MAIL_TLS", _tls_default) if os.getenv("MAIL_TLS") is not None else _env_bool("GMAIL_MAIL_TLS", _tls_default)
        MAIL_SSL = _env_bool("MAIL_SSL", _ssl_default) if os.getenv("MAIL_SSL") is not None else _env_bool("GMAIL_MAIL_SSL", _ssl_default)

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
