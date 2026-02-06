import os
import random
import string
import logging
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from app.core.config import settings

logger = logging.getLogger("email")
logger.setLevel(logging.INFO)


def generate_verification_code(length: int = 6) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def _mask_secret(value: str | None) -> str:
    if not value:
        return "None"
    if len(value) <= 2:
        return value[0] + "*"
    return value[:2] + "*" * (len(value) - 2)


def log_mail_env_and_settings():
    """
    호스팅에서 'UI는 587인데 앱은 465로 붙는다' 같은 문제를 잡기 위한 로그.
    - env에서 뭐가 들어왔는지
    - settings가 뭐로 파싱했는지
    를 둘 다 찍습니다.
    """
    try:
        logger.info("=== MAIL DEBUG (ENV) ===")
        logger.info("ENV EMAIL_PROVIDER=%s", os.getenv("EMAIL_PROVIDER"))
        logger.info("ENV MAIL_SERVER=%s", os.getenv("MAIL_SERVER"))
        logger.info("ENV MAIL_PORT=%s", os.getenv("MAIL_PORT"))
        logger.info("ENV MAIL_TLS=%s", os.getenv("MAIL_TLS"))
        logger.info("ENV MAIL_SSL=%s", os.getenv("MAIL_SSL"))
        logger.info("ENV MAIL_USERNAME=%s", os.getenv("MAIL_USERNAME"))
        logger.info("ENV MAIL_PASSWORD(masked)=%s", _mask_secret(os.getenv("MAIL_PASSWORD")))
        logger.info("ENV NAVER_MAIL_USERNAME=%s", os.getenv("NAVER_MAIL_USERNAME"))
        logger.info("ENV NAVER_MAIL_PASSWORD(masked)=%s", _mask_secret(os.getenv("NAVER_MAIL_PASSWORD")))
        logger.info("========================")

        logger.info("=== MAIL DEBUG (SETTINGS) ===")
        logger.info("settings.EMAIL_PROVIDER=%s", getattr(settings, "EMAIL_PROVIDER", None))
        logger.info("settings.MAIL_SERVER=%s", getattr(settings, "MAIL_SERVER", None))
        logger.info("settings.MAIL_PORT=%s", getattr(settings, "MAIL_PORT", None))
        logger.info("settings.MAIL_TLS=%s", getattr(settings, "MAIL_TLS", None))
        logger.info("settings.MAIL_SSL=%s", getattr(settings, "MAIL_SSL", None))
        logger.info("settings.MAIL_USERNAME=%s", getattr(settings, "MAIL_USERNAME", None))
        logger.info("settings.MAIL_PASSWORD(masked)=%s", _mask_secret(getattr(settings, "MAIL_PASSWORD", None)))
        logger.info("==============================")
    except Exception as e:
        logger.warning("MAIL DEBUG LOG FAILED: %s", e)


def build_mail_config() -> ConnectionConfig:
    """
    SMTP 설정
    - Naver: smtp.naver.com / 587 / STARTTLS(=MAIL_STARTTLS=True, MAIL_SSL_TLS=False)
    - Gmail: smtp.gmail.com / 587 / STARTTLS
    """
    provider = (getattr(settings, "EMAIL_PROVIDER", "") or "").lower().strip()

    # settings에서 읽되, 없으면 NAVER_*도 폴백 (호스팅에서 키를 섞어 넣는 경우 방어)
    username = getattr(settings, "MAIL_USERNAME", None) or os.getenv("MAIL_USERNAME") or os.getenv("NAVER_MAIL_USERNAME")
    password = getattr(settings, "MAIL_PASSWORD", None) or os.getenv("MAIL_PASSWORD") or os.getenv("NAVER_MAIL_PASSWORD")
    mail_from = getattr(settings, "MAIL_FROM", None) or os.getenv("MAIL_FROM") or os.getenv("NAVER_MAIL_FROM")

    # 서버/포트 폴백
    if provider == "naver":
        server = getattr(settings, "MAIL_SERVER", None) or os.getenv("MAIL_SERVER") or os.getenv("NAVER_MAIL_SERVER") or "smtp.naver.com"
        port_raw = getattr(settings, "MAIL_PORT", None) or os.getenv("MAIL_PORT") or os.getenv("NAVER_MAIL_PORT") or "587"
        port = int(str(port_raw).strip())

        # ✅ 네이버 587은 STARTTLS
        starttls = True
        ssl_tls = False
    else:
        server = getattr(settings, "MAIL_SERVER", None) or os.getenv("MAIL_SERVER") or "smtp.gmail.com"
        port_raw = getattr(settings, "MAIL_PORT", None) or os.getenv("MAIL_PORT") or "587"
        port = int(str(port_raw).strip())

        # ✅ 지메일도 587 STARTTLS
        starttls = True
        ssl_tls = False

    use_credentials = getattr(settings, "USE_CREDENTIALS", True)

    # 최종 적용값 로그(여기서 465가 찍히면 settings/ENV가 그렇게 들어온 겁니다)
    logger.info("=== MAIL DEBUG (FINAL CONFIG) ===")
    logger.info("provider=%s", provider)
    logger.info("server=%s", server)
    logger.info("port=%s", port)
    logger.info("MAIL_STARTTLS=%s", starttls)
    logger.info("MAIL_SSL_TLS=%s", ssl_tls)
    logger.info("username=%s", username)
    logger.info("password(masked)=%s", _mask_secret(password))
    logger.info("from=%s", mail_from)
    logger.info("===============================")

    return ConnectionConfig(
        MAIL_USERNAME=username,
        MAIL_PASSWORD=password,
        MAIL_FROM=mail_from,
        MAIL_PORT=port,
        MAIL_SERVER=server,
        MAIL_STARTTLS=starttls,
        MAIL_SSL_TLS=ssl_tls,
        USE_CREDENTIALS=use_credentials,
        TEMPLATE_FOLDER="",
    )


async def send_verification_email(email: str, code: str):
    # ✅ 가장 먼저: 지금 런타임에서 실제로 뭐가 읽히는지 찍기
    log_mail_env_and_settings()

    # ✅ 요청 시점에 config 생성(호스팅 env 변경/재배포 반영 확인용)
    conf = build_mail_config()

    html_body = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>연구의숲 인증 코드</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f5f7fa;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background-color: #ffffff;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                border-radius: 12px;
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                text-align: center;
                padding: 40px 20px;
            }}
            .header h1 {{
                font-size: 28px;
                margin-bottom: 10px;
                font-weight: 700;
            }}
            .header p {{
                font-size: 16px;
                opacity: 0.9;
            }}
            .content {{
                padding: 40px 30px;
                text-align: center;
            }}
            .welcome-text {{
                font-size: 18px;
                color: #555;
                margin-bottom: 30px;
            }}
            .code-container {{
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                border-radius: 12px;
                padding: 25px;
                margin: 30px 0;
                box-shadow: 0 8px 25px rgba(240, 147, 251, 0.3);
            }}
            .code-label {{
                color: white;
                font-size: 16px;
                margin-bottom: 10px;
                font-weight: 600;
            }}
            .verification-code {{
                background: rgba(255, 255, 255, 0.95);
                color: #333;
                font-size: 32px;
                font-weight: 700;
                letter-spacing: 4px;
                padding: 15px 30px;
                border-radius: 8px;
                display: inline-block;
                margin: 0 auto;
                border: 2px solid rgba(255, 255, 255, 0.3);
            }}
            .expiry-text {{
                color: #666;
                font-size: 14px;
                margin-top: 25px;
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid #ffc107;
            }}
            .footer {{
                background: #f8f9fa;
                text-align: center;
                padding: 30px 20px;
                border-top: 1px solid #e9ecef;
            }}
            .footer p {{
                color: #666;
                font-size: 14px;
                margin-bottom: 10px;
            }}
            .logo {{
                font-size: 24px;
                font-weight: 700;
                color: white;
                margin-bottom: 5px;
            }}
            .icon {{
                width: 60px;
                height: 60px;
                background: rgba(255, 255, 255, 0.2);
                border-radius: 50%;
                margin: 0 auto 20px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 30px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="icon">🌲</div>
                <div class="logo">연구의숲</div>
                <h1>회원가입 인증</h1>
                <p>안전한 인증을 위한 코드를 발송해드립니다</p>
            </div>

            <div class="content">
                <p class="welcome-text">
                    안녕하세요! 연구의숲에 가입해주셔서 감사합니다.<br>
                    아래 인증 코드를 입력하여 회원가입을 완료해주세요.
                </p>

                <div class="code-container">
                    <div class="code-label">인증 코드</div>
                    <div class="verification-code">{code}</div>
                </div>

                <div class="expiry-text">
                    ⚠️ 이 코드는 <strong>4분 후</strong>에 만료됩니다.<br>
                    시간 내에 인증을 완료해주세요.
                </div>
            </div>

            <div class="footer">
                <p><strong>연구의숲</strong> - 연구자들의 지식 공유 플랫폼</p>
                <p>이 메일은 자동으로 발송된 메일입니다. 문의사항이 있으시면 고객센터로 연락해주세요.</p>
                <p style="color: #999; font-size: 12px; margin-top: 15px;">
                    © 2024 연구의숲. All rights reserved.
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    message = MessageSchema(
        subject="연구의숲 회원가입 인증 코드",
        recipients=[email],
        body=html_body,
        subtype="html",
        # settings.MAIL_FROM 자체를 "연구의숲 <메일주소>" 형태로 넣었다면 그대로 사용
        sender=getattr(settings, "MAIL_FROM", None) or os.getenv("MAIL_FROM") or os.getenv("NAVER_MAIL_FROM"),
    )

    fm = FastMail(conf)
    await fm.send_message(message)
