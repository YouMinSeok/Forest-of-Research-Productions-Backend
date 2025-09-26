import random
import string
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from app.core.config import settings

def generate_verification_code(length: int = 6) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

# FastAPI-Mail ConnectionConfig 생성: 제공자에 따라 TLS/SSL 설정 변경
if settings.EMAIL_PROVIDER == "naver":
    conf = ConnectionConfig(
        MAIL_USERNAME=settings.MAIL_USERNAME,
        MAIL_PASSWORD=settings.MAIL_PASSWORD,
        MAIL_FROM=settings.MAIL_FROM,
        MAIL_PORT=settings.MAIL_PORT,
        MAIL_SERVER=settings.MAIL_SERVER,
        MAIL_STARTTLS=False,    # 네이버는 TLS 사용하지 않음
        MAIL_SSL_TLS=True,      # 네이버는 SSL 사용
        USE_CREDENTIALS=settings.USE_CREDENTIALS,
        TEMPLATE_FOLDER=""
    )
else:
    conf = ConnectionConfig(
        MAIL_USERNAME=settings.MAIL_USERNAME,
        MAIL_PASSWORD=settings.MAIL_PASSWORD,
        MAIL_FROM=settings.MAIL_FROM,
        MAIL_PORT=settings.MAIL_PORT,
        MAIL_SERVER=settings.MAIL_SERVER,
        MAIL_STARTTLS=True,     # Gmail은 TLS 사용
        MAIL_SSL_TLS=False,     # Gmail은 SSL 미사용
        USE_CREDENTIALS=settings.USE_CREDENTIALS,
        TEMPLATE_FOLDER=""
    )

async def send_verification_email(email: str, code: str):
    # HTML 템플릿
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
        subject="🌲 연구의숲 회원가입 인증 코드",
        recipients=[email],
        body=html_body,
        subtype="html",
        sender="연구의숲 <" + settings.MAIL_FROM + ">"
    )
    fm = FastMail(conf)
    await fm.send_message(message)
