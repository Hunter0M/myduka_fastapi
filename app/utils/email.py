# from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
# from pydantic import EmailStr
# import os
# from dotenv import load_dotenv

# load_dotenv()

# conf = ConnectionConfig(
#     MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
#     MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
#     MAIL_FROM=os.getenv("MAIL_FROM"),
#     MAIL_PORT=int(os.getenv("MAIL_PORT")),
#     MAIL_SERVER=os.getenv("MAIL_SERVER"),
#     MAIL_STARTTLS=True,
#     MAIL_SSL_TLS=False,
#     USE_CREDENTIALS=True,
#     VALIDATE_CERTS=True
# )

# async def send_reset_password_email(email: EmailStr, token: str):
#     reset_link = f"{os.getenv('FRONTEND_URL')}/reset-password?token={token}"
    
#     message = MessageSchema(
#         subject="Password Reset Request",
#         recipients=[email],
#         body=f"""
#         <html>
#             <body>
#                 <h1>Password Reset Request</h1>
#                 <p>You have requested to reset your password. Click the link below to proceed:</p>
#                 <p><a href="{reset_link}">Reset Password</a></p>
#                 <p>If you didn't request this, please ignore this email.</p>
#                 <p>This link will expire in 24 hours.</p>
#             </body>
#         </html>
#         """,
#         subtype="html"
#     )

#     fm = FastMail(conf)
#     await fm.send_message(message) 