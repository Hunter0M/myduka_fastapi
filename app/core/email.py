from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr, BaseModel
from typing import List
import os
from dotenv import load_dotenv
import ssl

load_dotenv()

# Print configuration for debugging
print("Loading Email Configuration:")
print(f"MAIL_USERNAME: {os.getenv('MAIL_USERNAME')}")
print(f"MAIL_FROM: {os.getenv('MAIL_FROM')}")
print(f"MAIL_SERVER: smtp.gmail.com")

# Email configuration with SSL context
ssl_context = ssl.create_default_context()

# Email configuration
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_APP_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TEMPLATE_FOLDER=None
)

class EmailSchema(BaseModel):
    email: List[EmailStr]

# This function for sending an Email
async def send_contact_email(name: str, email: str, subject: str, message: str):
    # Create email body with HTML formatting and inline styles
    html_content = f"""
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif; background-color: #f8fafc;">
        <div style="background-color: white; border-radius: 8px; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            <h2 style="color: #1e3a8a; font-size: 24px; font-weight: 600; margin-bottom: 20px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;">
                New Contact Form Submission
            </h2>
            
            <div style="margin-bottom: 20px;">
                <p style="margin-bottom: 12px;">
                    <span style="font-weight: 600; color: #475569; display: inline-block; width: 80px;">From:</span>
                    <span style="color: #1e293b;">{name}</span>
                </p>
                <p style="margin-bottom: 12px;">
                    <span style="font-weight: 600; color: #475569; display: inline-block; width: 80px;">Email:</span>
                    <a href="mailto:{email}" style="color: #2563eb; text-decoration: none;">{email}</a>
                </p>
                <p style="margin-bottom: 12px;">
                    <span style="font-weight: 600; color: #475569; display: inline-block; width: 80px;">Subject:</span>
                    <span style="color: #1e293b;">{subject}</span>
                </p>
            </div>
            
            <div style="background-color: #f8fafc; border-radius: 6px; padding: 16px; margin-top: 20px;">
                <h3 style="color: #475569; font-size: 18px; font-weight: 600; margin-bottom: 12px;">
                    Message:
                </h3>
                <p style="color: #1e293b; line-height: 1.6; white-space: pre-wrap;">{message}</p>
            </div>
            
            <div style="margin-top: 24px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 14px; color: #64748b; text-align: center;">
                This is an automated message from your contact form.
            </div>
        </div>
    </div>
    """

    # Configure email message
    message = MessageSchema(
        subject=f"New Contact Form: {subject}",
        recipients=[os.getenv("ADMIN_EMAIL")],
        body=html_content,
        subtype="html"
    )

    # Send email
    fm = FastMail(conf)
    await fm.send_message(message)



# This function for Reset Password :
async def send_password_reset_email(email: str, reset_token: str, base_url: str):
    """Send password reset email with a verification link"""
    try:
        print(f"Preparing to send reset email to: {email}")
        reset_link = f"{base_url}/reset-password?token={reset_token}"
        
        html_content = f"""
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
            <h2>Password Reset Request</h2>
            <p>Click the link below to reset your password:</p>
            <a href="{reset_link}" style="display: inline-block; padding: 10px 20px; 
                      background-color: #007bff; color: white; text-decoration: none; 
                      border-radius: 5px;">Reset Password</a>
            <p>Or copy this link: {reset_link}</p>
            <p>This link will expire in 30 minutes.</p>
        </div>
        """

        # Create message schema
        message = MessageSchema(
            subject="Password Reset Request",
            recipients=[email],
            body=html_content,
            subtype="html"
        )

        # Initialize FastMail
        print("Initializing FastMail...")
        fm = FastMail(conf)
        
        # Send email
        print("Attempting to send email...")
        await fm.send_message(message)
        print(f"Email sent successfully to {email}")
        
    except Exception as e:
        print(f"Error details: {str(e)}")
        raise Exception(f"Failed to send email: {str(e)}") 