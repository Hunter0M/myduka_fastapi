from passlib.context import CryptContext
from app.models import Users, Subscription
from app.database import sessionLocal, get_db
from datetime import timedelta, datetime, timezone
from typing import Optional
from jose import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_
import os

from app.schemas import UserLogin

# SECRET_KEY = "ec998ae8f46bc6a0b20726acfe452ca6b63c3559e215c9260187b3ae902edd70"
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# تكوين أوقات انتهاء الصلاحية
ACCESS_TOKEN_EXPIRE_MINUTES = 1  # 30 دقيقة
REFRESH_TOKEN_EXPIRE_DAYS = 7  # 7 أيام


PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 30  # Token expires in 30 minutes

# Create password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(
    db: Session, 
    password: str, 
    email: str = None, 
    username: str = None
) -> Optional[Users]:
    try:
        # Find user by email or username
        query = db.query(Users)
        if email:
            user = query.filter(Users.email == email.lower()).first()
        elif username:
            user = query.filter(Users.username == username.lower()).first()
        else:
            return None

        if not user:
            print("User not found")  # Debugging log
            return None

        if not verify_password(password, user.password):
            print("Password verification failed")  # Debugging log
            return None

        # Comment out or remove the subscription check
        # active_subscription = db.query(Subscription).filter(
        #     Subscription.company_id == user.company_id,
        #     Subscription.status == "active",
        #     Subscription.start_date <= datetime.now(timezone.utc),
        #     Subscription.end_date >= datetime.now(timezone.utc)
        # ).first()

        # if not active_subscription:
        #     raise HTTPException(
        #         status_code=403,
        #         detail="Your company does not have an active subscription. Please renew your subscription to continue."
        #     )

        print(f"Authenticated user: {user.email}")  # Debugging log
        return user

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        return None

def check_user(email):
    db = sessionLocal()
    user = db.query(Users).filter(Users.email == email).first()
    return user

def create_access_token(data: dict) -> dict:
    """إنشاء access token"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "token_type": "access"
    })
    
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "token": token,
        "expires_at": expire
    }

# def create_refresh_token(data: dict) -> dict:
#     """إنشاء refresh token"""
#     to_encode = data.copy()
#     expire = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_DAYS)
    
#     to_encode.update({
#         "exp": expire,
#         "token_type": "refresh"
#     })
    
#     token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return {
#         "token": token,
#         "expires_at": expire
#     }


def create_refresh_token(data: dict) -> dict:
    """إنشاء refresh token"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "token_type": "refresh"
    })
    
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "token": token,
        "expires_at": expire
    }


def verify_token(token: str) -> dict:
    """التحقق من صحة التوكن"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

def get_token_auth_headers(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    """التحقق من صحة header التوكن"""
    if credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme"
        )
    return credentials.credentials

def check_subscription_status(db: Session, company_id: int) -> bool:
    """Helper function to check if a company has an active subscription"""
    try:
        active_subscription = db.query(Subscription).filter(
            Subscription.company_id == company_id,
            Subscription.status == "active",
            Subscription.start_date <= datetime.now(timezone.utc),
            Subscription.end_date >= datetime.now(timezone.utc)
        ).first()
        
        return bool(active_subscription)
    except Exception as e:
        print(f"Error checking subscription status: {str(e)}")
        return False

async def get_current_user(
    token: str = Depends(get_token_auth_headers),
    db: Session = Depends(get_db)
) -> Users:
    try:
        payload = verify_token(token)
        
        if payload.get("token_type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        email = payload.get("user")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
        user = db.query(Users).filter(Users.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        # Optionally check for company association
        # if not user.company_id:
        #     raise HTTPException(
        #         status_code=status.HTTP_403_FORBIDDEN,
        #         detail="User is not associated with any company. Please contact administrator."
        #     )

        # Optionally check for active subscription
        # if user.company_id and not check_subscription_status(db, user.company_id):
        #     raise HTTPException(
        #         status_code=status.HTTP_403_FORBIDDEN,
        #         detail="Your company does not have an active subscription. Please renew your subscription to continue."
        #     )
        
        return user
    finally:
        db.close()

def verify_refresh_token(refresh_token: str) -> dict:
    """التحقق من صحة refresh token"""
    payload = verify_token(refresh_token)
    
    if payload.get("token_type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    return payload

def create_password_reset_token(email: str) -> str:
    """Create a password reset token"""
    expires = datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "exp": expires,
        "sub": email,
        "type": "password_reset"
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password_reset_token(token: str) -> str:
    """Verify password reset token and return email"""
    try:
        # Decode the token and verify it's a password reset token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Check if it's a valid password reset token and has an email
        if payload.get("type") != "password_reset" or not payload.get("sub"):
            raise jwt.JWTError("Invalid token")
            
        return payload["sub"]  # Return the email
        
    except Exception as e:
        # Handle all token-related errors with a single error message
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset link"
        )

def reset_user_password(db: Session, email: str, new_password: str) -> bool:
    """Reset user password in database"""
    try:
        user = db.query(Users).filter(Users.email == email).first()
        if not user:
            return False
        
        hashed_password = get_password_hash(new_password)
        user.password = hashed_password
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        print(f"Error resetting password: {str(e)}")
        return False









































# from passlib.context import CryptContext
# from models import Users
# from database import sessionLocal
# from datetime import timedelta, datetime, timezone
# from jose import jwt
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from fastapi import Depends, HTTPException, status

# SECRET_KEY = "ec998ae8f46bc6a0b20726acfe452ca6b63c3559e215c9260187b3ae902edd70"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 1

# # Password hashing
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# def check_user(email):
#     db = sessionLocal()
#     user = db.query(Users).filter(Users.email == email).first()
#     return user

# def create_token(data:dict, expires_delta:timedelta | None=None):
#     to_encode = data.copy()
#     if expires_delta:
#         expires = datetime.now(timezone.utc) + expires_delta
#     else:
#         expires = datetime.now(timezone.utc) + expires_delta(minutes=1)
#     to_encode.update({"exp":expires})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, ALGORITHM)
#     return encoded_jwt

# def get_token_auth_headers(credentials:HTTPAuthorizationCredentials=Depends(HTTPBearer())):
#     if credentials.scheme != "Bearer":
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication scheme")
#     return credentials.credentials

# def get_current_user(token:str = Depends(get_token_auth_headers)):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         email = payload.get("user")
#         if email is None:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
#     except jwt.ExpiredSignatureError:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired")
#     except jwt.JWTError:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token ")
#     user = check_user(email)
#     if not user:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User does not exist ")
#     return user





    
        


        


