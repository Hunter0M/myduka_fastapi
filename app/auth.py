from passlib.context import CryptContext
from app.models import Users
from app.database import sessionLocal
from datetime import timedelta, datetime, timezone
from jose import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, HTTPException, status

from sqlalchemy.orm import Session
from app.schemas import UserLogin

SECRET_KEY = "ec998ae8f46bc6a0b20726acfe452ca6b63c3559e215c9260187b3ae902edd70"
ALGORITHM = "HS256"

# تكوين أوقات انتهاء الصلاحية
ACCESS_TOKEN_EXPIRE_MINUTES = 1  # 30 دقيقة
REFRESH_TOKEN_EXPIRE_DAYS = 30  # 7 أيام

# Create password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, email: str, password: str) -> Users | None:
    """التحقق من صحة بيانات المستخدم"""
    user = db.query(Users).filter(Users.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return user

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

def create_refresh_token(data: dict) -> dict:
    """إنشاء refresh token"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_DAYS)
    
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

def get_current_user(token: str = Depends(get_token_auth_headers)):
    """الحصول على المستخدم الحالي من التوكن"""
    payload = verify_token(token)
    
    # التحقق من نوع التوكن
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
    
    user = check_user(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user

def verify_refresh_token(refresh_token: str) -> dict:
    """التحقق من صحة refresh token"""
    payload = verify_token(refresh_token)
    
    if payload.get("token_type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    return payload









































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





    
        


        


