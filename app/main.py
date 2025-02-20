import re # Pattern Matching: Regular expressions allow you to define a search pattern. This pattern can be used to check if a string contains specific characters, words, or sequences.
import os
import requests # pip install requests 
from pathlib import Path 
import io
from fastapi.staticfiles import StaticFiles
import shutil
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from sqlalchemy import func, or_
from fastapi.security import HTTPBearer

from typing import Optional, Union
import pandas as pd # pip install pandas openpyxl

from fastapi.responses import FileResponse

from fastapi import FastAPI, Depends, status, HTTPException, File, UploadFile, Query, BackgroundTasks, Form, Request
from sqlalchemy.orm import Session
from typing import List
import app.models as models
import app.database as database
import app.schemas as schemas
from app.auth import get_password_hash, authenticate_user, verify_refresh_token, create_access_token, create_refresh_token, get_current_user, create_password_reset_token, verify_password_reset_token, reset_user_password
from fastapi.middleware.cors import CORSMiddleware
# from app.schemas import ProductCreate, VendorCreate, VendorUpdate, Vendor , STKPushCreate, STKPushResponse

from app.schemas import *

from pydantic import ValidationError
from sqlalchemy.orm import joinedload

# from app.models import STKPush
from app.utils.mpesa import *
# from app.mpesa_config import *

from app.dependencies import get_current_company, get_current_user
from app.core.email import send_contact_email, send_password_reset_email

from datetime import datetime, timedelta
from jose import jwt
from sqlalchemy.exc import IntegrityError
import logging
import pytz

logger = logging.getLogger(__name__)

# Add these constants at the top of your file
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 30
SECRET_KEY = os.getenv("SECRET_KEY")  # Make sure this is in your .env file
ALGORITHM = "HS256"

app = FastAPI()
models.Base.metadata.create_all(database.engine)

origins = [
    "http://localhost:3000",  # Your React app URL
    "http://127.0.0.1:3000",
    "http://192.168.1.20:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# app.add_middleware(
#     CORSMiddleware,
#     # allow_origins=["http://http://178.62.113.250"],  # Allows all origins
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# Configure CORS
# origins = [
#     "http://localhost",
#     "http://localhost:5173",
#     "https://inventorysystem.co.ke",
#     "https://www.inventorysystem.co.ke"
# ]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


@app.get("/")
def index():
    return {"message": "Hello, World!"}
# Add this simple test route
@app.get("/test")
def test_route():
    return {"message": "Test route works!"}

# # Password hashing
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to validate password complexity
def validate_password(password: str) -> None:
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
    
    if not re.search(r"[A-Za-z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one letter small or capital")
    
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one number")
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character")


# Start route for registering a user >>
# Route for registering a user:
@app.post("/register", response_model=schemas.UserResponse)
async def register_user(
    user: schemas.UserCreate,
    company_id: int = Query(..., description="Company ID to associate with the user"),
    db: Session = Depends(database.get_db)
):
    try:
        validate_password(user.password)
        
        logger.info("Registering user: %s", user.username)
        # Check if the company exists
        company = db.query(models.Company).filter(models.Company.id == company_id).first()
        if not company:
            logger.error("Company not found: %d", company_id)
            raise HTTPException(status_code=404, detail="Company not found")

        # Check if username already exists
        existing_user = db.query(models.Users).filter(models.Users.username == user.username).first()
        if existing_user:
            logger.error("Username already exists: %s", user.username)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists. Please choose a different one."
            )

        # Create new user associated with the company
        db_user = models.Users(
            username=user.username,
            email=user.email,
            password=get_password_hash(user.password),
            full_name=user.full_name,
            company_id=company_id,
            company_role='owner',
            is_admin=True
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info("User registered successfully: %s", user.username)
        
        # Prepare the response
        response_data = schemas.UserResponse(
            id=db_user.id,
            email=db_user.email,
            full_name=db_user.full_name,
            is_admin=db_user.is_admin,
            hasCompany=True,
            company_role=db_user.company_role,
            created_at=db_user.created_at,
            updated_at=db_user.updated_at,
            hasUsedFreeTrial=False  
        )
        
        return response_data
        
    except HTTPException as he:
        logger.error("HTTPException: %s", str(he))
        raise he
    except IntegrityError as ie:
        db.rollback()
        logger.error("IntegrityError: %s", str(ie.orig))
        if "users_email_key" in str(ie.orig):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This email is already registered."
            )
        elif "users_username_key" in str(ie.orig):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This username is already taken."
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred. Please try again."
            )
    except Exception as e:
        db.rollback()
        logger.error("Unexpected error: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again."
        )

@app.post("/validate")
async def validate_user(data: schemas.ValidationRequest, db: Session = Depends(database.get_db)):
    if data.username:
        # Check if the username already exists
        existing_user = db.query(models.Users).filter(models.Users.username == data.username).first()
        if existing_user:
            return {"exists": True}
    
    if data.email:
        # Check if the email already exists
        existing_user = db.query(models.Users).filter(models.Users.email == data.email).first()
        if existing_user:
            return {"exists": True}
    
    return {"exists": False}    


@app.post("/login", response_model=schemas.TokenResponse)
def login(
    user_credentials: schemas.UserLogin,
    db: Session = Depends(database.get_db)
):
    try:
        # Check if input is email or username
        is_email = '@' in user_credentials.email_or_username
        print(f"Login attempt with {'email' if is_email else 'username'}: {user_credentials.email_or_username}")

        # Authenticate user
        user = authenticate_user(
            db=db,
            password=user_credentials.password,
            email=user_credentials.email_or_username if is_email else None,
            username=user_credentials.email_or_username if not is_email else None
        )

        if not user:
            print("Authentication failed: Incorrect username/email or password")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username/email or password"
            )

        # Generate tokens
        access_token = create_access_token({"user": user.email})
        refresh_token = create_refresh_token({"user": user.email})

        print(f"User {user.email} authenticated successfully")

        return {
            "access_token": access_token["token"],
            "access_token_expires": access_token["expires_at"],
            "refresh_token": refresh_token["token"],
            "refresh_token_expires": refresh_token["expires_at"],
            "token_type": "bearer",
            "user_email": user.email
        }
    
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Unexpected error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@app.post("/refresh", response_model=schemas.TokenResponse)
async def refresh_token(refresh_request: schemas.RefreshTokenRequest):
    payload = verify_refresh_token(refresh_request.refresh_token)
    
    access_token_data = create_access_token({"user": payload["user"]})
    
    return {
        "access_token": access_token_data["token"],
        "access_token_expires": access_token_data["expires_at"],
        "refresh_token": refresh_request.refresh_token,
        "refresh_token_expires": datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        "token_type": "bearer"
    }

 # The end for login a user <<
    


# Route for getting all users:


@app.get("/users", response_model=List[schemas.UserResponse])
def get_all_users(
    skip: int = Query(default=0, description="Number of users to skip"),
    limit: int = Query(default=100, description="Maximum number of users to return"),
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    # Check if the requesting user is an admin
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Only administrators can view all users"
        )
    
    try:
        # Query all users with pagination
        users = db.query(models.Users)\
            .offset(skip)\
            .limit(limit)\
            .all()
        
        # Convert None to False for is_admin field and format response
        formatted_users = []
        for user in users:
            formatted_users.append({
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                # "phone": user.phone,
                "is_admin": bool(user.is_admin),
                "company_role": user.company_role or "user",  # Default to "user" if None
                "created_at": user.created_at,
                "updated_at": user.updated_at
            })
        
        return formatted_users

    except Exception as e:
        print(f"Error fetching users: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while fetching users"
        )

@app.get("/users/me", response_model=schemas.UserResponse)
def get_current_user_info(
    db: Session = Depends(database.get_db),
    current_user: models.Users = Depends(get_current_user)
):
    # Fetch the user from the database
    user = db.query(models.Users).filter(models.Users.id == current_user.id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Determine if the user has a company
    has_company = user.company_id is not None
    
    # Check if the user's company has used a free trial
    has_used_free_trial = False
    if has_company:
        free_trial_subscription = db.query(models.Subscription).join(
            models.SubscriptionPlan
        ).filter(
            models.Subscription.company_id == user.company_id,
            models.SubscriptionPlan.name == "Free Trial"
        ).first()
        has_used_free_trial = free_trial_subscription is not None
    
    # Return user data including hasCompany and hasUsedFreeTrial status
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": bool(user.is_admin),
        "company_role": user.company_role,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "hasCompany": has_company,
        "hasUsedFreeTrial": has_used_free_trial
    }

@app.get("/users/{user_id}", response_model=schemas.UserResponse)
def fetch_user(user_id: int, db: Session = Depends(database.get_db)):
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

@app.get("/users/email/{email}", response_model=schemas.UserResponse)
def fetch_user_by_email(email: str, db: Session = Depends(database.get_db)):
    user = db.query(models.Users).filter(models.Users.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

@app.get("/users/email/{email}", response_model=schemas.UserResponse)
def fetch_user_by_email(email: str, db: Session = Depends(database.get_db)):
    user = db.query(models.Users).filter(models.Users.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

# Route for updating a user, including password update:
@app.put("/users/{user_id}", response_model=schemas.UserResponse)
def update_user(
    user_id: int,
    user_update: schemas.UserUpdate,
    db: Session = Depends(database.get_db)
):
    existing_user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if existing_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # تحديث البيانات المقدمة فقط
    update_data = user_update.dict(exclude_unset=True)
    
    # معالجة خاصة للمة المرور إذا تم تقديمها
    if 'password' in update_data:
        update_data['password'] = get_password_hash(update_data['password'])

    for key, value in update_data.items():
        setattr(existing_user, key, value) 

    db.commit()
    db.refresh(existing_user)
    return existing_user

# Route for deleting a user:    
@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(database.get_db)):
    existing_user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if existing_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    db.delete(existing_user)
    db.commit()
    return None

# Route for making a user an admin: 
@app.post("/users/{user_id}/make-admin", response_model=schemas.UserResponse)
def make_user_admin(
    user_id: int,
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    # Only existing admins can make other users admin
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Only administrators can perform this action"
        )
    
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    user.is_admin = True
    db.commit()
    db.refresh(user)
    return user

# Route for revoking admin privileges:
@app.post("/users/{user_id}/revoke-admin", response_model=schemas.UserResponse)
def revoke_admin_privileges(
    user_id: int,
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    # Only existing admins can revoke admin privileges
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Only administrators can perform this action"
        )
    
    # Prevent self-revocation
    if user_id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot revoke your own admin privileges"
        )
    
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    user.is_admin = False
    db.commit()
    db.refresh(user)
    return user

# Route for seeing the trial left for the user
@app.get("/users/me/trial", response_model=schemas.TrialStatusResponse)
async def get_user_trial_status(
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    try:
        # Get user's company
        company = db.query(models.Company).filter(
            models.Company.id == current_user.company_id
        ).first()
        
        if not company:
            return {
                "is_trial": False,
                "message": "No company associated with user",
                "minutes_left": 0,
                "trial_end": None,
                "user_email": current_user.email
            }

        # Get trial subscription
        trial_subscription = db.query(models.Subscription).join(
            models.SubscriptionPlan
        ).filter(
            models.Subscription.company_id == company.id,
            models.SubscriptionPlan.name == "Free Trial",
            models.Subscription.status == "active"
        ).first()


        if not trial_subscription:
            return {
                "is_trial": False,
                "message": "No valid trial found",
                "minutes_left": 0,
                "trial_end": None,
                "user_email": current_user.email
            }

        # Ensure end_date is timezone-aware
        end_date = trial_subscription.end_date
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=pytz.UTC)

        # Get current time as timezone-aware
        now = datetime.now(pytz.UTC)
        time_left = end_date - now
        minutes_left = max(0, int(time_left.total_seconds() / 60))

        return {
            "is_trial": minutes_left > 0,
            "message": f"Trial active with {minutes_left} minutes remaining",
            "minutes_left": minutes_left,
            "trial_end": end_date,
            "user_email": current_user.email
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error checking trial status: {str(e)}"
        )



# The end for the User routes <<



@app.get("/activity", response_model=schemas.UserActivity)
def get_user_activity(
    current_user: models.Users = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    # Get recent sales (last 30 days)
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_sales = db.query(models.Sale)\
        .filter(
            models.Sale.user_id == current_user.id,
            models.Sale.created_at >= thirty_days_ago
        )\
        .order_by(models.Sale.created_at.desc())\
        .limit(10)\
        .all()

    # Get recent products
    recent_products = db.query(models.Product)\
        .filter(models.Product.owner_id == current_user.id)\
        .order_by(models.Product.created_at.desc())\
        .limit(10)\
        .all()

    # Calculate statistics
    sales_stats = db.query(
        func.count(models.Sale.id).label('total_sales'),
        func.sum(models.Sale.total_amount).label('revenue')
    ).filter(models.Sale.user_id == current_user.id).first()

    total_products = db.query(func.count(models.Product.id))\
        .filter(models.Product.owner_id == current_user.id)\
        .scalar()

    return {
        "recent_sales": recent_sales,
        "recent_products": recent_products,
        "statistics": {
            "total_sales": sales_stats.total_sales or 0,
            "total_products": total_products or 0,
            "revenue": float(sales_stats.revenue or 0)
        }
    }



# Start Product Routes >> 
# Define base directory and upload paths
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
PRODUCTS_DIR = UPLOAD_DIR / "products"

# Create necessary directories
os.makedirs(PRODUCTS_DIR, exist_ok=True)

# Mount the uploads directory
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

# Helper function to handle file upload
async def save_upload_file(upload_file: UploadFile, company_id: int) -> str:
    try:
        # Create company-specific directory
        company_dir = PRODUCTS_DIR / f"company_{company_id}"
        os.makedirs(str(company_dir), exist_ok=True)
        
        # Generate unique filename
        file_extension = Path(upload_file.filename).suffix
        unique_filename = f"{uuid4()}{file_extension}"
        
        # Create full file path
        file_path = company_dir / unique_filename
        
        # Save file
        with open(str(file_path), "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
        
        # Return relative path for database storage
        return f"/uploads/products/company_{company_id}/{unique_filename}"
        
    except Exception as e:
        print(f"Error saving file: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not save image file"
        )

DEFAULT_IMAGE_PATH = "/uploads/default-product.jpg"  # Adjust path as needed

@app.post("/products", response_model=schemas.ProductResponse, status_code=status.HTTP_201_CREATED)
async def add_product(
    product_name: str = Form(...),
    product_price: int = Form(...),
    selling_price: int = Form(...),
    vendor_id: int = Form(...),
    description: Optional[str] = Form(default=None),
    image: UploadFile = File(default=None),
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check if the company is on a free trial
        subscription = db.query(models.Subscription).filter(
            models.Subscription.company_id == current_company.id,
            models.Subscription.status == "active"
        ).first()
        
        # this is to check if the company is on a free trial
        if subscription and subscription.plan.name == "Free Trial":
            # Count the number of products already created
            product_count = db.query(models.Products).filter(
                models.Products.company_id == current_company.id
            ).count()

            # Debug: Log product count and subscription details
            print(f"Product count for company {current_company.id}: {product_count}")
            print(f"Subscription plan: {subscription.plan.name}")

            # this is to check if the company has reached the limit of 5 products   
            if product_count >= 5:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Free trial allows only up to 5 products"
                )

        # Create product data dict without stock_quantity
        product_data = {
            "product_name": product_name.strip(),
            "product_price": product_price,
            "selling_price": selling_price,
            "vendor_id": vendor_id,
            "description": description.strip() if description else None,
            "image_url": DEFAULT_IMAGE_PATH,
            "company_id": current_company.id
        }

        # Handle image upload only if a valid image is provided
        if image and image.filename:
            try:
                if not image.content_type.startswith("image/"):
                    raise HTTPException(
                        status_code=400, 
                        detail="File must be an image"
                    )
                
                image_url = await save_upload_file(
                    image, 
                    company_id=current_company.id
                )
                product_data["image_url"] = image_url
            except Exception as e:
                print(f"Error processing image: {str(e)}")
                # Continue with default image if image processing fails
                pass

        # Check user permissions
        if current_user.company_role not in ['owner', 'admin', 'staff']:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to add products"
            )

        # Validate vendor exists and belongs to the same company
        vendor = db.query(models.Vendor).filter(
            models.Vendor.id == vendor_id,
            models.Vendor.company_id == current_company.id
        ).first()
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail=f"Vendor with ID {vendor_id} not found in your company"
            )

        # Check for duplicate product name within the same company
        existing_product = db.query(models.Products).filter(
            models.Products.product_name == product_name.strip(),
            models.Products.company_id == current_company.id
        ).first()
        if existing_product:
            raise HTTPException(
                status_code=400,
                detail=f"Product with name '{product_name}' already exists in your company"
            )

        # Create new product in database
        new_product = models.Products(**product_data)
        db.add(new_product)
        db.commit()
        db.refresh(new_product)
        
        return new_product

    except ValidationError as ve:
        raise HTTPException(status_code=422, detail=str(ve))
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error adding product: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/products/check-name")
async def check_product_name(
    product_name: str, 
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Convert to lowercase and trim whitespace for comparison
        normalized_name = product_name.lower().strip()
        
        # Check within the current company's products only
        product = db.query(models.Products).filter(
            func.lower(models.Products.product_name) == normalized_name,
            models.Products.company_id == current_company.id
        ).first()
        
        exists = product is not None
        print(f"Checking product name: {product_name} for company {current_company.id}, exists: {exists}")  # Debug log
        
        return {
            "exists": exists,
            "company_id": current_company.id,
            "message": f"Product {'already exists' if exists else 'name is available'} in your company"
        }
    except Exception as e:
        print(f"Error checking product name for company {current_company.id}: {str(e)}")  # Debug log
        raise HTTPException(
            status_code=500, 
            detail=f"Error checking product name: {str(e)}"
        )

@app.get("/product")
def fetch_my_company_products(
    skip: int = Query(default=0, description="Number of records to skip"),
    limit: int = Query(default=100, description="Maximum number of records to return"),
    search: Optional[str] = Query(None, description="Search products by name"),
    sort_by: Optional[str] = Query(None, description="Sort field"),
    sort_order: Optional[str] = Query("asc", description="Sort direction (asc/desc)"),
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get user with company relationship
        user = db.query(models.Users).filter(
            models.Users.id == current_user.id
        ).first()
        
        if not user or not user.company_id:
            raise HTTPException(
                status_code=400,
                detail="User not associated with any company"
            )

        # Start with base query for user's company using left join
        query = db.query(models.Products, models.ProductStock.stock_quantity)\
            .outerjoin(models.ProductStock, models.ProductStock.product_id == models.Products.id)\
            .filter(models.Products.company_id == user.company_id)\
            .options(joinedload(models.Products.vendor))

        # Add search filter if provided
        if search:
            search_term = f"%{search.lower()}%"
            query = query.filter(func.lower(models.Products.product_name).like(search_term))

        # Add sorting
        if sort_by:
            sort_column = getattr(models.Products, sort_by, None)
            if sort_column is not None:
                query = query.order_by(
                    sort_column.desc() if sort_order == "desc" else sort_column
                )

        # Get total count before pagination
        total_count = query.count()

        # Add pagination
        products = query.offset(skip).limit(limit).all()
        
        # Format the response
        formatted_products = []
        for product, stock_quantity in products:
            product_dict = {
                "id": product.id,
                "product_name": product.product_name,
                "product_price": product.product_price,
                "selling_price": product.selling_price,
                "description": product.description,
                "image_url": product.image_url,
                "created_at": product.created_at,
                "updated_at": product.updated_at,
                "vendor_id": product.vendor_id,
                "company_id": product.company_id,
                "stock_quantity": stock_quantity or 0,  # Handle None stock quantity
                "vendor": {
                    "id": product.vendor.id,
                    "name": product.vendor.name,
                    "contact_person": product.vendor.contact_person,
                    "email": product.vendor.email,
                    "phone": product.vendor.phone,
                    "address": product.vendor.address
                } if product.vendor else None
            }
            formatted_products.append(product_dict)
        
        return {
            "products": formatted_products,
            "total": total_count,
            "skip": skip,
            "limit": limit,
            "has_more": total_count > (skip + limit),
            "company_id": user.company_id
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error fetching products: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching products: {str(e)}"
        )

@app.get("/products/{id}", response_model=schemas.ProductResponse)
def fetch_product(
    id: int, 
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Query product with company check
        product = db.query(models.Products)\
            .options(joinedload(models.Products.vendor))\
            .filter(
                models.Products.id == id,
                models.Products.company_id == current_company.id  # Add company filter
            ).first()
            
        if not product:
            raise HTTPException(
                status_code=404, 
                detail="Product not found in your company"
            )
            
        # Convert to dict and include vendor information
        return {
            "id": product.id,
            "product_name": product.product_name,
            "description": product.description,
            "product_price": product.product_price,
            "selling_price": product.selling_price,
            "image_url": product.image_url,
            "created_at": product.created_at,
            "updated_at": product.updated_at,
            "vendor_id": product.vendor_id,
            "company_id": current_company.id,  # Include company_id in response
            "vendor": {
                "id": product.vendor.id,
                "name": product.vendor.name,
                "contact_person": product.vendor.contact_person,
                "email": product.vendor.email,
                "phone": product.vendor.phone,
                "address": product.vendor.address
            } if product.vendor else None
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error fetching product {id} for company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error fetching product: {str(e)}"
        )

@app.put("/products/{id}", status_code=status.HTTP_200_OK)
async def update_product(
    id: int,
    product_name: str = Form(...),
    product_price: float = Form(...),
    selling_price: float = Form(...),
    # stock_quantity: int = Form(...),
    description: Optional[str] = Form(default=None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check user permissions
        if current_user.company_role not in ['owner', 'admin']:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to update products"
            )

        # Fetch existing product with company check
        product = db.query(models.Products).filter(
            models.Products.id == id,
            models.Products.company_id == current_company.id
        ).first()
        
        if not product:
            raise HTTPException(
                status_code=404, 
                detail="Product not found in your company"
            )

        # Check for duplicate name within the same company
        existing_product = db.query(models.Products).filter(
            models.Products.product_name == product_name.strip(),
            models.Products.id != id,
            models.Products.company_id == current_company.id
        ).first()
        
        if existing_product:
            raise HTTPException(
                status_code=400,
                detail=f"Product with name '{product_name}' already exists in your company"
            )

        # Handle image upload
        if image:
            try:
                if not image.content_type.startswith("image/"):
                    raise HTTPException(status_code=400, detail="File must be an image")
                
                # Delete old image if it exists and isn't the default
                if product.image_url and not product.image_url.endswith('default-product.png'):
                    old_image_path = os.path.join(
                        UPLOAD_DIR, 
                        f"company_{current_company.id}",
                        os.path.basename(product.image_url)
                    )
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Save new image with company context
                image_url = await save_upload_file(image, company_id=current_company.id)
                product.image_url = image_url
                
            except Exception as e:
                print(f"Error handling image for company {current_company.id}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error uploading image: {str(e)}")

        # Update other fields
        product.product_name = product_name.strip()
        product.product_price = float(product_price)
        product.selling_price = float(selling_price)
        # product.stock.stock_quantity = stock_quantity
        # product.stock.updated_at = datetime.utcnow()
        # if description is not None:
        #     product.description = description.strip()
        
        product.updated_at = datetime.utcnow()

        # Commit changes
        db.commit()
        db.refresh(product)
        
        return {
            "message": "Product updated successfully",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "product_price": product.product_price,
                "selling_price": product.selling_price,
                # "stock_quantity": product.stock.stock_quantity,
                "description": product.description,
                "image_url": product.image_url,
                "updated_at": product.updated_at,
                "company_id": current_company.id
            }
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error updating product for company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error updating product: {str(e)}"
        )



@app.put("/products/{id}/remove-image", status_code=status.HTTP_200_OK)
async def remove_product_image(
    id: int, 
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check user permissions
        if current_user.company_role not in ['owner', 'admin']:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to modify products"
            )

        # Get product with company check
        product = db.query(models.Products).filter(
            models.Products.id == id,
            models.Products.company_id == current_company.id
        ).first()
        
        if not product:
            raise HTTPException(
                status_code=404, 
                detail="Product not found in your company"
            )

        # Delete the physical image file if it exists
        if product.image_url:
            image_path = os.path.join(
                os.getcwd(),
                'static',
                f'company_{current_company.id}',
                os.path.basename(product.image_url)
            )
            if os.path.exists(image_path):
                os.remove(image_path)

        # Update the database record
        product.image_url = DEFAULT_IMAGE_PATH
        product.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(product)
        
        return {
            "message": "Image removed successfully",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "image_url": product.image_url,
                "company_id": current_company.id
            }
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error removing image for product {id} in company {current_company.id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/products/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_product(
    id: int, 
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check user permissions
        if current_user.company_role not in ['owner', 'admin']:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to delete products"
            )

        # Get product with company check
        product = db.query(models.Products).filter(
            models.Products.id == id,
            models.Products.company_id == current_company.id
        ).first()
        
        if not product:
            raise HTTPException(
                status_code=404, 
                detail="Product not found in your company"
            )

        # Delete image file if exists
        if product.image_url and not product.image_url.endswith('default-product.png'):
            image_path = os.path.join(
                os.getcwd(),
                'static',
                f'company_{current_company.id}',
                os.path.basename(product.image_url)
            )
            if os.path.exists(image_path):
                os.remove(image_path)

        # Delete the product
        db.delete(product)
        db.commit()
        
        return None

    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error deleting product {id} in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error deleting product: {str(e)}"
        )

# The end for the Product routes <<

# Start Stock Routes >>
# This is for creating a new stock entry for a product:
@app.post("/product-stocks", response_model=schemas.ProductStockResponse)
async def post_product_stock(
    product_id: int = Form(...),
    stock_quantity: int = Form(...),
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check user permissions
        if current_user.company_role not in ['owner', 'admin']:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to modify stock quantities"
            )

        # Fetch the product with company check
        product = db.query(models.Products).filter(
            models.Products.id == product_id,
            models.Products.company_id == current_company.id
        ).first()
        
        if not product:
            raise HTTPException(
                status_code=404,
                detail="Product not found in your company"
            )

        # Check if stock entry already exists
        stock = db.query(models.ProductStock).filter(
            models.ProductStock.product_id == product_id
        ).first()

        if stock:
            # Update existing stock quantity
            stock.stock_quantity = stock_quantity
            stock.updated_at = datetime.utcnow()
        else:
            # Create new stock entry
            stock = models.ProductStock(
                product_id=product_id,
                stock_quantity=stock_quantity
            )
            db.add(stock)

        db.commit()
        db.refresh(stock)
        
        # Return the stock with product name and selling price
        return {
            "id": stock.id,
            "product_id": stock.product_id,
            "stock_quantity": stock.stock_quantity,
            "product_name": product.product_name,  # Include product name
            "selling_price": product.selling_price,  # Include selling price
            "updated_at": stock.updated_at
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error posting product stock for product {product_id} in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error posting product stock: {str(e)}"
        )

# This is for retrieving all the product stocks for the current company:
@app.get("/product-stocks", response_model=List[schemas.ProductStockResponse])
async def get_product_stocks(
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Fetch product stocks with product names and selling prices
        stocks = db.query(
            models.ProductStock,
            models.Products.product_name,
            models.Products.selling_price  # Include selling price
        ).join(models.Products).filter(
            models.Products.company_id == current_company.id
        ).all()

        # Format the response to include product_name and selling_price
        response = [
            {
                "id": stock.ProductStock.id,
                "product_id": stock.ProductStock.product_id,
                "stock_quantity": stock.ProductStock.stock_quantity,
                "product_name": stock.product_name,
                "selling_price": stock.selling_price,  # Include selling price
                "updated_at": stock.ProductStock.updated_at
            }
            for stock in stocks
        ]

        return response

    except Exception as e:
        print(f"Error fetching product stocks: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error fetching product stocks"
        )
    
# This is for retrieving the stock quantity of a product:
@app.get("/product-stocks/{product_id}", response_model=schemas.ProductStockResponse)
async def get_product_stock(
    product_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Fetch the product stock with product name
        stock = db.query(models.ProductStock, models.Products.product_name)\
            .join(models.Products)\
            .filter(
                models.ProductStock.product_id == product_id,
                models.Products.company_id == current_company.id
            ).first()
        
        if not stock:
            raise HTTPException(
                status_code=404,
                detail="Stock entry not found for this product"
            )
        
        # Return the stock with product name
        return {
            "id": stock.ProductStock.id,
            "product_id": stock.ProductStock.product_id,
            "stock_quantity": stock.ProductStock.stock_quantity,
            "product_name": stock.product_name,  # Include product name
            "updated_at": stock.ProductStock.updated_at
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error fetching product stock for product {product_id} in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching product stock: {str(e)}"
        )

@app.put("/product-stocks/{product_id}", response_model=schemas.ProductStockResponse)
async def update_product_stock(
    product_id: int,
    stock_quantity: int = Form(...),
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        print(f"Attempting to update product stock for product_id: {product_id} in company: {current_company.id}")

        # Check user permissions
        if current_user.company_role not in ['owner', 'admin']:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to update stock quantities"
            )

        # Fetch the product stock with product name and selling price
        stock = db.query(models.ProductStock, models.Products.product_name, models.Products.selling_price)\
            .join(models.Products)\
            .filter(
                models.ProductStock.product_id == product_id,
                models.Products.company_id == current_company.id
            ).first()
        
        if not stock:
            print(f"Product stock not found for product_id: {product_id} in company: {current_company.id}")
            raise HTTPException(
                status_code=404,
                detail="Product stock not found in your company"
            )

        # Update stock quantity
        stock.ProductStock.stock_quantity = stock_quantity
        stock.ProductStock.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(stock.ProductStock)
        
        # Return the stock with product name and selling price
        return {
            "id": stock.ProductStock.id,
            "product_id": stock.ProductStock.product_id,
            "stock_quantity": stock.ProductStock.stock_quantity,
            "product_name": stock.product_name,  # Include product name
            "selling_price": stock.selling_price,  # Include selling price
            "updated_at": stock.ProductStock.updated_at
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error updating product stock for product {product_id} in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error updating product stock: {str(e)}"
        )


# The end for the Stock Routes <<





# Start Sale Routes >> 

# This is for creating a sale:  
@app.post("/sales", response_model=schemas.TransactionResponse)
def create_sale(
    sale: schemas.CartSaleCreate,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Initialize total amount
        total_amount = 0
        sales_records = []

        # Process each item in the cart
        for item in sale.cart_items:
            # Get product for current company
            product = db.query(models.Products).filter(
                models.Products.id == item.product_id,
                models.Products.company_id == current_company.id
            ).first()
            
            if not product:
                raise HTTPException(
                    status_code=404,
                    detail=f"Product {item.product_id} not found in your company"
                )

            # Validate stock
            if product.stock.stock_quantity < item.quantity:
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient stock for {product.product_name}"
                )

            # Calculate item total and update total amount
            item_total = item.quantity * item.selling_price
            total_amount += item_total

            # Create sale record
            sale_record = models.Sales(
                pid=product.id,
                quantity=item.quantity,
                unit_price=item.selling_price,
                user_id=current_user.id,
                company_id=current_company.id,
                status="completed"
            )
            db.add(sale_record)
            db.flush()  # Get the sale_record ID
            sales_records.append((sale_record, product))

            # Update product stock
            product.stock.stock_quantity -= item.quantity

        # Create transaction record
        transaction = models.Transactions(
            user_id=current_user.id,
            company_id=current_company.id,
            total_amount=total_amount,
            status="completed"
        )
        db.add(transaction)
        db.flush()

        # Link sales to transaction
        for sale_record, _ in sales_records:
            db.add(models.TransactionSales(
                transaction_id=transaction.id,
                sale_id=sale_record.id,
                company_id=current_company.id
            ))

        # Commit all changes
        db.commit()

        # Return formatted response
        return {
            "id": transaction.id,
            "total_amount": total_amount,
            "status": "completed",
            "created_at": transaction.created_at,
            "company_id": current_company.id,
            "sales": [
                {
                    "id": sale.id,
                    "pid": sale.pid,
                    "product_name": product.product_name,
                    "quantity": sale.quantity,
                    "unit_price": sale.unit_price,
                    "total_amount": sale.quantity * sale.unit_price,
                    "user_id": current_user.id,
                    "company_id": current_company.id,
                    "status": sale.status,
                    "created_at": sale.created_at
                }
                for sale, product in sales_records
            ]
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# This is for cancelling a sale:    
@app.post("/sales/cancel/{transaction_id}", response_model=schemas.TransactionCancelResponse)
def cancel_sale(
    transaction_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get pending transaction for current company
        transaction = db.query(models.Transactions).filter(
            models.Transactions.id == transaction_id,
            models.Transactions.company_id == current_company.id,
            models.Transactions.status == "pending"
        ).first()

        if not transaction:
            raise HTTPException(status_code=404, detail="Pending transaction not found")

        # Update transaction status
        transaction.status = "cancelled"
        transaction.updated_at = datetime.utcnow()

        # Get and update associated sales
        sales = db.query(models.Sales).join(
            models.TransactionSales
        ).filter(
            models.TransactionSales.transaction_id == transaction_id,
            models.Sales.company_id == current_company.id
        ).all()

        for sale in sales:
            sale.status = "cancelled"

        db.commit()

        return {
            "message": "Sale cancelled successfully",
            "transaction": {
                "id": transaction.id,
                "status": "cancelled",
                "total_amount": transaction.total_amount,
                "updated_at": transaction.updated_at
            }
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sales/user/{user_id}", response_model=List[schemas.SaleSummary])
def get_user_sales(
    user_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        sales = db.query(
            models.Sales.id,
            models.Products.product_name,
            models.Sales.quantity,
            models.Sales.unit_price,
            models.Sales.created_at
        ).join(
            models.Products
        ).filter(
            models.Sales.user_id == user_id,
            models.Sales.company_id == current_company.id
        ).order_by(
            models.Sales.created_at.desc()
        ).all()

        return [
            {
                "id": sale.id,
                "product_name": sale.product_name,
                "quantity": sale.quantity,
                "unit_price": sale.unit_price,
                "total_amount": sale.quantity * sale.unit_price,
                "created_at": sale.created_at
            }
            for sale in sales
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sales", response_model=List[schemas.SaleListResponse])
def fetch_sales(
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        sales = db.query(
            models.Sales,
            models.Users.full_name,
            models.Products.product_name,
            models.Products.product_price
        ).join(
            models.Users
        ).join(
            models.Products
        ).filter(
            models.Sales.company_id == current_company.id
        ).order_by(
            models.Sales.created_at.desc()
        ).all()

        return [
            {
                "id": sale.Sales.id,
                "product_name": sale.product_name,
                "quantity": sale.Sales.quantity,
                "seller_name": sale.first_name,
                "total_amount": sale.Sales.quantity * sale.product_price,
                "created_at": sale.Sales.created_at
            }
            for sale in sales
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Route for getting sale by the sale id:
@app.get("/sales/{id}", status_code=status.HTTP_200_OK)
def fetch_sale(
    id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        sale = db.query(
            models.Sales,
            models.Products.product_name,
        ).join(
            models.Products
        ).filter(
            models.Sales.id == id,
            models.Sales.company_id == current_company.id
        ).first()

        if not sale:
            raise HTTPException(status_code=404, detail="Sale not found")

        return {
            "id": sale.Sales.id,
            "product_name": sale.product_name,
            "quantity": sale.Sales.quantity,
            "unit_price": sale.Sales.unit_price,
            "total_amount": sale.Sales.quantity * sale.Sales.unit_price,
            "status": sale.Sales.status,
            "created_at": sale.Sales.created_at
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Route for getting sales by user ID:
@app.get("/sales/user/{user_id}", status_code=status.HTTP_200_OK)
def fetch_sales_by_user(
    user_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        sales = db.query(
            models.Sales,
            models.Products.product_name
        ).join(
            models.Products
        ).filter(
            models.Sales.user_id == user_id,
            models.Sales.company_id == current_company.id
        ).order_by(
            models.Sales.created_at.desc()
        ).all()

        if not sales:
            raise HTTPException(status_code=404, detail="No sales found")

        return [
            {
                "id": sale.Sales.id,
                "product_name": sale.product_name,
                "quantity": sale.Sales.quantity,
                "unit_price": sale.Sales.unit_price,
                "total_amount": sale.Sales.quantity * sale.Sales.unit_price,
                "status": sale.Sales.status,
                "created_at": sale.Sales.created_at
            }
            for sale in sales
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Route for updating sales:
@app.put("/sales/{id}", response_model=schemas.SaleResponse)
def update_sale(
    id: int,
    request: schemas.SaleUpdate,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Get sale and product
        sale = db.query(models.Sales).filter(
            models.Sales.id == id,
            models.Sales.company_id == current_company.id
        ).first()
        
        if not sale:
            raise HTTPException(status_code=404, detail="Sale not found")

        product = db.query(models.Products).filter(
            models.Products.id == request.product_id,
            models.Products.company_id == current_company.id
        ).first()
        
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        # Check stock availability
        stock_change = request.quantity - sale.quantity
        if product.stock.stock_quantity < stock_change:
            raise HTTPException(status_code=400, detail="Insufficient stock")

        # Update sale and stock
        sale.quantity = request.quantity
        sale.unit_price = request.unit_price
        sale.pid = request.product_id
        product.stock.stock_quantity -= stock_change

        db.commit()
        
        return {
            "id": sale.id,
            "product_name": product.product_name,
            "quantity": sale.quantity,
            "unit_price": sale.unit_price,
            "total_amount": sale.quantity * sale.unit_price,
            "status": sale.status,
            "created_at": sale.created_at
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# Route for deleting a sale:
@app.delete("/sales/{sale_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_sale(
    sale_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Get sale for current company
        sale = db.query(models.Sales).filter(
            models.Sales.id == sale_id,
            models.Sales.company_id == current_company.id
        ).first()

        if not sale:
            raise HTTPException(status_code=404, detail="Sale not found")

        # Restore product stock
        product = db.query(models.Products).filter(
            models.Products.id == sale.pid,
            models.Products.company_id == current_company.id
        ).first()

        if product:
            product.stock.stock_quantity += sale.quantity

        # Delete sale
        db.delete(sale)
        db.commit()

        return None

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# The end for the Sale routes <<

# Start contact Routes >> 

@app.post("/contact", response_model=schemas.ContactResponse)
async def create_contact(
    contact: schemas.ContactCreate,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Create new contact record
        new_contact = models.Contact(
            name=contact.name,
            email=contact.email,
            subject=contact.subject,
            message=contact.message,
            company_id=current_company.id,
            status="open"
        )
        
        db.add(new_contact)
        db.commit()
        db.refresh(new_contact)

        # Send email notification
        await send_contact_email(
            name=contact.name,
            email=contact.email,
            subject=contact.subject,
            message=contact.message
        )

        return new_contact

    except Exception as e:
        db.rollback()
        print(f"Error creating contact: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error creating contact: {str(e)}"
        )

@app.post("/contact/{contact_id}/reply", response_model=schemas.ContactResponse)
async def reply_to_contact(
    contact_id: int,
    reply_data: schemas.ReplyCreate,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        contact = db.query(models.Contact).filter(
            models.Contact.id == contact_id,
            models.Contact.company_id == current_company.id
        ).first()
        
        if not contact:
            raise HTTPException(
                status_code=404,
                detail="Contact message not found in your company"
            )
        
        contact.response = reply_data.reply
        contact.status = "closed"
        contact.updated_at = datetime.utcnow()
        contact.responded_by = current_user.id
        
        # Add audit log
        models.AuditLog.log(
            db=db,
            action="reply_contact",
            entity_type="contact",
            entity_id=contact.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={"status": "closed"}
        )
        
        db.commit()
        db.refresh(contact)
        return contact
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/contact", response_model=List[schemas.ContactResponse])
async def get_contacts(
    status: Optional[str] = Query(None, enum=["open", "closed"]),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=100),
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    query = db.query(models.Contact).filter(
        models.Contact.company_id == current_company.id
    )
    
    if status:
        query = query.filter(models.Contact.status == status)
    
    contacts = query.order_by(models.Contact.created_at.desc())\
        .offset(skip)\
        .limit(limit)\
        .all()
    
    return contacts

@app.get("/contact/{contact_id}", response_model=schemas.ContactResponse)
async def get_contact(
    contact_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    contact = db.query(models.Contact).filter(
        models.Contact.id == contact_id,
        models.Contact.company_id == current_company.id
    ).first()
    
    if not contact:
        raise HTTPException(
            status_code=404,
            detail="Contact not found in your company"
        )
    return contact

@app.put("/contact/{contact_id}/status", response_model=schemas.ContactResponse)
async def update_contact_status(
    contact_id: int,
    status_data: schemas.StatusUpdate,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    contact = db.query(models.Contact).filter(
        models.Contact.id == contact_id,
        models.Contact.company_id == current_company.id
    ).first()
    
    if not contact:
        raise HTTPException(
            status_code=404,
            detail="Contact not found in your company"
        )
    
    old_status = contact.status
    contact.status = status_data.status
    contact.updated_at = datetime.utcnow()
    contact.updated_by = current_user.id
    
    # Add audit log
    models.AuditLog.log(
        db=db,
        action="update_contact_status",
        entity_type="contact",
        entity_id=contact.id,
        user_id=current_user.id,
        company_id=current_company.id,
        details={
            "old_status": old_status,
            "new_status": status_data.status
        }
    )
    
    db.commit()
    return contact

@app.delete("/contact/{contact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_contact(
    contact_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    contact = db.query(models.Contact).filter(
        models.Contact.id == contact_id,
        models.Contact.company_id == current_company.id
    ).first()
    
    if not contact:
        raise HTTPException(
            status_code=404,
            detail="Contact not found in your company"
        )
    
    # Add audit log before deletion
    models.AuditLog.log(
        db=db,
        action="delete_contact",
        entity_type="contact",
        entity_id=contact_id,
        user_id=current_user.id,
        company_id=current_company.id,
        details={"status": contact.status}
    )
    
    db.delete(contact)
    db.commit()
    return None

# The end for the Contact routes <<



@app.post("/import/products", response_model=schemas.ImportResponse)
async def import_products(
    file: UploadFile = File(...),
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    # Create import history record
    import_record = models.ImportHistory(
        filename=file.filename,
        status='processing',
        user_id=current_user.id,
        company_id=current_company.id
    )
    db.add(import_record)
    db.commit()

    try:
        # Read file content
        content = await file.read()
        
        # Process based on file type
        if file.filename.endswith('.csv'):
            df = pd.read_csv(io.StringIO(content.decode('utf-8')))
        elif file.filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(io.BytesIO(content))
        else:
            raise HTTPException(
                status_code=400,
                detail="Unsupported file format. Please upload CSV or Excel file."
            )

        # Validate required columns
        required_columns = ['product_name', 'product_price', 'selling_price', 'stock_quantity']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required columns: {', '.join(missing_columns)}"
            )

        # Update import record with total rows
        import_record.total_rows = len(df)
        db.commit()

        # Process records
        success_count = 0
        error_count = 0
        errors = []

        for index, row in df.iterrows():
            try:
                # Check if product already exists in this company
                existing_product = db.query(models.Products).filter(
                    models.Products.product_name == row['product_name'],
                    models.Products.company_id == current_company.id
                ).first()

                if existing_product:
                    # Update existing product
                    existing_product.product_price = row['product_price']
                    existing_product.selling_price = row['selling_price']
                    existing_product.stock.stock_quantity = row['stock_quantity']
                    existing_product.description = row.get('description')
                    existing_product.updated_at = datetime.utcnow()
                    existing_product.updated_by = current_user.id
                else:
                    # Create new product
                    new_product = models.Products(
                        product_name=row['product_name'],
                        product_price=row['product_price'],
                        selling_price=row['selling_price'],
                        description=row.get('description'),
                        company_id=current_company.id,
                        created_by=current_user.id
                    )
                    db.add(new_product)
                    db.flush()  # Ensure new_product.id is available

                    # Create stock entry
                    new_stock = models.ProductStock(
                        product_id=new_product.id,
                        stock_quantity=row['stock_quantity']
                    )
                    db.add(new_stock)

                success_count += 1
            except Exception as e:
                error_count += 1
                errors.append({
                    'row': index + 2,
                    'product_name': row['product_name'],
                    'error': str(e)
                })

        # Add audit log
        models.AuditLog.log(
            db=db,
            action="import_products",
            entity_type="import",
            entity_id=import_record.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "total_rows": len(df),
                "successful": success_count,
                "failed": error_count
            }
        )

        # Update import record with results
        import_record.status = 'completed'
        import_record.successful_rows = success_count
        import_record.failed_rows = error_count
        import_record.errors = errors
        import_record.completed_at = datetime.utcnow()
        
        db.commit()

        return {
            "import_id": import_record.id,
            "message": "Import completed",
            "total_processed": len(df),
            "successful": success_count,
            "failed": error_count,
            "errors": errors if errors else None,
            "company_id": current_company.id
        }

    except Exception as e:
        # Update import record with error status
        import_record.status = 'failed'
        import_record.errors = [{"error": str(e)}]
        import_record.completed_at = datetime.utcnow()
        db.commit()
        
        print(f"Import error in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Import failed: {str(e)}"
        )

@app.get("/import/template/{file_type}")
async def get_import_template(
    file_type: str,
    background_tasks: BackgroundTasks,
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Validate file type
        if file_type not in ['csv', 'excel']:
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Use 'csv' or 'excel'"
            )
        
        # Create sample data
        data = {
            'product_name': ['Sample Product 1', 'Sample Product 2'],
            'product_price': [100.00, 200.00],
            'selling_price': [150.00, 250.00],
            'stock_quantity': [50, 75],
            'description': ['Sample description 1', 'Sample description 2']
        }
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Create temporary file
        file_extension = 'xlsx' if file_type == 'excel' else 'csv'
        temp_file = f"temp_template_{current_company.id}.{file_extension}"
        
        # Save template
        if file_type == 'excel':
            df.to_excel(temp_file, index=False)
        else:
            df.to_csv(temp_file, index=False)
        
        # Add cleanup task
        background_tasks.add_task(os.remove, temp_file)
        
        # Add simple audit log
        models.AuditLog.log(
            db=next(database.get_db()),
            action="download_template",
            entity_type="import_template",
            entity_id=None,
            user_id=getattr(current_company, 'user_id', None),
            company_id=current_company.id,
            details={"file_type": file_type}
        )
        
        return FileResponse(
            path=temp_file,
            filename=f"product_import_template.{file_extension}",
            media_type='application/octet-stream'
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Error generating template"
        )

@app.post("/import/products/validate", response_model=schemas.ImportValidationResponse)
async def validate_import_file(
    file: UploadFile = File(...),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        content = await file.read()
        
        # Process based on file type
        if file.filename.endswith('.csv'):
            df = pd.read_csv(io.StringIO(content.decode('utf-8')))
        elif file.filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(io.BytesIO(content))
        else:
            raise HTTPException(
                status_code=400,
                detail="Please upload CSV or Excel file"
            )

        # Check required columns
        required_columns = ['product_name', 'product_price', 'selling_price', 'stock_quantity']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            return {
                "valid": False,
                "total_rows": 0,
                "errors": [{"message": f"Missing columns: {', '.join(missing_columns)}"}]
            }

        # Validate data
        errors = []
        for index, row in df.iterrows():
            row_errors = []
            
            # Check product name
            if pd.isna(row['product_name']) or str(row['product_name']).strip() == '':
                row_errors.append("Product name is required")
            
            # Check numbers
            for field in ['product_price', 'selling_price', 'stock_quantity']:
                try:
                    value = float(row[field])
                    if value < 0:
                        row_errors.append(f"{field} must be positive")
                except:
                    row_errors.append(f"Invalid {field}")
            
            if row_errors:
                errors.append({
                    "row": index + 2,
                    "product": str(row['product_name']),
                    "errors": row_errors
                })

        return {
            "valid": len(errors) == 0,
            "total_rows": len(df),
            "errors": errors if errors else None
        }

    except Exception as e:
        print(f"Validation error for company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error validating file"
        )

# Add endpoints to view import history
@app.get("/import/history", response_model=List[schemas.ImportHistoryResponse])
async def get_import_history(
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, le=100),
    status: Optional[str] = Query(None, enum=['processing', 'completed', 'failed'])
):
    # Build query with company filter
    query = db.query(models.ImportHistory)\
        .filter(models.ImportHistory.company_id == current_company.id)
    
    # Add status filter if provided
    if status:
        query = query.filter(models.ImportHistory.status == status)
    
    # Get records
    imports = query.order_by(models.ImportHistory.created_at.desc())\
        .offset(skip)\
        .limit(limit)\
        .all()
    
    return imports

@app.get("/import/history/{import_id}", response_model=schemas.ImportHistoryDetailResponse)
async def get_import_details(
    import_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    # Get record with company check
    import_record = db.query(models.ImportHistory)\
        .filter(
            models.ImportHistory.id == import_id,
            models.ImportHistory.company_id == current_company.id
        )\
        .first()
    
    if not import_record:
        raise HTTPException(
            status_code=404,
            detail="Import record not found in your company"
        )
    
    return import_record



# Start Vendor Routes >>
@app.post("/vendors", response_model=schemas.VendorResponse)
def create_vendor(
    vendor: schemas.VendorCreate, 
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user) 
):
    try:
        # Get user's company
        company = db.query(models.Company).filter(
            models.Company.id == current_user.company_id
        ).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="Company not found"
            )

        # Create vendor with company_id
        db_vendor = models.Vendor(
            name=vendor.name,
            contact_person=vendor.contact_person,
            email=vendor.email,
            phone=vendor.phone,
            address=vendor.address,
            company_id=company.id
        )
        
        db.add(db_vendor)
        db.commit()
        db.refresh(db_vendor)
        return db_vendor
        
    except Exception as e:
        db.rollback()
        print(f"Error creating vendor: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vendors", response_model=List[schemas.Vendor])
def get_vendors(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    vendors = db.query(models.Vendor).filter(
        models.Vendor.company_id == current_user.company_id
    ).offset(skip).limit(limit).all()
    
    return vendors

@app.get("/vendors", response_model=List[schemas.VendorResponse])
def get_vendors(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=100),
    search: Optional[str] = None,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Base query with company filter
        query = db.query(models.Vendor).filter(
            models.Vendor.company_id == current_company.id
        )
        
        # Add search if provided
        if search:
            query = query.filter(
                or_(
                    models.Vendor.name.ilike(f"%{search}%"),
                    models.Vendor.contact_person.ilike(f"%{search}%")
                )
            )
        
        # Get vendors with pagination
        vendors = query.order_by(models.Vendor.name)\
            .offset(skip)\
            .limit(limit)\
            .all()
        
        return vendors

    except Exception as e:
        print(f"Error fetching vendors for company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error fetching vendors"
        )

@app.get("/vendors/{vendor_id}", response_model=schemas.VendorResponse)
def get_vendor(
    vendor_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Get vendor with products
        vendor = db.query(models.Vendor).filter(
            models.Vendor.id == vendor_id,
            models.Vendor.company_id == current_company.id
        ).first()

        if not vendor:
            raise HTTPException(status_code=404, detail="Vendor not found")

        # Get vendor's products
        products = db.query(models.Products).filter(
            models.Products.vendor_id == vendor_id,
            models.Products.company_id == current_company.id
        ).all()

        return {
            "id": vendor.id,
            "name": vendor.name,
            "contact_person": vendor.contact_person,
            "email": vendor.email,
            "phone": vendor.phone,
            "address": vendor.address,
            "company_id": vendor.company_id,
            "created_by": vendor.created_by,
            "created_at": vendor.created_at,
            "updated_at": vendor.updated_at,
            "products": [
                {
                    "id": product.id,
                    "product_name": product.product_name,
                    "product_price": product.product_price,
                    "selling_price": product.selling_price,
                    "stock_quantity": product.stock.stock_quantity,
                    "created_at": product.created_at
                }
                for product in products
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/vendors/{vendor_id}", response_model=schemas.VendorResponse)
def update_vendor(
    vendor_id: int,
    vendor: schemas.VendorUpdate,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get vendor with company check
        db_vendor = db.query(models.Vendor).filter(
            models.Vendor.id == vendor_id,
            models.Vendor.company_id == current_company.id
        ).first()
        
        if not db_vendor:
            raise HTTPException(
                status_code=404,
                detail="Vendor not found in your company"
            )
        
        # Check if name is being updated and if it would cause a duplicate
        if vendor.name and vendor.name != db_vendor.name:
            existing = db.query(models.Vendor).filter(
                models.Vendor.name == vendor.name,
                models.Vendor.company_id == current_company.id,
                models.Vendor.id != vendor_id
            ).first()
            
            if existing:
                raise HTTPException(
                    status_code=400,
                    detail="Vendor with this name already exists in your company"
                )
        
        # Store old values for audit
        old_values = {
            "name": db_vendor.name,
            "contact_person": db_vendor.contact_person,
            "email": db_vendor.email,
            "phone": db_vendor.phone,
            "address": db_vendor.address
        }
        
        # Update vendor
        for key, value in vendor.dict(exclude_unset=True).items():
            setattr(db_vendor, key, value)
        
        db_vendor.updated_at = datetime.utcnow()
        db_vendor.updated_by = current_user.id
        
        # Add audit log
        models.AuditLog.log(
            db=db,
            action="update_vendor",
            entity_type="vendor",
            entity_id=vendor_id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "previous": old_values,
                "updated": vendor.dict(exclude_unset=True)
            }
        )
        
        db.commit()
        db.refresh(db_vendor)
        return db_vendor

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error updating vendor in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error updating vendor"
        )

@app.delete("/vendors/{vendor_id}", response_model=schemas.MessageResponse)
def delete_vendor(
    vendor_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Get vendor with company check
        vendor = db.query(models.Vendor).filter(
            models.Vendor.id == vendor_id,
            models.Vendor.company_id == current_company.id
        ).first()
        
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail="Vendor not found in your company"
            )
        
        # Check if vendor has products
        if db.query(models.Products).filter(models.Products.vendor_id == vendor_id).first():
            raise HTTPException(
                status_code=400,
                detail="Cannot delete vendor with associated products"
            )
        
        # Delete vendor
        db.delete(vendor)
        db.commit()
        
        return {"message": "Vendor deleted successfully"}

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Error deleting vendor"
        )

# The end for the Vendor routes <<


# Start MPESA Routes >>
print("Access Token: ",get_access_token())


# Start Company Routes >>   
@app.post("/companies", response_model=schemas.CompanyIDResponse)
async def create_company(
    company: schemas.CompanyCreate,
    plan_id: int,  # Accept plan_id as a query parameter
    db: Session = Depends(database.get_db)
):
    try:
        # Validate subscription plan
        plan = db.query(models.SubscriptionPlan).filter(
            models.SubscriptionPlan.id == plan_id
        ).first()
        if not plan:
            raise HTTPException(status_code=404, detail="Subscription plan not found")

        # Create new company without user context
        db_company = models.Company(
            name=company.name,
            phone=company.phone or "",
            email=company.email or "",
            location=company.location or "",
            description=company.description,
            status="active"
        )
        
        db.add(db_company)
        db.commit()
        db.refresh(db_company)
        
        # Create a subscription for the company
        subscription = models.Subscription(
            company_id=db_company.id,
            plan_id=plan.id,
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),  # Example: 30-day subscription
            status="active"
        )
        db.add(subscription)
        db.commit()
        
        # Log and return only the company ID
        company_id = db_company.id
        print(f"Created company with ID: {company_id}")
        return {"id": company_id}
        
    except Exception as e:
        db.rollback()
        print(f"Error creating company: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error creating company: {str(e)}"
        )

@app.get("/companies/me", response_model=schemas.CompanyResponse)
def get_my_company(
    db: Session = Depends(database.get_db)
):
    try:
        # Fetch the company without user context
        company = db.query(models.Company).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="No company found"
            )

        return company

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching company details: {str(e)}"
        )

@app.put("/companies/me", response_model=schemas.CompanyResponse)
def update_my_company(
    company_update: schemas.CompanyUpdate,
    db: Session = Depends(database.get_db)
):
    try:
        # Get active company without user context
        company = db.query(models.Company).filter(
            models.Company.status == "active"
        ).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="No active company found"
            )
        
        # Update company fields
        for key, value in company_update.dict(exclude_unset=True).items():
            setattr(company, key, value)
        
        company.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(company)
        return company

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Error updating company"
        )
# End Company Routes << 


# Start Subscription Routes >>  
@app.post("/subscription-plans", response_model=schemas.SubscriptionPlan)
def create_subscription_plan(
    plan: schemas.SubscriptionPlanCreate,
    db: Session = Depends(database.get_db)
):
    try:
        # Check if plan name already exists
        existing_plan = db.query(models.SubscriptionPlan).filter(
            models.SubscriptionPlan.name == plan.name
        ).first()
        
        if existing_plan:
            raise HTTPException(
                status_code=400,
                detail="A plan with this name already exists"
            )
        
        # Create new plan
        new_plan = models.SubscriptionPlan(**plan.dict())
        
        db.add(new_plan)
        db.commit()
        db.refresh(new_plan)
        
        return new_plan

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Error creating subscription plan"
        )

# Route for getting all subscription plans: 
@app.get("/subscription-plans", response_model=List[schemas.SubscriptionPlan])
def get_subscription_plans(
    db: Session = Depends(database.get_db)
):
    return db.query(models.SubscriptionPlan).all()

# Route for getting a specific subscription plan: 
@app.get("/subscription-plans/{plan_id}", response_model=schemas.SubscriptionPlan)
def get_subscription_plan(
    plan_id: int,
    db: Session = Depends(database.get_db)
):
    try:
        plan = db.query(models.SubscriptionPlan).filter(
            models.SubscriptionPlan.id == plan_id
        ).first()
        
        if not plan:
            raise HTTPException(
                status_code=404,
                detail="Subscription plan not found"
            )
        
        return plan
        
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error fetching subscription plan: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error fetching subscription plan"
        )

# Route for creating a subscription: 
@app.post("/subscriptions", response_model=schemas.SubscriptionResponse)
def create_subscription(
    subscription: schemas.SubscriptionCreate,
    db: Session = Depends(database.get_db)
):
    try:
        # Check if company exists
        company = db.query(models.Company).filter(
            models.Company.id == subscription.company_id
        ).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="Company not found"
            )
            
        # Check if plan exists
        plan = db.query(models.SubscriptionPlan).filter(
            models.SubscriptionPlan.id == subscription.plan_id
        ).first()
        
        if not plan:
            raise HTTPException(
                status_code=404,
                detail="Subscription plan not found"
            )
            
        # Check if there's already an active subscription
        active_subscription = db.query(models.Subscription).filter(
            models.Subscription.company_id == subscription.company_id,
            models.Subscription.status == "active"
        ).first()
        
        if active_subscription:
            raise HTTPException(
                status_code=400,
                detail="Company already has an active subscription"
            )
            
        # Create new subscription
        new_subscription = models.Subscription(
            company_id=subscription.company_id,
            plan_id=subscription.plan_id,
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),  # 30-day subscription
            status="active"
        )
        
        db.add(new_subscription)
        db.commit()
        db.refresh(new_subscription)
        
        return new_subscription
        
    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error creating subscription: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error creating subscription"
        )

# Route for getting the current user's subscription:    
@app.get("/subscriptions/me", response_model=schemas.Subscription)
def get_my_subscription(
    db: Session = Depends(database.get_db)
):
    try:
        # Get active subscription with plan details
        subscription = db.query(models.Subscription)\
            .options(joinedload(models.Subscription.plan))\
            .filter(
                models.Subscription.status == "active"
            )\
            .first()
        
        if not subscription:
            raise HTTPException(
                status_code=404,
                detail="No active subscription found"
            )
        
        return subscription

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error fetching subscription: {str(e)}")  # Add logging
        raise HTTPException(
            status_code=500,
            detail="Error fetching subscription"
        )




@app.post("/stk-push", response_model=schemas.STKPushResponse)
async def initiate_stk_push(
    transaction: schemas.STKPushCreate,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Format phone number using existing utility
        try:
            formatted_phone = format_phone_number(transaction.phone_number)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Get MPESA access token
        access_token = await get_access_token()
        if not access_token:
            raise HTTPException(status_code=500, detail="Failed to get MPESA token")

        # Send STK Push
        result = await initiate_stk_push_request(
            phone_number=formatted_phone,
            amount=transaction.amount,
            access_token=access_token
        )

        # Save transaction
        mpesa_tx = models.MPESATransaction(
            checkout_request_id=result["CheckoutRequestID"],
            merchant_request_id=result["MerchantRequestID"],
            phone_number=formatted_phone,
            amount=transaction.amount,
            status="PENDING",
            company_id=current_company.id
        )
        db.add(mpesa_tx)
        db.commit()

        return {
            "checkout_request_id": result["CheckoutRequestID"],
            "merchant_request_id": result["MerchantRequestID"],
            "status": "pending",
            "message": "Please complete payment on your phone"
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stk-push/status", response_model=schemas.STKPushCheckResponse)
async def check_stk_push_status(
    merchant_request_id: str,
    checkout_request_id: str,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Get transaction
        transaction = db.query(models.MPESATransaction).filter(
            models.MPESATransaction.merchant_request_id == merchant_request_id.strip(),
            models.MPESATransaction.checkout_request_id == checkout_request_id.strip(),
            models.MPESATransaction.company_id == current_company.id
        ).first()
        
        if not transaction:
            return {
                "success": False,
                "status": "NOT_FOUND",
                "message": "Transaction not found"
            }
        
        return {
            "success": transaction.status == "COMPLETED",
            "status": transaction.status,
            "message": f"Payment {transaction.status.lower()}"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/stk-push/callback", response_model=schemas.CallbackResponse)
async def stk_push_callback(
    callback_data: schemas.MPESACallback,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Find transaction
        transaction = db.query(models.MPESATransaction).filter(
            models.MPESATransaction.checkout_request_id == callback_data.CheckoutRequestID.strip(),
            models.MPESATransaction.company_id == current_company.id
        ).first()
        
        if not transaction:
            raise HTTPException(status_code=404, detail="Transaction not found")

        # Update only essential fields
        transaction.status = (
            models.MPESAStatus.COMPLETED if callback_data.ResultCode == 0 
            else models.MPESAStatus.FAILED
        )
        transaction.result_code = str(callback_data.ResultCode)
        transaction.result_desc = callback_data.ResultDesc
        
        db.commit()

        return {
            "success": True,
            "message": f"Payment {transaction.status.value}"
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/subscription/status", response_model=schemas.SubscriptionStatusResponse)
def check_subscription_status(
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get user's company
        company = db.query(models.Company).filter(
            models.Company.id == current_user.company_id
        ).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="No company found for this user"
            )

        # Get subscription with plan details
        subscription = db.query(models.Subscription)\
            .options(joinedload(models.Subscription.plan))\
            .filter(
                models.Subscription.company_id == company.id,
                models.Subscription.status == "active"
            ).first()

        if not subscription:
            return {
                "is_active": False,
                "message": "No active subscription found",
                "days_remaining": 0,
                "expiration_date": None,
                "plan_name": None,
                "subscription_status": "inactive"
            }

        # Calculate days remaining
        now = datetime.now(timezone.utc)
        days_remaining = (subscription.end_date - now).days

        # Determine status message based on days remaining
        if days_remaining < 0:
            status_message = "Your subscription has expired"
            is_active = False
        elif days_remaining <= 7:
            status_message = f"Your subscription will expire in {days_remaining} days"
            is_active = True
        else:
            status_message = f"Your subscription is active"
            is_active = True

        return {
            "is_active": is_active,
            "message": status_message,
            "days_remaining": max(0, days_remaining),
            "expiration_date": subscription.end_date,
            "plan_name": subscription.plan.name if subscription.plan else None,
            "subscription_status": subscription.status
        }

    except Exception as e:
        print(f"Error checking subscription status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error checking subscription status"
        )

@app.post("/public/subscribe-after-register", response_model=schemas.SubscriptionResponse)
async def subscribe_after_register(
    subscription_data: schemas.PostRegisterSubscription,
    db: Session = Depends(database.get_db)
):
    try:
        # Ensure plan_id is provided
        if not hasattr(subscription_data, 'plan_id'):
            raise HTTPException(status_code=400, detail="Subscription plan ID is required")

        # Fetch the subscription plan
        plan = db.query(models.SubscriptionPlan).filter(
            models.SubscriptionPlan.id == subscription_data.plan_id
        ).first()

        if not plan:
            raise HTTPException(status_code=404, detail="Subscription plan not found")

        # Use a default duration if duration_days is not available
        duration_days = 30  # Default to 30 days

        # Create the subscription
        subscription = models.Subscription(
            company_id=subscription_data.company_id,
            plan_id=subscription_data.plan_id,
            start_date=datetime.now(timezone.utc),
            end_date=datetime.now(timezone.utc) + timedelta(days=duration_days),
            status="active"
        )
        
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        
        return subscription

    except Exception as e:
        db.rollback()
        print(f"Error creating subscription: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating subscription: {str(e)}")

# Add this endpoint to check subscription details
@app.get("/debug/subscription/{company_id}")
async def debug_subscription(
    company_id: int,
    db: Session = Depends(database.get_db)
):
    subscription = db.query(models.Subscription).filter(
        models.Subscription.company_id == company_id
    ).first()
    
    if not subscription:
        return {
            "status": "No subscription found",
            "company_id": company_id
        }
    
    return {
        "id": subscription.id,
        "company_id": subscription.company_id,
        "plan_id": subscription.plan_id,
        "status": subscription.status,
        "start_date": subscription.start_date,
        "end_date": subscription.end_date,
        "current_time": datetime.now(timezone.utc)
    }

@app.post("/forgot-password", response_model=schemas.MessageResponse)
async def forgot_password(
    request: schemas.PasswordResetRequest,
    db: Session = Depends(database.get_db)
):
    try:
        print(f"Received password reset request for email: {request.email}")
        
        # Check if user exists
        user = db.query(models.Users).filter(models.Users.email == request.email).first()
        if user:
            print(f"User found with email: {request.email}")
            token = create_password_reset_token(request.email)
            base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
            
            # Print configuration for debugging
            print("Email Configuration:")
            print(f"MAIL_USERNAME: {os.getenv('MAIL_USERNAME')}")
            print(f"MAIL_FROM: {os.getenv('MAIL_FROM')}")
            print(f"FRONTEND_URL: {base_url}")
            
            try:
                await send_password_reset_email(request.email, token, base_url)
                print(f"Password reset email sent successfully to {request.email}")
                return {
                    "message": "Password reset email sent successfully",
                    "status": True,
                    "data": None
                }
            except Exception as email_error:
                print(f"Error sending email: {str(email_error)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error sending email: {str(email_error)}"
                )
        else:
            print(f"No user found with email: {request.email}")
        
        return {
            "message": "If an account with that email exists, we have sent a password reset link",
            "status": True,
            "data": None
        }
        
    except Exception as e:
        print(f"Error in forgot_password endpoint: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/reset-password", response_model=schemas.MessageResponse)
async def reset_password(
    request: schemas.PasswordReset,
    db: Session = Depends(database.get_db)
):
    email = verify_password_reset_token(request.token)
    if reset_user_password(db, email, request.new_password):
        return {"message": "Password updated successfully"}
    
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Failed to reset password"
    )

@app.post("/payments/initiate", response_model=schemas.PaymentResponse1)
def initiate_payment(
    payment_request: schemas.PaymentRequest,
    db: Session = Depends(database.get_db),
    current_user: models.Users = Depends(get_current_user)
):
    # Validate payment amount
    if payment_request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than zero")

    # Retrieve the user's company
    if not current_user.company_id:
        raise HTTPException(status_code=404, detail="User does not have an associated company")

    company_id = current_user.company_id

    # Check if the company exists
    company = db.query(models.Company).filter(models.Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    # Create a new payment record with status "PENDING"
    new_payment = models.Payment(
        amount=payment_request.amount,
        mode="mpesa",  # Assuming a default mode, adjust as needed
        payment_type="SALE",  # Assuming a default type, adjust as needed
        status=models.PaymentStatus.PENDING,
        created_at=datetime.utcnow(),
        company_id=company_id
    )
    
    db.add(new_payment)
    db.commit()
    db.refresh(new_payment)

    return schemas.PaymentResponse1(
        amount=new_payment.amount,
        phone=payment_request.phone
    )


@app.post("/payments/confirm", response_model=schemas.TransactionResponse)
def confirm_payment_and_create_sale(
    payment_id: int,
    sale: schemas.CartSaleCreate,
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Retrieve the payment record
        payment = db.query(models.Payment).filter(
            models.Payment.id == payment_id,
            models.Payment.status == models.PaymentStatus.COMPLETED
        ).first()

        if not payment:
            raise HTTPException(status_code=400, detail="Payment not completed or not found")

        # Initialize total amount
        total_amount = 0
        sales_records = []

        # Process each item in the cart
        for item in sale.cart_items:
            # Get product for current company
            product = db.query(models.Products).filter(
                models.Products.id == item.product_id,
                models.Products.company_id == current_user.company_id
            ).first()
            
            if not product:
                raise HTTPException(
                    status_code=404,
                    detail=f"Product {item.product_id} not found in your company"
                )

            # Validate stock
            if product.stock.stock_quantity < item.quantity:
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient stock for {product.product_name}"
                )

            # Calculate item total and update total amount
            item_total = item.quantity * item.selling_price
            total_amount += item_total

            # Create sale record
            sale_record = models.Sales(
                pid=product.id,
                quantity=item.quantity,
                unit_price=item.selling_price,
                user_id=current_user.id,
                company_id=current_user.company_id,
                status="completed"
            )
            db.add(sale_record)
            db.flush()  # Get the sale_record ID
            sales_records.append((sale_record, product))

            # Update product stock
            product.stock.stock_quantity -= item.quantity

        # Create transaction record
        transaction = models.Transactions(
            user_id=current_user.id,
            company_id=current_user.company_id,
            total_amount=total_amount,
            status="completed"
        )
        db.add(transaction)
        db.flush()

        # Link sales to transaction
        for sale_record, _ in sales_records:
            db.add(models.TransactionSales(
                transaction_id=transaction.id,
                sale_id=sale_record.id,
                company_id=current_user.company_id
            ))

        # Commit all changes
        db.commit()

        # Return formatted response
        return {
            "id": transaction.id,
            "total_amount": total_amount,
            "status": "completed",
            "created_at": transaction.created_at,
            "company_id": current_user.company_id,
            "sales": [
                {
                    "id": sale.id,
                    "pid": sale.pid,
                    "product_name": product.product_name,
                    "quantity": sale.quantity,
                    "unit_price": sale.unit_price,
                    "total_amount": sale.quantity * sale.unit_price,
                    "user_id": current_user.id,
                    "company_id": current_user.company_id,
                    "status": sale.status,
                    "created_at": sale.created_at
                }
                for sale, product in sales_records
            ]
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))    







# @app.post("/companies/create-with-plan", response_model=schemas.CompanyResponse)
# def create_company_with_plan(
#     company_data: schemas.CompanyCreateWithPlan,
#     db: Session = Depends(database.get_db),
#     current_user: schemas.UserResponse = Depends(get_current_user)
# ):
#     try:
#         existing_company = db.query(models.Company).filter(
#             models.Company.email == company_data.email
#         ).first()
#         if existing_company:
#             raise HTTPException(status_code=400, detail="Company with this email already exists")

#         plan = db.query(models.SubscriptionPlan).filter(
#             models.SubscriptionPlan.id == company_data.plan_id
#         ).first()
#         if not plan:
#             raise HTTPException(status_code=404, detail="Subscription plan not found")

#         new_company = models.Company(
#             name=company_data.name,
#             phone=company_data.phone,
#             email=company_data.email,
#             location=company_data.location,
#             description=company_data.description,
#             status="active",
#             user_id=current_user.id
#         )
#         db.add(new_company)
#         db.commit()
#         db.refresh(new_company)

#         new_subscription = models.Subscription(
#             company_id=new_company.id,
#             plan_id=plan.id,
#             start_date=datetime.utcnow(),
#             end_date=datetime.utcnow() + timedelta(days=30),
#             status=models.SubscriptionStatus.ACTIVE.value
#         )
#         db.add(new_subscription)
#         db.commit()

#         return new_company

#     except IntegrityError:
#         db.rollback()
#         raise HTTPException(status_code=400, detail="Integrity error: possible duplicate entry")
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(status_code=500, detail=f"Error creating company with plan: {str(e)}")

@app.get("/companies/{company_id}", response_model=schemas.CompanyResponse)
def get_company_details(
    company_id: int,
    db: Session = Depends(database.get_db)
):
    try:
        # Fetch the company by ID
        company = db.query(models.Company).filter(models.Company.id == company_id).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="Company not found"
            )

        return company

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching company details: {str(e)}"
        )



# Create a company with a free trial    
@app.post("/companies/free-trial", response_model=schemas.CompanyResponse)
async def create_company_with_free_trial(
    company_data: schemas.CompanyCreate,
    db: Session = Depends(database.get_db)
):
    try:
        # Check if a company with the same email already exists
        existing_company = db.query(models.Company).filter(
            models.Company.email == company_data.email
        ).first()
        if existing_company:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A company with this email already exists"
            )

        # Create the new company
        new_company = models.Company(
            name=company_data.name,
            phone=company_data.phone,
            email=company_data.email,
            location=company_data.location,
            description=company_data.description,
            status="active"
        )
        db.add(new_company)
        db.commit()
        db.refresh(new_company)

        # Assign a free trial subscription
        free_trial_plan = db.query(models.SubscriptionPlan).filter(
            models.SubscriptionPlan.name == "Free Trial"
        ).first()
        if not free_trial_plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Free trial plan not found"
            )

        free_trial_subscription = models.Subscription(
            company_id=new_company.id,
            plan_id=free_trial_plan.id,
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=1),  
            status="active"
        )
        db.add(free_trial_subscription)
        db.commit()

        return new_company

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating company with free trial: {str(e)}"
        )

# Get free trial status for a company   
@app.get("/companies/{company_id}/free-trial", response_model=schemas.FreeTrialResponse)
async def get_free_trial_status(company_id: int, db: Session = Depends(database.get_db)):
    try:
        subscription = db.query(models.Subscription).filter(
            models.Subscription.company_id == company_id,
            models.Subscription.status == "active"
        ).first()

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Active subscription not found"
            )

        now = datetime.utcnow()
        if subscription.end_date < now:
            return {"is_trial": False, "days_left": 0}  # Changed to days_left

        remaining_time = subscription.end_date - now
        days_left = remaining_time.days  # Calculate days left

        return {"is_trial": True, "days_left": days_left}  # Changed to days_left

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving free trial status: {str(e)}"
        )
