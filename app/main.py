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
from app.auth import get_password_hash, authenticate_user, verify_refresh_token, create_access_token, create_refresh_token, get_current_user
from fastapi.middleware.cors import CORSMiddleware
# from app.schemas import ProductCreate, VendorCreate, VendorUpdate, Vendor , STKPushCreate, STKPushResponse

from app.schemas import *

from pydantic import ValidationError
from sqlalchemy.orm import joinedload

# from app.models import STKPush
from app.utils.mpesa import *
# from app.mpesa_config import *

from app.dependencies import get_current_company, get_current_user



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
async def register(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    try:
        # Check if email exists
        existing_user = db.query(models.Users).filter(
            models.Users.email == user.email.lower()
        ).first()
        
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create company first
        company = models.Company(
            name=f"{user.first_name}'s Company",
            email=user.email,
            phone=user.phone,
            location="Default Location"
        )
        db.add(company)
        db.flush()

        # Check if this is the first user in the company
        is_first_user = not db.query(models.Users).filter(
            models.Users.company_id == company.id
        ).first()

        # Create user with company relationship
        db_user = models.Users(
            email=user.email.lower(),
            first_name=user.first_name.strip(),
            last_name=user.last_name.strip(),
            phone=user.phone,
            password=get_password_hash(user.password),
            company_id=company.id,
            company_role='owner',
            is_admin=is_first_user  # Only first user becomes admin
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        return db_user
            
    except Exception as e:
        db.rollback()
        print(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login", response_model=schemas.TokenResponse)
async def login(user_credentials: schemas.UserLogin, db: Session = Depends(database.get_db)):
    user = authenticate_user(db, user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )
    
    access_token_data = create_access_token({"user": user.email})
    refresh_token_data = create_refresh_token({"user": user.email})
    
    return {
        "access_token": access_token_data["token"],
        "access_token_expires": access_token_data["expires_at"],
        "refresh_token": refresh_token_data["token"],
        "refresh_token_expires": refresh_token_data["expires_at"],
        "token_type": "bearer"
    }

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
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone": user.phone,
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
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    # Fetch fresh user data from database to ensure we have all fields
    user = db.query(models.Users).filter(models.Users.id == current_user.id).first()
    
    # Convert None to False for is_admin field
    if user.is_admin is None:
        user.is_admin = False
        db.commit()
        db.refresh(user)
    
    # Ensure company_role has a default value if None
    if user.company_role is None:
        user.company_role = "user"
        db.commit()
        db.refresh(user)
    
    # Ensure is_admin is boolean before returning
    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "phone": user.phone,
        "is_admin": bool(user.is_admin),
        "company_role": user.company_role,  # Added this line
        "created_at": user.created_at,
        "updated_at": user.updated_at
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
# Define base directory for the app
BASE_DIR = Path("/code/app")
UPLOAD_DIR = BASE_DIR / "uploads"

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Mount static files directory - use absolute path
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

# Helper function to handle file upload
async def save_upload_file(
    upload_file: UploadFile,
    company_id: int
) -> str:
    try:
        # Create company-specific directory
        company_upload_dir = f"uploads/company_{company_id}/products"
        os.makedirs(company_upload_dir, exist_ok=True)
        
        # Generate unique filename
        file_extension = Path(upload_file.filename).suffix
        unique_filename = f"{uuid4()}{file_extension}"
        
        # Create full file path
        file_path = os.path.join(company_upload_dir, unique_filename)
        
        # Save file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
        
        # Return relative path for database storage
        return f"/static/company_{company_id}/products/{unique_filename}"
        
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
    stock_quantity: int = Form(...),
    vendor_id: int = Form(...),
    description: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
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

        # Create product data dict with company_id
        product_data = {
            "product_name": product_name.strip(),
            "product_price": product_price,
            "selling_price": selling_price,
            "stock_quantity": stock_quantity,
            "vendor_id": vendor_id,
            "description": description.strip() if description else None,
            "image_url": DEFAULT_IMAGE_PATH,
            "company_id": current_company.id  
        }

        # Handle image upload if provided
        if image and image.filename:
            if not image.content_type.startswith("image/"):
                raise HTTPException(status_code=400, detail="File must be an image")
            
            # Include company ID in the file path for better organization
            image_url = await save_upload_file(
                image, 
                company_id=current_company.id
            )
            product_data["image_url"] = image_url

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
        
        # Add to audit log
        audit_log = models.AuditLog(
            action="create_product",
            entity_type="product",
            entity_id=new_product.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "product_name": product_name,
                "price": product_price,
                "selling_price": selling_price
            }
        )
        db.add(audit_log)
        
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


@app.get("/products")
def fetch_products(
    skip: int = Query(default=0, description="Number of records to skip"),
    limit: int = Query(default=100, description="Maximum number of records to return"),
    search: Optional[str] = Query(None, description="Search products by name"),
    sort_by: Optional[str] = Query(None, description="Sort field"),
    sort_order: Optional[str] = Query("asc", description="Sort direction (asc/desc)"),
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Start with base query for current company
        query = db.query(models.Products)\
            .filter(models.Products.company_id == current_company.id)\
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
        for product in products:
            product_dict = {
                "id": product.id,
                "product_name": product.product_name,
                "product_price": product.product_price,
                "selling_price": product.selling_price,
                "stock_quantity": product.stock_quantity,
                "description": product.description,
                "image_url": product.image_url,
                "created_at": product.created_at,
                "updated_at": product.updated_at,
                "vendor_id": product.vendor_id,
                "company_id": product.company_id,
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
            "has_more": total_count > (skip + limit)
        }

    except Exception as e:
        print(f"Error fetching products for company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching products: {str(e)}"
        )

    finally:
        # Add to audit log
        try:
            audit_log = models.AuditLog(
                action="fetch_products",
                entity_type="products",
                user_id=current_user.id,
                company_id=current_company.id,
                details={
                    "search": search,
                    "sort_by": sort_by,
                    "sort_order": sort_order,
                    "results_count": len(formatted_products)
                }
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            print(f"Error logging product fetch: {str(e)}")
            db.rollback()

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
            "stock_quantity": product.stock_quantity,
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
    except HTTPException:
        raise
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
    stock_quantity: int = Form(...),
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
        product.stock_quantity = int(stock_quantity)
        if description is not None:
            product.description = description.strip()
        
        product.updated_at = datetime.utcnow()

        # Add audit log
        audit_log = models.AuditLog(
            action="update_product",
            entity_type="product",
            entity_id=product.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "previous_values": {
                    "product_name": product.product_name,
                    "product_price": product.product_price,
                    "selling_price": product.selling_price,
                    "stock_quantity": product.stock_quantity
                },
                "new_values": {
                    "product_name": product_name,
                    "product_price": product_price,
                    "selling_price": selling_price,
                    "stock_quantity": stock_quantity
                }
            }
        )
        db.add(audit_log)

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
                "stock_quantity": product.stock_quantity,
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
        
        # Add audit log
        audit_log = models.AuditLog(
            action="remove_product_image",
            entity_type="product",
            entity_id=product.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "previous_image_url": product.image_url
            }
        )
        db.add(audit_log)
        
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

        # Store product info for audit log
        product_info = {
            "id": product.id,
            "product_name": product.product_name,
            "product_price": product.product_price,
            "selling_price": product.selling_price,
            "stock_quantity": product.stock_quantity
        }

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

        # Add audit log before deletion
        audit_log = models.AuditLog(
            action="delete_product",
            entity_type="product",
            entity_id=product.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "deleted_product": product_info
            }
        )
        db.add(audit_log)

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
        print(f"Processing sale for company {current_company.id}")  # Debug log
        
        # First validate all products and calculate total
        sales_to_create = []
        total_amount = 0

        for item in sale.cart_items:
            # Query product with company check
            product = db.query(models.Products).filter(
                models.Products.id == item.product_id,
                models.Products.company_id == current_company.id
            ).first()
            
            if not product:
                raise HTTPException(
                    status_code=404,
                    detail=f"Product with ID {item.product_id} not found in your company"
                )

            # Check stock
            if product.stock_quantity < item.quantity:
                raise HTTPException(
                    status_code=400,
                    detail=f"Not enough stock for {product.product_name}. Available: {product.stock_quantity}"
                )

            # Store product info for later
            sales_to_create.append({
                "product": product,
                "quantity": item.quantity,
                "unit_price": item.selling_price
            })
            
            total_amount += (item.quantity * item.selling_price)

        # Create transaction record with company context
        transaction = models.Transactions(
            user_id=current_user.id,
            company_id=current_company.id,
            total_amount=total_amount,
            status="pending"
        )
        db.add(transaction)
        db.flush()

        # Create sales records with company context
        sales_records = []
        for item in sales_to_create:
            new_sale = models.Sales(
                pid=item["product"].id,
                quantity=item["quantity"],
                unit_price=item["unit_price"],
                user_id=current_user.id,
                company_id=current_company.id,
                status="pending"
            )
            db.add(new_sale)
            db.flush()
            sales_records.append(new_sale)

            # Update product stock
            item["product"].stock_quantity -= item["quantity"]

            # Create transaction_sales relationship
            trans_sale = models.TransactionSales(
                transaction_id=transaction.id,
                sale_id=new_sale.id,
                company_id=current_company.id
            )
            db.add(trans_sale)

        # Add audit log
        models.AuditLog.log(
            db=db,
            action="create_sale",
            entity_type="transaction",
            entity_id=transaction.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "total_amount": total_amount,
                "items_count": len(sales_records),
                "products": [
                    {
                        "id": item["product"].id,
                        "name": item["product"].product_name,
                        "quantity": item["quantity"],
                        "unit_price": item["unit_price"]
                    }
                    for item in sales_to_create
                ]
            }
        )

        # Commit all changes
        db.commit()

        # Format response
        return {
            "id": transaction.id,
            "total_amount": total_amount,
            "status": transaction.status,
            "created_at": transaction.created_at,
            "company_id": current_company.id,
            "sales": [
                {
                    "id": sale.id,
                    "pid": sale.pid,
                    "product_name": item["product"].product_name,
                    "quantity": sale.quantity,
                    "unit_price": sale.unit_price,
                    "total_amount": sale.quantity * sale.unit_price,
                    "user_id": current_user.id,
                    "company_id": current_company.id,
                    "status": sale.status,
                    "created_at": sale.created_at
                }
                for sale, item in zip(sales_records, sales_to_create)
            ]
        }

    except HTTPException as he:
        print(f"HTTP Exception in company {current_company.id}: {he.detail}")
        db.rollback()
        raise he
    except Exception as e:
        print(f"Unexpected error in company {current_company.id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )

@app.post("/confirm-payment/{transaction_id}")
def confirm_payment(
    transaction_id: int,
    payment_info: schemas.PaymentConfirmation,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get the transaction with company check
        transaction = db.query(models.Transactions).filter(
            models.Transactions.id == transaction_id,
            models.Transactions.company_id == current_company.id
        ).first()

        if not transaction:
            raise HTTPException(
                status_code=404,
                detail="Transaction not found in your company"
            )

        if transaction.status != "pending":
            raise HTTPException(
                status_code=400,
                detail=f"Transaction is already {transaction.status}"
            )

        # Get all associated sales with company check
        sales = db.query(models.Sales).join(
            models.TransactionSales
        ).filter(
            models.TransactionSales.transaction_id == transaction_id,
            models.Sales.company_id == current_company.id
        ).all()

        # Track changes for audit log
        stock_changes = []

        # Update product quantities and sale status
        for sale in sales:
            product = db.query(models.Products).filter(
                models.Products.id == sale.pid,
                models.Products.company_id == current_company.id
            ).first()
            
            if not product:
                raise HTTPException(
                    status_code=404,
                    detail=f"Product not found in your company"
                )
            
            # Recheck stock availability
            if product.stock_quantity < sale.quantity:
                raise HTTPException(
                    status_code=400,
                    detail=f"Not enough stock for product {product.product_name}"
                )
            
            # Track stock change
            stock_changes.append({
                "product_id": product.id,
                "product_name": product.product_name,
                "previous_stock": product.stock_quantity,
                "quantity_sold": sale.quantity,
                "new_stock": product.stock_quantity - sale.quantity
            })
            
            # Update product stock
            product.stock_quantity -= sale.quantity
            
            # Update sale status
            sale.status = "completed"

        # Create payment record with company context
        payment = models.Payment(
            sale_id=sales[0].id,
            amount=transaction.total_amount,
            mode=payment_info.payment_mode,
            transaction_code=payment_info.transaction_code,
            company_id=current_company.id,
            user_id=current_user.id
        )
        db.add(payment)

        # Update transaction status
        transaction.status = "completed"
        transaction.updated_at = datetime.utcnow()

        # Add audit log
        models.AuditLog.log(
            db=db,
            action="confirm_payment",
            entity_type="transaction",
            entity_id=transaction.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "payment_info": {
                    "amount": transaction.total_amount,
                    "mode": payment_info.payment_mode,
                    "transaction_code": payment_info.transaction_code
                },
                "stock_changes": stock_changes,
                "sales_completed": len(sales)
            }
        )

        db.commit()

        return {
            "message": "Payment confirmed and sales completed successfully",
            "transaction": {
                "id": transaction.id,
                "total_amount": transaction.total_amount,
                "status": transaction.status,
                "company_id": current_company.id,
                "payment": {
                    "mode": payment.mode,
                    "transaction_code": payment.transaction_code,
                    "created_at": payment.created_at
                },
                "sales_count": len(sales),
                "updated_at": transaction.updated_at
            }
        }

    except HTTPException as he:
        db.rollback()
        print(f"Error confirming payment in company {current_company.id}: {he.detail}")
        raise he
    except Exception as e:
        db.rollback()
        print(f"Unexpected error in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error confirming payment: {str(e)}"
        )

# This is for confirming a sale:    
@app.post("/sales/confirm/{transaction_id}", response_model=schemas.SaleConfirmationResponse)
def confirm_sale(
    transaction_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Fetch the pending transaction with company check
        transaction = db.query(models.Transactions).filter(
            models.Transactions.id == transaction_id,
            models.Transactions.status == "pending",
            models.Transactions.company_id == current_company.id
        ).first()

        if not transaction:
            raise HTTPException(
                status_code=404,
                detail="Pending transaction not found in your company"
            )

        # Get associated sales from transaction_sales
        sales_items = db.query(models.Sales).join(
            models.TransactionSales,
            models.TransactionSales.sale_id == models.Sales.id
        ).filter(
            models.TransactionSales.transaction_id == transaction_id,
            models.Sales.company_id == current_company.id
        ).all()

        if not sales_items:
            raise HTTPException(
                status_code=404,
                detail="No sales items found for this transaction"
            )

        # Track changes for audit log
        stock_updates = []

        # Update stock for each sale
        for sale in sales_items:
            product = db.query(models.Products).filter(
                models.Products.id == sale.pid,
                models.Products.company_id == current_company.id
            ).first()

            if not product:
                raise HTTPException(
                    status_code=404,
                    detail=f"Product with ID {sale.pid} not found in your company"
                )

            # Recheck stock availability
            if product.stock_quantity < sale.quantity:
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient stock for product {product.product_name}"
                )

            # Track stock change
            stock_updates.append({
                "product_id": product.id,
                "product_name": product.product_name,
                "previous_stock": product.stock_quantity,
                "quantity_sold": sale.quantity,
                "new_stock": product.stock_quantity - sale.quantity
            })

            # Update product stock
            product.stock_quantity -= sale.quantity
            
            # Update sale status
            sale.status = "completed"
            sale.updated_at = datetime.utcnow()

        # Update transaction status
        transaction.status = "completed"
        transaction.updated_at = datetime.utcnow()

        # Add audit log
        models.AuditLog.log(
            db=db,
            action="confirm_sale",
            entity_type="transaction",
            entity_id=transaction.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "transaction_amount": transaction.total_amount,
                "sales_count": len(sales_items),
                "stock_updates": stock_updates
            }
        )
        
        # Commit all changes
        db.commit()

        return {
            "message": "Sale confirmed successfully",
            "transaction": {
                "id": transaction.id,
                "status": transaction.status,
                "total_amount": transaction.total_amount,
                "company_id": current_company.id,
                "created_at": transaction.created_at,
                "updated_at": transaction.updated_at
            },
            "sales": [
                {
                    "id": sale.id,
                    "product_id": sale.pid,
                    "quantity": sale.quantity,
                    "unit_price": sale.unit_price,
                    "total": sale.quantity * sale.unit_price,
                    "status": sale.status
                }
                for sale in sales_items
            ],
            "stock_updates": stock_updates
        }

    except HTTPException as he:
        db.rollback()
        print(f"Error confirming sale in company {current_company.id}: {he.detail}")
        raise he
    except Exception as e:
        db.rollback()
        print(f"Unexpected error in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error confirming sale: {str(e)}"
        )

# This is for cancelling a sale:    
@app.post("/sales/cancel/{transaction_id}", response_model=schemas.TransactionCancelResponse)
def cancel_sale(
    transaction_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get transaction with company check
        transaction = db.query(models.Transactions).filter(
            models.Transactions.id == transaction_id,
            models.Transactions.status == "pending",
            models.Transactions.company_id == current_company.id
        ).first()

        if not transaction:
            raise HTTPException(
                status_code=404,
                detail="Pending transaction not found in your company"
            )

        transaction.status = "cancelled"
        transaction.updated_at = datetime.utcnow()

        # Add audit log
        models.AuditLog.log(
            db=db,
            action="cancel_sale",
            entity_type="transaction",
            entity_id=transaction.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={"previous_status": "pending"}
        )

        db.commit()

        return {
            "message": "Sale cancelled successfully",
            "transaction": {
                "id": transaction.id,
                "status": "cancelled",
                "company_id": current_company.id,
                "updated_at": transaction.updated_at
            }
        }

    except Exception as e:
        db.rollback()
        print(f"Error cancelling sale in company {current_company.id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sales/user/{user_id}", response_model=List[schemas.SaleSummary])
def get_user_sales(user_id: int, db: Session = Depends(database.get_db)):
    sales = db.query(
        models.Products.product_name,
        models.Sales.quantity,
        (models.Sales.quantity * models.Sales.unit_price).label('total_amount'),
        models.Sales.created_at
    ).join(
        models.Products,
        models.Sales.pid == models.Products.id
    ).filter(
        models.Sales.user_id == user_id
    ).all()

    return sales

@app.get("/sales", status_code=status.HTTP_200_OK)
def fetch_sales(db: Session = Depends(database.get_db)):
    sales = db.query(models.Sales).join(models.Users).join(models.Products).all()
    return [
        {
            "id": sale.id,
            "pid": sale.pid,
            "user_id": sale.user_id,
            "first_name": sale.users.first_name,
            "quantity": sale.quantity,
            "created_at": sale.created_at,
            "product_name": sale.products.product_name, 
            "product_price": sale.products.product_price,
            "total_amount": sale.quantity * sale.products.product_price
        }
        for sale in sales
    ]


# Route for getting sale by the sale id:
@app.get("/sales/{id}", status_code=status.HTTP_200_OK)
def fetch_sale(id: int, db: Session = Depends(database.get_db)):
    sale = (
        db.query(models.Sales)
        .join(models.Users)
        .join(models.Products)
        .filter(models.Sales.id == id)
        .first()
    )
    
    if sale:
        total_amount = sale.quantity * sale.products.product_price  # Calculate total amount
        return {
            "id": sale.id,
            "pid": sale.pid,
            "user_id": sale.users.id, 
            "product_name": sale.products.product_name,
            "quantity": sale.quantity, 
            "created_at": sale.created_at,
            "total_amount": total_amount  # Include total amount in the response
        }
    
    raise HTTPException(status_code=404, detail="Sale not found")

# Route for getting sales by user ID:
@app.get("/sales/user/{user_id}", status_code=status.HTTP_200_OK)
def fetch_sales_by_user(user_id: int, db: Session = Depends(database.get_db)):
    sales = db.query(models.Sales).join(models.Users).join(models.Products).filter(models.Sales.user_id == user_id).all()
    
    if not sales:
        raise HTTPException(status_code=404, detail="No sales found for this user")
    
    return [{
        "id": sale.id,
        "pid": sale.pid,
        "user_id": sale.user_id,
        "first_name": sale.users.first_name,
        "quantity": sale.quantity,
        "created_at": sale.created_at,  # Include created_at in the response
        "total_amount": sale.quantity * sale.products.product_price  # Calculate total amount
    } for sale in sales]
    

# Route for updating sales:
@app.put("/sales/{id}", response_model=schemas.SaleUpdateResponse)
def update_sale(
    id: int,
    request: schemas.UpdateSale,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Fetch the existing sale with company check
        sale = db.query(models.Sales).filter(
            models.Sales.id == id,
            models.Sales.company_id == current_company.id
        ).first()
        
        if not sale:
            raise HTTPException(
                status_code=404,
                detail="Sale not found in your company"
            )

        # Fetch the product with company check
        product = db.query(models.Products).filter(
            models.Products.id == request.pid,
            models.Products.company_id == current_company.id
        ).first()
        
        if not product:
            raise HTTPException(
                status_code=404,
                detail="Product not found in your company"
            )

        # Calculate and validate stock change
        quantity_difference = request.quantity - sale.quantity
        if product.stock_quantity - quantity_difference < 0:
            raise HTTPException(
                status_code=400,
                detail=f"Not enough stock available for {product.product_name}"
            )

        # Update the sale
        sale.quantity = request.quantity
        sale.price = request.price
        sale.pid = request.pid
        sale.updated_at = datetime.utcnow()

        # Update the product stock
        product.stock_quantity -= quantity_difference

        # Add simple audit log
        models.AuditLog.log(
            db=db,
            action="update_sale",
            entity_type="sale",
            entity_id=sale.id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "quantity_change": quantity_difference,
                "new_price": request.price
            }
        )

        db.commit()
        
        return {
            "message": "Sale updated successfully",
            "sale": {
                "id": sale.id,
                "quantity": sale.quantity,
                "price": sale.price,
                "product_id": sale.pid,
                "updated_at": sale.updated_at
            }
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error updating sale: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to update sale"
        )


# Route for deleting a sale:
@app.delete("/sales/{sale_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_sale(
    sale_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get sale with company check
        existing_sale = db.query(models.Sales).filter(
            models.Sales.id == sale_id,
            models.Sales.company_id == current_company.id
        ).first()

        if not existing_sale:
            raise HTTPException(
                status_code=404,
                detail="Sale not found in your company"
            )

        # Get product with company check
        product = db.query(models.Products).filter(
            models.Products.id == existing_sale.pid,
            models.Products.company_id == current_company.id
        ).first()

        if product:
            # Restore stock quantity
            product.stock_quantity += existing_sale.quantity

        # Add audit log
        models.AuditLog.log(
            db=db,
            action="delete_sale",
            entity_type="sale",
            entity_id=sale_id,
            user_id=current_user.id,
            company_id=current_company.id,
            details={
                "quantity_restored": existing_sale.quantity,
                "product_id": existing_sale.pid
            }
        )

        # Delete the sale
        db.delete(existing_sale)
        db.commit()
        
        return None

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error deleting sale: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to delete sale"
        )

# The end for the Sale routes <<

# Start contact Routes >> 

@app.post("/contact", response_model=schemas.ContactResponse)
async def create_contact(
    contact: schemas.ContactCreate,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        new_contact = models.Contact(
            **contact.dict(),
            company_id=current_company.id,
            status="open"
        )
        db.add(new_contact)
        db.commit()
        db.refresh(new_contact)
        return new_contact
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

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
                    existing_product.stock_quantity = row['stock_quantity']
                    existing_product.description = row.get('description')
                    existing_product.updated_at = datetime.utcnow()
                    existing_product.updated_by = current_user.id
                else:
                    # Create new product
                    new_product = models.Products(
                        product_name=row['product_name'],
                        product_price=row['product_price'],
                        selling_price=row['selling_price'],
                        stock_quantity=row['stock_quantity'],
                        description=row.get('description'),
                        company_id=current_company.id,
                        created_by=current_user.id
                    )
                    db.add(new_product)
                
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
    current_company: models.Company = Depends(get_current_company),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check if vendor already exists in company
        existing_vendor = db.query(models.Vendor).filter(
            models.Vendor.name == vendor.name,
            models.Vendor.company_id == current_company.id
        ).first()
        
        if existing_vendor:
            raise HTTPException(
                status_code=400,
                detail="Vendor already exists in your company"
            )

        # Create new vendor
        db_vendor = models.Vendor(
            **vendor.dict(),
            company_id=current_company.id,
            created_by=current_user.id
        )
        
        db.add(db_vendor)
        db.commit()
        db.refresh(db_vendor)
        
        return db_vendor

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error creating vendor in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error creating vendor"
        )

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

@app.get("/vendors/{vendor_id}", response_model=schemas.VendorDetailResponse)
def get_vendor(
    vendor_id: int,
    db: Session = Depends(database.get_db),
    current_company: models.Company = Depends(get_current_company)
):
    try:
        # Get vendor with company check and products
        vendor = db.query(models.Vendor)\
            .options(joinedload(models.Vendor.products))\
            .filter(
                models.Vendor.id == vendor_id,
                models.Vendor.company_id == current_company.id
            )\
            .first()
        
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail="Vendor not found in your company"
            )
            
        return {
            "id": vendor.id,
            "name": vendor.name,
            "contact_person": vendor.contact_person,
            "email": vendor.email,
            "phone": vendor.phone,
            "address": vendor.address,
            "company_id": vendor.company_id,
            "created_at": vendor.created_at,
            "products": [
                {
                    "id": product.id,
                    "name": product.product_name,
                    "price": product.product_price,
                    "selling_price": product.selling_price,
                    "stock": product.stock_quantity,
                    "created_at": product.created_at
                }
                for product in vendor.products
            ] if vendor.products else []
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error fetching vendor in company {current_company.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error fetching vendor details"
        )

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
@app.post("/companies", response_model=schemas.CompanyResponse)
def create_company(
    company: schemas.CompanyCreate,
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    try:
        # Create new company with current user as owner
        db_company = models.Company(
            name=company.name,
            phone=company.phone or "",  # Provide default value since it's required
            email=company.email or "",  # Provide default value since it's required
            location=company.location or "",  # Provide default value since it's required
            description=company.description,
            user_id=current_user.id,
            status="active"
        )
        
        db.add(db_company)
        db.commit()
        db.refresh(db_company)
        
        # Update the user's company_id and role
        user = db.query(models.Users).filter(models.Users.id == current_user.id).first()
        user.company_id = db_company.id
        user.company_role = "owner"
        db.commit()
        
        return db_company
        
    except Exception as e:
        db.rollback()
        print(f"Error creating company: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error creating company"
        )

@app.get("/companies/me", response_model=schemas.CompanyResponse)
def get_my_company(
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        company = db.query(models.Company)\
            .filter(
                models.Company.user_id == current_user.id,
                models.Company.status == "active"
            )\
            .first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="You don't have an active company"
            )
        
        return company

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Error fetching company details"
        )

@app.put("/companies/me", response_model=schemas.CompanyResponse)
def update_my_company(
    company_update: schemas.CompanyUpdate,
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get active company
        company = db.query(models.Company).filter(
            models.Company.user_id == current_user.id,
            models.Company.status == "active"
        ).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="You don't have an active company"
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
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check admin permission
        if not current_user.is_admin:
            raise HTTPException(
                status_code=403,
                detail="Only administrators can create subscription plans"
            )
        
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
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check if company exists and user has permission
        company = db.query(models.Company).filter(
            models.Company.id == subscription.company_id
        ).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="Company not found"
            )
            
        # Check if user has permission for this company
        if company.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to create subscriptions for this company"
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
            status="active",
            created_by=current_user.id
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
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get active company
        company = db.query(models.Company).filter(
            models.Company.user_id == current_user.id,
            models.Company.status == "active"
        ).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="You don't have an active company"
            )
        
        # Get active subscription with plan details
        subscription = db.query(models.Subscription)\
            .options(joinedload(models.Subscription.plan))\
            .filter(
                models.Subscription.company_id == company.id,
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
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Get user's company
        company = db.query(models.Company).filter(
            models.Company.user_id == current_user.id,
            models.Company.status == "active"
        ).first()
        
        if not company:
            raise HTTPException(
                status_code=404,
                detail="No active company found for this user"
            )

        # Get fresh access token
        access_token = await get_access_token()
        if not access_token:
            raise HTTPException(
                status_code=500,
                detail="Failed to get MPESA access token"
            )

        # Send STK Push request
        result = await initiate_stk_push_request(
            transaction.phone_number,
            transaction.amount,
            access_token
        )
        
        # Store transaction details
        mpesa_tx = models.MPESATransaction(
            checkout_request_id=result["CheckoutRequestID"],
            merchant_request_id=result["MerchantRequestID"],
            phone_number=transaction.phone_number,
            amount=transaction.amount,
            status="PENDING",
            company_id=company.id
        )
        db.add(mpesa_tx)
        db.commit()
        
        return {
            "checkout_request_id": result["CheckoutRequestID"],
            "merchant_request_id": result["MerchantRequestID"],
            "status": "pending",
            "response_code": "0",
            "response_description": "Success. Request accepted for processing",
            "customer_message": "Please check your phone to complete the payment"
        }
            
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        print(f"STK Push error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stk-push/status", response_model=schemas.STKPushCheckResponse)
async def check_stk_push_status(
    merchant_request_id: str,
    checkout_request_id: str,
    db: Session = Depends(database.get_db),
    current_user: schemas.UserResponse = Depends(get_current_user)  # Add current user
):
    # Get user's company
    company = db.query(models.Company).filter(
        models.Company.user_id == current_user.id,
        models.Company.status == "active"
    ).first()
    
    if not company:
        raise HTTPException(
            status_code=404,
            detail="No active company found for this user"
        )

    # Check transaction status with company context
    transaction = db.query(models.MPESATransaction).filter(
        models.MPESATransaction.merchant_request_id == merchant_request_id,
        models.MPESATransaction.checkout_request_id == checkout_request_id,
        models.MPESATransaction.company_id == company.id  # Add company filter
    ).first()
    
    if not transaction:
        return {
            "success": False,
            "message": "Transaction not found",
            "status": None
        }
    
    return {
        "success": transaction.status == models.MPESAStatus.COMPLETED,
        "message": f"Transaction {transaction.status}",
        "status": transaction.status
    }


@app.post("/stk-push/callback")
async def stk_push_callback(
    callback_data: schemas.MPESACallback,
    db: Session = Depends(database.get_db)
):
    print("Received callback data:", callback_data)
    
    # Get the transaction first to get the company_id
    transaction = db.query(models.MPESATransaction).filter(
        models.MPESATransaction.checkout_request_id == callback_data.CheckoutRequestID
    ).first()
    
    if not transaction:
        raise HTTPException(
            status_code=404,
            detail="Transaction not found"
        )
    
    # Convert Pydantic model to dict for the callback processor
    callback_dict = callback_data.dict()
    
    # Pass the company_id to the process_stk_push_callback function
    return await process_stk_push_callback(callback_dict, db, transaction.company_id)

@app.get("/mpesa/config/check")
async def check_mpesa_config(
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    try:
        # Check if user is admin
        if not current_user.is_admin:
            raise HTTPException(
                status_code=403,
                detail="Only administrators can check MPESA configuration"
            )
            
        config = {
            "consumer_key": CONSUMER_KEY[-4:] if CONSUMER_KEY else None,
            "consumer_secret": CONSUMER_SECRET[-4:] if CONSUMER_SECRET else None,
            "business_short_code": BUSINESS_SHORT_CODE,
            "pass_key": PASS_KEY[-4:] if PASS_KEY else None,
            "callback_url": CALLBACK_URL
        }
        
        missing = [k for k, v in config.items() if not v]
        
        return {
            "status": "ok" if not missing else "missing_config",
            "config": {k: "..." + str(v) if v and k != "callback_url" else v for k, v in config.items()},
            "missing": missing
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error checking MPESA config: {str(e)}"
        )

