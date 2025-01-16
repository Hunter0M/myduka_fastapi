import re # Pattern Matching: Regular expressions allow you to define a search pattern. This pattern can be used to check if a string contains specific characters, words, or sequences.
import os
import requests # pip install requests 
from pathlib import Path 
import io
from fastapi.staticfiles import StaticFiles
import shutil
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from sqlalchemy import func
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



app = FastAPI(
    title="Inventory System API",
    description="API for managing inventory and sales",
    version="1.0.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)
models.Base.metadata.create_all(database.engine)

# origins = [
#     "http://localhost:3000",  # Your React app URL
#     "http://127.0.0.1:3000",
#     "http://192.168.1.20:3000",
# ]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,  # Don't use ["*"] when using credentials
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"]
# )


# app.add_middleware(
#     CORSMiddleware,
#     # allow_origins=["http://http://178.62.113.250"],  # Allows all origins
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# Configure CORS
origins = [
    "http://localhost",
    "http://localhost:5173",
    "https://www.inventorysystem.co.ke",
    "https://inventorysystem.co.ke"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
        # Check if email already exists
        existing_user = db.query(models.Users).filter(
            models.Users.email == user.email.lower()
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )

        # Password validation is handled by Pydantic model (min_length=6)
        # Password matching is handled by Pydantic validator
        # Phone validation is handled by Pydantic validator

        # Create new user with normalized data
        db_user = models.Users(
            email=user.email.lower(),
            first_name=user.first_name.strip(),
            last_name=user.last_name.strip(),
            phone=user.phone,
            password=get_password_hash(user.password)
        )

        try:
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            return db_user
            
        except Exception as db_error:
            db.rollback()
            print(f"Database error during registration: {str(db_error)}")
            raise HTTPException(
                status_code=500,
                detail="Failed to create user account"
            )

    except HTTPException as he:
        # Re-raise HTTP exceptions with their original status codes
        raise he
    except ValueError as ve:
        # Handle validation errors from Pydantic
        raise HTTPException(
            status_code=422,
            detail=str(ve)
        )
    except Exception as e:
        # Handle unexpected errors
        print(f"Unexpected error during registration: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

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

@app.get("/users/me", response_model=List[schemas.UserResponse])
def fetch_users(db: Session = Depends(database.get_db)):
    users = db.query(models.Users).all()
    return users

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
async def save_upload_file(upload_file: UploadFile) -> str:
    try:
        # Generate unique filename
        file_extension = os.path.splitext(upload_file.filename)[1]
        unique_filename = f"{uuid4()}{file_extension}"
        file_path = UPLOAD_DIR / unique_filename
        
        # Save the file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
        
        # Return the relative URL (this part stays the same)
        return f"/uploads/{unique_filename}"
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        

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
    db: Session = Depends(database.get_db)
):
    try:
        # Validate vendor exists
        vendor = db.query(models.Vendor).filter(models.Vendor.id == vendor_id).first()
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail=f"Vendor with ID {vendor_id} not found"
            )

        # Create product data dict
        product_data = {
            "product_name": product_name.strip(),
            "product_price": product_price,
            "selling_price": selling_price,
            "stock_quantity": stock_quantity,
            "vendor_id": vendor_id,
            "description": description.strip() if description else None,
            "image_url": DEFAULT_IMAGE_PATH
        }

        # Handle image upload if provided
        if image and image.filename:
            if not image.content_type.startswith("image/"):
                raise HTTPException(status_code=400, detail="File must be an image")
            image_url = await save_upload_file(image)
            product_data["image_url"] = image_url

        # Check for duplicate product name
        existing_product = db.query(models.Products).filter(
            models.Products.product_name == product_name.strip()
        ).first()
        if existing_product:
            raise HTTPException(
                status_code=400,
                detail=f"Product with name '{product_name}' already exists"
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


# @app.get("/products/check-name")  # New endpoint specifically for checking product names
# async def check_product_name(product_name: str, db: Session = Depends(database.get_db)):
#     try:
#         product = db.query(models.Products).filter(
#             models.Products.product_name == product_name
#         ).first()
#         return {"exists": product is not None}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


@app.get("/products/check-name")
async def check_product_name(product_name: str, db: Session = Depends(database.get_db)):
    try:
        # Convert to lowercase and trim whitespace for comparison
        normalized_name = product_name.lower().strip()
        product = db.query(models.Products).filter(
            func.lower(models.Products.product_name) == normalized_name
        ).first()
        
        exists = product is not None
        print(f"Checking product name: {product_name}, exists: {exists}")  # Debug log
        
        return {"exists": exists}
    except Exception as e:
        print(f"Error checking product name: {str(e)}")  # Debug log
        raise HTTPException(status_code=500, detail=str(e))


# Your existing routes remain unchanged
# @app.get("/products")
# def fetch_products(db: Session = Depends(database.get_db)):
#     try:
#         products = db.query(models.Products).all()
#         return {"products": products}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
@app.get("/products")
def fetch_products(db: Session = Depends(database.get_db)):
    try:
        # Query products with vendor information
        products = db.query(models.Products).options(
            joinedload(models.Products.vendor)
        ).all()
        
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
        
        return {"products": formatted_products}
    except Exception as e:
        print(f"Error fetching products: {str(e)}")  # Debug log
        raise HTTPException(status_code=500, detail=str(e))
    
    
# @app.get("/products/{id}")
# def fetch_product(id: int, db: Session = Depends(database.get_db)):
#     product = db.query(models.Products).filter(models.Products.id == id).first()
#     if product:
#         return product
#     raise HTTPException(status_code=404, detail="Product not found")


@app.get("/products/{id}")
def fetch_product(id: int, db: Session = Depends(database.get_db)):
    try:
        # Use joinedload to eagerly load the vendor relationship
        product = db.query(models.Products)\
            .options(joinedload(models.Products.vendor))\
            .filter(models.Products.id == id)\
            .first()
            
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
            
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
            "vendor": {
                "id": product.vendor.id,
                "name": product.vendor.name,
                "contact_person": product.vendor.contact_person,
                "email": product.vendor.email,
                "phone": product.vendor.phone,
                "address": product.vendor.address
            } if product.vendor else None
        }
    except Exception as e:
        print(f"Error fetching product: {str(e)}")  # Debug log
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/products/{id}", status_code=status.HTTP_200_OK)
async def update_product(
    id: int,
    product_name: str = Form(...),
    product_price: float = Form(...),
    selling_price: float = Form(...),
    stock_quantity: int = Form(...),
    description: Optional[str] = Form(default=None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(database.get_db)
):
    try:
        # Fetch existing product
        product = db.query(models.Products).filter(models.Products.id == id).first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        # Check for duplicate name
        existing_product = db.query(models.Products).filter(
            models.Products.product_name == product_name.strip(),
            models.Products.id != id
        ).first()
        
        if existing_product:
            raise HTTPException(
                status_code=400,
                detail=f"Product with name '{product_name}' already exists"
            )

        # Handle image upload
        if image:
            try:
                if not image.content_type.startswith("image/"):
                    raise HTTPException(status_code=400, detail="File must be an image")
                
                # Delete old image if it exists and isn't the default
                if product.image_url and not product.image_url.endswith('default-product.png'):
                    old_image_path = os.path.join(UPLOAD_DIR, os.path.basename(product.image_url))
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Save new image
                image_url = await save_upload_file(image)
                product.image_url = image_url
                
            except Exception as e:
                print(f"Error handling image: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error uploading image: {str(e)}")

        # Update other fields
        product.product_name = product_name.strip()
        product.product_price = float(product_price)
        product.selling_price = float(selling_price)
        product.stock_quantity = int(stock_quantity)
        if description is not None:
            product.description = description.strip()
        
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
                "stock_quantity": product.stock_quantity,
                "description": product.description,
                "image_url": product.image_url,
                "updated_at": product.updated_at
            }
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error updating product: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))



# @app.put("/products/{id}", status_code=status.HTTP_200_OK)
# async def update_product(
#     id: int,
#     product_name: str = Query(None),
#     product_price: int = Query(None),
#     selling_price: int = Query(None),
#     stock_quantity: int = Query(None),
#     description: str = Query(None),
#     image: UploadFile = File(None),
#     image_url: str = Form(None),  # Add this parameter
#     db: Session = Depends(database.get_db)
# ):
#     try:
#         # Fetch the existing product
#         product = db.query(models.Products).filter(models.Products.id == id).first()
#         if not product:
#             raise HTTPException(status_code=404, detail="Product not found")
        
#         # Update product fields if new values are provided
#         if product_name is not None:
#             product.product_name = product_name
#         if product_price is not None:
#             product.product_price = product_price
#         if selling_price is not None:
#             product.selling_price = selling_price
#         if stock_quantity is not None:
#             product.stock_quantity = stock_quantity
#         if description is not None:
#             product.description = description
        
#         # Handle image removal
#         if image_url == '':
#             # Delete the old image file if it exists
#             if product.image_url:
#                 old_image_path = os.path.join(os.getcwd(), product.image_url.lstrip('/'))
#                 if os.path.exists(old_image_path):
#                     os.remove(old_image_path)
#             product.image_url = None
#         # Handle new image upload
#         elif image:
#             if not image.content_type.startswith("image/"):
#                 raise HTTPException(status_code=400, detail="File must be an image")
            
#             # Delete old image if exists
#             if product.image_url:
#                 old_image_path = os.path.join(os.getcwd(), product.image_url.lstrip('/'))
#                 if os.path.exists(old_image_path):
#                     os.remove(old_image_path)
            
#             # Save new image
#             image_url = await save_upload_file(image)
#             product.image_url = image_url
        
#         # Update the updated_at timestamp
#         product.updated_at = datetime.utcnow()

#         # Commit the changes to the database
#         db.commit()
#         db.refresh(product)
        
#         return {"message": "Product updated successfully", "product": product}
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(status_code=500, detail=str(e))
    
@app.put("/products/{id}/remove-image", status_code=status.HTTP_200_OK)
async def remove_product_image(id: int, db: Session = Depends(database.get_db)):
    try:
        product = db.query(models.Products).filter(models.Products.id == id).first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        # Delete the physical image file if it exists
        if product.image_url:
            image_path = os.path.join(os.getcwd(), product.image_url.lstrip('/'))
            if os.path.exists(image_path):
                os.remove(image_path)

        # Update the database record
        product.image_url = None
        product.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(product)
        
        return {"message": "Image removed successfully", "product": product}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    

# Route for deleting an existing product:
@app.delete("/products/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_product(id: int, db: Session = Depends(database.get_db)):
    try:
        product = db.query(models.Products).filter(models.Products.id == id).first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        # Delete image file if exists
        if product.image_url:
            image_path = os.path.join(os.getcwd(), product.image_url.lstrip('/'))
            if os.path.exists(image_path):
                os.remove(image_path)

        db.delete(product)
        db.commit()
        return None
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# The end for the Product routes <<



# Start Sale Routes >> 

# This is for creating a sale:  
@app.post("/sales", response_model=schemas.TransactionResponse)
def create_sale(sale: schemas.CartSaleCreate, db: Session = Depends(database.get_db)):
    try:
        print("Received sale data:", sale.dict())  # Debug log
        
        # First validate all products and calculate total
        sales_to_create = []
        total_amount = 0

        for item in sale.cart_items:
            print(f"Processing item: {item.dict()}")  # Debug log
            
            product = db.query(models.Products).filter(
                models.Products.id == item.product_id
            ).first()
            
            if not product:
                raise HTTPException(
                    status_code=404,
                    detail=f"Product with ID {item.product_id} not found"
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

        # Create transaction record with pending status
        transaction = models.Transactions(
            user_id=sale.user_id,
            total_amount=total_amount,
            status="pending"
        )
        db.add(transaction)
        db.flush()  # Get transaction ID without committing

        # Create sales records with pending status
        sales_records = []
        for item in sales_to_create:
            new_sale = models.Sales(
                pid=item["product"].id,
                quantity=item["quantity"],
                unit_price=item["unit_price"],
                user_id=sale.user_id,
                status="pending"
            )
            db.add(new_sale)
            db.flush()  # Get the sale ID
            sales_records.append(new_sale)

            # Create transaction_sales relationship
            trans_sale = models.TransactionSales(
                transaction_id=transaction.id,
                sale_id=new_sale.id
            )
            db.add(trans_sale)

        # Commit all changes
        db.commit()

        # Format response
        return {
            "id": transaction.id,
            "total_amount": total_amount,
            "status": transaction.status,
            "created_at": transaction.created_at,
            "sales": [
                {
                    "id": sale.id,
                    "pid": sale.pid,
                    "product_name": item["product"].product_name,
                    "quantity": sale.quantity,
                    "unit_price": sale.unit_price,
                    "total_amount": sale.quantity * sale.unit_price,
                    "user_id": sale.user_id,
                    "status": sale.status,
                    "created_at": sale.created_at
                }
                for sale, item in zip(sales_records, sales_to_create)
            ]
        }

    except HTTPException as he:
        print(f"HTTP Exception: {he.detail}")  # Debug log
        db.rollback()
        raise he
    except Exception as e:
        print(f"Unexpected error: {str(e)}")  # Debug log
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )

@app.post("/confirm-payment/{transaction_id}")
def confirm_payment(
    transaction_id: int,
    payment_info: schemas.PaymentConfirmation,
    db: Session = Depends(database.get_db)
):
    try:
        # Get the transaction
        transaction = db.query(models.Transactions).filter(
            models.Transactions.id == transaction_id
        ).first()

        if not transaction:
            raise HTTPException(
                status_code=404,
                detail="Transaction not found"
            )

        if transaction.status != "pending":
            raise HTTPException(
                status_code=400,
                detail=f"Transaction is already {transaction.status}"
            )

        # Get all associated sales
        sales = db.query(models.Sales).join(
            models.TransactionSales
        ).filter(
            models.TransactionSales.transaction_id == transaction_id
        ).all()

        # Update product quantities and sale status
        for sale in sales:
            product = db.query(models.Products).filter(
                models.Products.id == sale.pid
            ).first()
            
            # Recheck stock availability
            if product.stock_quantity < sale.quantity:
                raise HTTPException(
                    status_code=400,
                    detail=f"Not enough stock for product {product.product_name}"
                )
            
            # Update product stock
            product.stock_quantity -= sale.quantity
            
            # Update sale status
            sale.status = "completed"

        # Create payment record
        payment = models.Payment(
            sale_id=sales[0].id,  # Link to first sale
            amount=transaction.total_amount,
            mode=payment_info.payment_mode,
            transaction_code=payment_info.transaction_code
        )
        db.add(payment)

        # Update transaction status
        transaction.status = "completed"

        db.commit()

        return {"message": "Payment confirmed and sales completed successfully"}

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

# This is for confirming a sale:    
@app.post("/sales/confirm/{transaction_id}")
def confirm_sale(transaction_id: int, db: Session = Depends(database.get_db)):
    try:
        # Fetch the pending transaction
        transaction = db.query(models.Transactions).filter(
            models.Transactions.id == transaction_id,
            models.Transactions.status == "pending"
        ).first()

        if not transaction:
            raise HTTPException(
                status_code=404,
                detail="Pending transaction not found"
            )

        # Fetch cart items (you'll need to store these temporarily, perhaps in the transaction details)
        # For this example, let's assume we're receiving them again
        cart_items = []  # This should come from your payment confirmation logic

        # Create sales records and update stock
        sales_records = []
        for item in cart_items:
            product = db.query(models.Products).filter(
                models.Products.id == item["product_id"]
            ).first()

            if not product:
                raise HTTPException(
                    status_code=404,
                    detail=f"Product with ID {item['product_id']} not found"
                )

            # Create sale record
            new_sale = models.Sales(
                pid=item["product_id"],
                quantity=item["quantity"],
                user_id=transaction.user_id,
                unit_price=item["unit_price"]
            )
            
            # Update product stock
            product.stock_quantity -= item["quantity"]
            
            sales_records.append(new_sale)
            db.add(new_sale)

        # Update transaction status
        transaction.status = "completed"
        
        # Commit all changes
        db.commit()

        return {
            "message": "Sale confirmed successfully",
            "transaction_id": transaction.id,
            "status": "completed"
        }

    except HTTPException as he:
        db.rollback()
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

# This is for cancelling a sale:    
@app.post("/sales/cancel/{transaction_id}")
def cancel_sale(transaction_id: int, db: Session = Depends(database.get_db)):
    try:
        transaction = db.query(models.Transactions).filter(
            models.Transactions.id == transaction_id,
            models.Transactions.status == "pending"
        ).first()

        if not transaction:
            raise HTTPException(
                status_code=404,
                detail="Pending transaction not found"
            )

        transaction.status = "cancelled"
        db.commit()

        return {
            "message": "Sale cancelled successfully",
            "transaction_id": transaction.id,
            "status": "cancelled"
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

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
@app.put("/sales/{id}", status_code=status.HTTP_202_ACCEPTED)
def update_sale(id: int, request: schemas.UpdateSale, db: Session = Depends(database.get_db)):
    try:
        # Print request data for debugging
        print(f"Updating sale {id} with data:", request)
        
        # Fetch the existing sale
        sale = db.query(models.Sales).filter(models.Sales.id == id).first()
        if not sale:
            raise HTTPException(status_code=404, detail="Sale not found")
        print(f"Found existing sale:", sale.__dict__)

        # Fetch the corresponding product
        product = db.query(models.Products).filter(models.Products.id == request.pid).first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        print(f"Found product:", product.__dict__)

        # Calculate the difference in quantity
        quantity_difference = request.quantity - sale.quantity
        print(f"Quantity difference:", quantity_difference)

        # Validate stock quantity
        if product.stock_quantity - quantity_difference < 0:
            raise HTTPException(
                status_code=400,
                detail="Not enough stock available"
            )

        # Update the sale details
        sale.quantity = request.quantity
        sale.user_id = request.user_id
        sale.price = request.price
        sale.date = request.date
        sale.pid = request.pid

        # Update the product's stock quantity
        product.stock_quantity -= quantity_difference

        # Commit the changes
        db.commit()
        
        return {
            "message": "Sale updated successfully",
            "sale": {
                "id": sale.id,
                "quantity": sale.quantity,
                "price": sale.price,
                "date": sale.date,
                "user_id": sale.user_id,
                "pid": sale.pid
            }
        }
    except Exception as e:
        db.rollback()  # Rollback changes if there's an error
        print(f"Error updating sale: {str(e)}")  # Print the error
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update sale: {str(e)}"
        )


# Route for deleting a sale:
@app.delete("/sales/{sale_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_sale(sale_id: int, db: Session = Depends(database.get_db)):
    existing_sale = db.query(models.Sales).filter(models.Sales.id == sale_id).first()  # Fetch sale by ID
    if existing_sale is None:
        raise HTTPException(status_code=404, detail="Sale not found") 
    product = db.query(models.Products).filter(models.Products.id == existing_sale.pid).first()
    if product:
        product.stock_quantity += existing_sale.quantity  # Restore stock quantity if needed

    db.delete(existing_sale)  # Delete the sale from the database
    db.commit()  # Commit the deletion to the database
    return  # Return nothing for 204 No Content

# The end for the Sale routes <<

# Start contact Routes >> 

@app.post("/contact", response_model=schemas.ContactResponse)
async def create_contact(
    contact: schemas.ContactCreate,
    db: Session = Depends(database.get_db)
):
    try:
        new_contact = models.Contact(**contact.dict())
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
    db: Session = Depends(database.get_db)
):
    try:
        # Find the contact message
        contact = db.query(models.Contact).filter(models.Contact.id == contact_id).first()
        if not contact:
            raise HTTPException(status_code=404, detail="Contact message not found")
        
        # Update contact with reply
        contact.response = reply_data.reply
        contact.status = "closed"
        contact.updated_at = datetime.now(timezone.utc)
        
        db.commit()
        db.refresh(contact)
        
        return contact
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/contact", response_model=List[schemas.ContactResponse])
async def get_contacts(
    db: Session = Depends(database.get_db),
):
    contacts = db.query(models.Contact).order_by(
        models.Contact.created_at.desc()
    )
    return contacts

@app.get("/contact/{contact_id}", response_model=schemas.ContactResponse)
async def get_contact(contact_id: int, db: Session = Depends(database.get_db)):
    contact = db.query(models.Contact).filter(models.Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


@app.put("/contact/{contact_id}/status")
async def update_contact_status(
    contact_id: int,
    status_data: dict,
    db: Session = Depends(database.get_db)
):
    contact = db.query(models.Contact).filter(models.Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    
    contact.status = status_data.get("status")
    db.commit()
    return contact

@app.delete("/contact/{contact_id}")
async def delete_contact(
    contact_id: int,
    db: Session = Depends(database.get_db)
):
    contact = db.query(models.Contact).filter(models.Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    
    db.delete(contact)
    db.commit()
    return {"message": "Contact deleted successfully"}

# The end for the Contact routes <<



@app.post("/import/products")
async def import_products(
    file: UploadFile = File(...),
    db: Session = Depends(database.get_db),
    current_user: Optional[int] = None
):
    # Create import history record
    import_record = models.ImportHistory(
        filename=file.filename,
        status='processing',
        user_id=current_user
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

        # Update import record with total rows
        import_record.total_rows = len(df)
        db.commit()

        # Process records
        success_count = 0
        error_count = 0
        errors = []

        for index, row in df.iterrows():
            try:
                # Check if product already exists
                existing_product = db.query(models.Products).filter(
                    models.Products.product_name == row['product_name']
                ).first()

                if existing_product:
                    # Update existing product
                    existing_product.product_price = row['product_price']
                    existing_product.selling_price = row['selling_price']
                    existing_product.stock_quantity = row['stock_quantity']
                    if 'description' in row:
                        existing_product.description = row['description']
                else:
                    # Create new product
                    new_product = models.Products(
                        product_name=row['product_name'],
                        product_price=row['product_price'],
                        selling_price=row['selling_price'],
                        stock_quantity=row['stock_quantity'],
                        description=row.get('description', None)
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

        # Update import record with results
        import_record.status = 'completed'
        import_record.successful_rows = success_count
        import_record.failed_rows = error_count
        import_record.errors = errors
        import_record.completed_at = datetime.now()
        
        # Commit all changes
        db.commit()

        return {
            "import_id": import_record.id,
            "message": "Import completed",
            "total_processed": len(df),
            "successful": success_count,
            "failed": error_count,
            "errors": errors if errors else None
        }

    except Exception as e:
        # Update import record with error status
        import_record.status = 'failed'
        import_record.errors = [{"error": str(e)}]
        import_record.completed_at = datetime.now()
        db.commit()
        
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/import/template/{file_type}")
async def get_import_template(file_type: str, background_tasks: BackgroundTasks):
    if file_type not in ['csv', 'excel']:
        raise HTTPException(status_code=400, detail="Invalid template type")
    
    # Create sample data
    data = {
        'product_name': ['Sample Product 1', 'Sample Product 2'],
        'product_price': [100, 200],
        'selling_price': [150, 250],
        'stock_quantity': [50, 75],
        'description': ['Sample description 1', 'Sample description 2']
    }
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Create temporary file
    temp_file = f"temp_template.{'xlsx' if file_type == 'excel' else 'csv'}"
    
    # Save template
    if file_type == 'excel':
        df.to_excel(temp_file, index=False)
    else:
        df.to_csv(temp_file, index=False)
    
    # Add cleanup task
    background_tasks.add_task(os.remove, temp_file)
    
    # Return file
    return FileResponse(
        path=temp_file,
        filename=f"product_import_template.{'xlsx' if file_type == 'excel' else 'csv'}",
        media_type='application/octet-stream'
    )

# Add this utility endpoint to validate file before import
@app.post("/import/products/validate")
async def validate_import_file(
    file: UploadFile = File(...)
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
                detail="Unsupported file format. Please upload CSV or Excel file."
            )

        # Validate required columns
        required_columns = ['product_name', 'product_price', 'selling_price', 'stock_quantity']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            return {
                "valid": False,
                "errors": f"Missing required columns: {', '.join(missing_columns)}"
            }

        # Validate data types and values
        errors = []
        for index, row in df.iterrows():
            row_errors = []
            
            # Validate product name
            if not row['product_name'] or pd.isna(row['product_name']):
                row_errors.append("Product name is required")
            
            # Validate prices and quantity
            for field in ['product_price', 'selling_price', 'stock_quantity']:
                try:
                    value = float(row[field])
                    if value < 0:
                        row_errors.append(f"{field} cannot be negative")
                except (ValueError, TypeError):
                    row_errors.append(f"Invalid {field}")
            
            if row_errors:
                errors.append({
                    "row": index + 2,
                    "product_name": row['product_name'],
                    "errors": row_errors
                })

        return {
            "valid": len(errors) == 0,
            "total_rows": len(df),
            "errors": errors if errors else None
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Add endpoints to view import history
@app.get("/import/history")
async def get_import_history(
    db: Session = Depends(database.get_db),
    skip: int = 0,
    limit: int = 10
):
    imports = db.query(models.ImportHistory)\
        .order_by(models.ImportHistory.created_at.desc())\
        .offset(skip)\
        .limit(limit)\
        .all()
    
    return imports

@app.get("/import/history/{import_id}")
async def get_import_details(
    import_id: int,
    db: Session = Depends(database.get_db)
):
    import_record = db.query(models.ImportHistory)\
        .filter(models.ImportHistory.id == import_id)\
        .first()
    
    if not import_record:
        raise HTTPException(status_code=404, detail="Import record not found")
    
    return import_record





















    
    




# Start Vendor Routes >>

@app.post("/vendors", response_model=schemas.Vendor)
def create_vendor(vendor: schemas.VendorCreate, db: Session = Depends(database.get_db)):
    try:
        db_vendor = models.Vendor(**vendor.dict())
        db.add(db_vendor)
        db.commit()
        db.refresh(db_vendor)
        return db_vendor
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vendors", response_model=List[schemas.Vendor])
def get_vendors(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(database.get_db)
):
    vendors = db.query(models.Vendor).offset(skip).limit(limit).all()
    return vendors

# @app.get("/vendors/{vendor_id}", response_model=schemas.Vendor)
# def get_vendor(vendor_id: int, db: Session = Depends(database.get_db)):
#     vendor = db.query(models.Vendor).filter(models.Vendor.id == vendor_id).first()
#     if vendor is None:
#         raise HTTPException(status_code=404, detail="Vendor not found")
#     return vendor

@app.get("/vendors/{vendor_id}")
def get_vendor(vendor_id: int, db: Session = Depends(database.get_db)):
    try:
        vendor = db.query(models.Vendor)\
            .options(joinedload(models.Vendor.products))\
            .filter(models.Vendor.id == vendor_id)\
            .first()
        
        if vendor is None:
            raise HTTPException(status_code=404, detail="Vendor not found")
            
        # Convert to dict with all necessary fields
        return {
            "id": vendor.id,
            "name": vendor.name,
            "contact_person": vendor.contact_person,
            "email": vendor.email,
            "phone": vendor.phone,
            "address": vendor.address,
            "created_at": vendor.created_at,
            "updated_at": vendor.updated_at,
            "products": [
                {
                    "id": product.id,
                    "product_name": product.product_name,
                    "product_price": product.product_price,
                    "selling_price": product.selling_price,
                    "stock_quantity": product.stock_quantity,
                    "created_at": product.created_at,  # Add this line
                    "updated_at": product.updated_at   # Add this line
                }
                for product in vendor.products
            ] if vendor.products else []
        }
    except Exception as e:
        print(f"Error fetching vendor: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/vendors/{vendor_id}", response_model=schemas.Vendor)
def update_vendor(
    vendor_id: int, 
    vendor: schemas.VendorUpdate, 
    db: Session = Depends(database.get_db)
):
    try:
        db_vendor = db.query(models.Vendor).filter(models.Vendor.id == vendor_id).first()
        if db_vendor is None:
            raise HTTPException(status_code=404, detail="Vendor not found")
        
        for key, value in vendor.dict(exclude_unset=True).items():
            setattr(db_vendor, key, value)
        
        db.commit()
        db.refresh(db_vendor)
        return db_vendor
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/vendors/{vendor_id}")
def delete_vendor(vendor_id: int, db: Session = Depends(database.get_db)):
    try:
        vendor = db.query(models.Vendor).filter(models.Vendor.id == vendor_id).first()
        if vendor is None:
            raise HTTPException(status_code=404, detail="Vendor not found")
        
        db.delete(vendor)
        db.commit()
        return {"message": "Vendor deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# The end for the Vendor routes <<


# Start MPESA Routes >>
print("Access Token: ",get_access_token())
# @app.post("/stk-push")
# def initiate_stk_push(stk_push: STKPushCreate, db: Session = Depends(database.get_db)):
#     #  dummy STK Push record
#     new_stk_push = STKPush(
#         merchant_request_id="mrid_123",
#         checkout_request_id="crid_456",
#         amount=stk_push.amount,
#         phone=stk_push.phone
#     )
#     db.add(new_stk_push)
#     db.commit()
#     db.refresh(new_stk_push)
#     return new_stk_push






# @app.get("/stk-push/checker", response_model=schemas.STKPushCheckResponse)
# def check_stk_push(mrid: str, crid: str, db: Session = Depends(database.get_db)):
#     stk_push = db.query(STKPush).filter(
#         STKPush.merchant_request_id == mrid,
#         STKPush.checkout_request_id == crid
#     ).first()
    
#     if not stk_push:
#         return schemas.STKPushCheckResponse(
#             success=False,
#             message="Transaction not found")
            

# The end for the MPESA Routes <<   





















    
    




# Start Vendor Routes >>

@app.post("/vendors", response_model=schemas.Vendor)
def create_vendor(vendor: schemas.VendorCreate, db: Session = Depends(database.get_db)):
    try:
        db_vendor = models.Vendor(**vendor.dict())
        db.add(db_vendor)
        db.commit()
        db.refresh(db_vendor)
        return db_vendor
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vendors", response_model=List[schemas.Vendor])
def get_vendors(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(database.get_db)
):
    vendors = db.query(models.Vendor).offset(skip).limit(limit).all()
    return vendors

# @app.get("/vendors/{vendor_id}", response_model=schemas.Vendor)
# def get_vendor(vendor_id: int, db: Session = Depends(database.get_db)):
#     vendor = db.query(models.Vendor).filter(models.Vendor.id == vendor_id).first()
#     if vendor is None:
#         raise HTTPException(status_code=404, detail="Vendor not found")
#     return vendor

@app.get("/vendors/{vendor_id}")
def get_vendor(vendor_id: int, db: Session = Depends(database.get_db)):
    try:
        vendor = db.query(models.Vendor)\
            .options(joinedload(models.Vendor.products))\
            .filter(models.Vendor.id == vendor_id)\
            .first()
        
        if vendor is None:
            raise HTTPException(status_code=404, detail="Vendor not found")
            
        # Convert to dict with all necessary fields
        return {
            "id": vendor.id,
            "name": vendor.name,
            "contact_person": vendor.contact_person,
            "email": vendor.email,
            "phone": vendor.phone,
            "address": vendor.address,
            "created_at": vendor.created_at,
            "updated_at": vendor.updated_at,
            "products": [
                {
                    "id": product.id,
                    "product_name": product.product_name,
                    "product_price": product.product_price,
                    "selling_price": product.selling_price,
                    "stock_quantity": product.stock_quantity,
                    "created_at": product.created_at,  # Add this line
                    "updated_at": product.updated_at   # Add this line
                }
                for product in vendor.products
            ] if vendor.products else []
        }
    except Exception as e:
        print(f"Error fetching vendor: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/vendors/{vendor_id}", response_model=schemas.Vendor)
def update_vendor(
    vendor_id: int, 
    vendor: schemas.VendorUpdate, 
    db: Session = Depends(database.get_db)
):
    try:
        db_vendor = db.query(models.Vendor).filter(models.Vendor.id == vendor_id).first()
        if db_vendor is None:
            raise HTTPException(status_code=404, detail="Vendor not found")
        
        for key, value in vendor.dict(exclude_unset=True).items():
            setattr(db_vendor, key, value)
        
        db.commit()
        db.refresh(db_vendor)
        return db_vendor
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/vendors/{vendor_id}")
def delete_vendor(vendor_id: int, db: Session = Depends(database.get_db)):
    try:
        vendor = db.query(models.Vendor).filter(models.Vendor.id == vendor_id).first()
        if vendor is None:
            raise HTTPException(status_code=404, detail="Vendor not found")
        
        db.delete(vendor)
        db.commit()
        return {"message": "Vendor deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# The end for the Vendor routes <<


# Start MPESA Routes >>
# print("Access Token: ",get_access_token())
# @app.post("/stk-push")
# def initiate_stk_push(stk_push: STKPushCreate, db: Session = Depends(database.get_db)):
#     #  dummy STK Push record
#     new_stk_push = STKPush(
#         merchant_request_id="mrid_123",
#         checkout_request_id="crid_456",
#         amount=stk_push.amount,
#         phone=stk_push.phone
#     )
#     db.add(new_stk_push)
#     db.commit()
#     db.refresh(new_stk_push)
#     return new_stk_push


# Start MPESA Routes >>
def test():
    pass 


@app.post("/stk-push", response_model=schemas.STKPushResponse)
async def initiate_stk_push(
    transaction: schemas.STKPushCreate,
    db: Session = Depends(database.get_db)
):
    try:
        # Get fresh access token before making request
        access_token = get_access_token()
        if not access_token:
            raise HTTPException(
                status_code=500,
                detail="Failed to get MPESA access token"
            )

        # Send STK Push request to Safaricom with fresh token
        result = await initiate_stk_push_request(
            transaction.phone_number,
            transaction.amount,
            access_token  # Pass the token to the request function
        )
        
        # Check for error response
        if "errorCode" in result:
            raise HTTPException(
                status_code=400,
                detail=f"STK Push failed: {result.get('errorMessage', 'Unknown error')}"
            )
        
        # Store transaction details if successful
        if "CheckoutRequestID" in result:
            mpesa_tx = models.MPESATransaction(
                checkout_request_id=result["CheckoutRequestID"],
                merchant_request_id=result["MerchantRequestID"],
                phone_number=transaction.phone_number,
                amount=transaction.amount,
                status=models.MPESAStatus.PENDING
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
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid response from MPESA"
            )
            
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        print(f"STK Push error: {str(e)}")  
        raise HTTPException(status_code=500, detail=str(e))



# Check the status of the STK Push
@app.get("/stk-push/status", response_model=schemas.STKPushCheckResponse)
async def check_stk_push_status(
    merchant_request_id: str,
    checkout_request_id: str,
    db: Session = Depends(database.get_db)
):
    transaction = check_transaction_status(merchant_request_id, checkout_request_id, db)
    
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


# Callback for the STK Push >>  




@app.post("/stk-push/callback")
async def stk_push_callback(
    callback_data: schemas.MPESACallback,
    db: Session = Depends(database.get_db)
):
    print("Received callback data:", callback_data) 
    return await process_stk_push_callback(callback_data, db)



# @app.post("/stk-push/callback")
# async def stk_push_callback(
#     callback_data: schemas.MPESACallback,
#     db: Session = Depends(database.get_db)
# ):
#     try:
#         transaction = check_transaction_status(
#             callback_data.merchant_request_id,
#             callback_data.checkout_request_id,
#             db
#         )
        
#         if not transaction:
#             raise HTTPException(status_code=404, detail="Transaction not found")

#         # Update transaction status
#         transaction.status = (
#             models.MPESAStatus.COMPLETED 
#             if callback_data.result_code == "0" 
#             else models.MPESAStatus.FAILED
#         )
#         transaction.result_code = callback_data.result_code
#         transaction.result_desc = callback_data.result_desc
        
#         db.commit()
#         return {"status": "success"}

#     except Exception as e:
#         db.rollback()
#         raise HTTPException(status_code=500, detail=str(e))

# The end for the STK Push Routes <<







# @app.get("/stk-push/checker", response_model=schemas.STKPushCheckResponse)
# def check_stk_push(mrid: str, crid: str, db: Session = Depends(database.get_db)):
#     stk_push = db.query(STKPush).filter(
#         STKPush.merchant_request_id == mrid,
#         STKPush.checkout_request_id == crid
#     ).first()
    
#     if not stk_push:
#         return schemas.STKPushCheckResponse(
#             success=False,
#             message="Transaction not found")
            

# The end for the MPESA Routes <<   





















    
    



