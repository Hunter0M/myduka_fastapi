from pydantic import BaseModel, EmailStr, validator, Field
from datetime import date
from typing import Optional, List, Dict, Any
from datetime import datetime
import re
from app.utils.mpesa import format_phone_number




# Pydantic model for user creation
class UserBase(BaseModel):
    """المخطط الأساسي للمستخدم"""
    email: EmailStr
    first_name: str
    last_name: str
    phone: str

    @validator('phone')
    def validate_phone(cls, v):
        if not re.match(r'^\+?1?\d{9,15}$', v):
            raise ValueError('Invalid phone number format')
        return v

class UserCreate(UserBase):
    """مخطط إنشاء مستخدم جديد"""
    password: str = Field(..., min_length=6)
    confirm_password: str

    @validator('phone')
    def validate_phone(cls, v):
        if not re.match(r'^\+?1?\d{9,15}$', v):
            raise ValueError('Invalid phone number format')
        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class UserUpdate(BaseModel):
    """مخطط تحديث المستخدم"""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    password: Optional[str] = None

    @validator('email')
    def validate_email(cls, v):
        return v.lower().strip()

    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        if not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip()

    @validator('phone')
    def validate_phone(cls, v):
        if v and not re.match(r'^\+?1?\d{9,15}$', v):
            raise ValueError('Invalid phone number format')
        return v

    @validator('password')
    def validate_password(cls, v):
        if v and len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        return v


class UserLogin(BaseModel):
    """مخطط تسجيل الدخول"""
    email: EmailStr
    password: str

class UserResponse(UserBase):
    """مخطط استجابة بيانات المستخدم"""
    id: int
    created_at: datetime  
    updated_at: datetime | None = None     #

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class TokenResponse(BaseModel):
    """مخطط استجابة التوكن الكامل"""
    access_token: str
    access_token_expires: datetime
    refresh_token: str
    refresh_token_expires: datetime
    token_type: str = "bearer"

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class TokenData(BaseModel):
    """مخطط بيانات التوكن المستخرجة"""
    email: Optional[str] = None
    token_type: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    """مخطط طلب تجديد التوكن"""
    refresh_token: str


# class LoginRequest(BaseModel):
#     email: str
#     password: str

# class LoginResponse(BaseModel):
#     message: str
#     user_id: int


# Schema for creating a new product

# Base Product Schema (shared properties)
class ProductBase(BaseModel):
    product_name: str
    description: Optional[str] = None
    product_price: int
    selling_price: int
    stock_quantity: int
    image_url: Optional[str] = None

# Schema for creating a product
class ProductCreate(ProductBase):
    pass

# Schema for reading a product (includes ID and timestamps)
class Product(ProductBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        # orm_mode = True   # This will cause a warning in Pydantic V2
        from_attributes = True  # Updated for Pydantic V2

# Schema for updating a product
class ProductUpdate(BaseModel):
    product_name: Optional[str] = None
    description: Optional[str] = None
    product_price: Optional[int] = None
    selling_price: Optional[int] = None
    stock_quantity: Optional[int] = None
    image_url: Optional[str] = None

# Schema for product response
class ProductResponse(ProductCreate):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    vendor: Optional['VendorBase'] = None  # Add vendor relationship

    class Config:
        from_attributes = True


# Vendor Schema:
class VendorBase(BaseModel):
    name: str
    contact_person: Optional[str] = None
    email: EmailStr
    phone: Optional[str] = None
    address: Optional[str] = None

class VendorCreate(VendorBase):
    pass

class VendorUpdate(VendorBase):
    pass

class Vendor(VendorBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True




# Base Schema for Sale Input
class SaleCreate(BaseModel):
    pid: int
    quantity: int
    user_id: int

# Schema for Cart Item
class CartItem(BaseModel):
    product_id: int
    quantity: int
    selling_price: float

    @validator('quantity')
    def validate_quantity(cls, v):
        if v <= 0:
            raise ValueError('Quantity must be greater than 0')
        return v

# Schema for Cart Sale
class CartSaleCreate(BaseModel):
    user_id: int
    cart_items: List[CartItem]

    @validator('cart_items')
    def validate_cart_items(cls, v):
        if not v:
            raise ValueError('Cart items cannot be empty')
        return v

# Schema for Sale Response
class SaleResponse(BaseModel):
    id: int
    pid: int
    product_name: str
    quantity: int
    unit_price: float
    total_amount: float
    user_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# Schema for Sale Update
class SaleUpdate(BaseModel):
    pid: int
    user_id: int
    quantity: int
    price: float
    date: date

    class Config:
        from_attributes = True

# Schema for Sale Summary (used in user profile)
class SaleSummary(BaseModel):
    product_name: str
    quantity: int
    total_amount: float
    created_at: datetime

    class Config:
        from_attributes = True

class SaleItem(BaseModel):
    id: int
    pid: int
    quantity: int
    unit_price: float
    total_amount: float
    user_id: int
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

class TransactionResponse(BaseModel):
    id: int
    total_amount: float
    status: str
    created_at: datetime
    sales: List[SaleItem]

    class Config:
        from_attributes = True

# This schema for user profile:
class Statistics(BaseModel):
    total_sales: int
    total_products: int
    revenue: float

class ContactBase(BaseModel):
    name: str
    email: EmailStr
    subject: str
    message: str

class ContactCreate(ContactBase):
    pass

class ContactResponse(ContactBase):
    id: int
    created_at: datetime
    status: str  # e.g., 'pending', 'responded', 'closed'
    response: Optional[str] = None

    class Config:
        from_attributes = True


class ReplyCreate(BaseModel):
    reply: str

    class Config:
        from_attributes = True




class ImportHistoryBase(BaseModel):
    filename: str
    status: str
    total_rows: Optional[int]
    successful_rows: Optional[int]
    failed_rows: Optional[int]
    errors: Optional[List[Dict[str, Any]]]
    created_at: datetime
    completed_at: Optional[datetime]
    user_id: Optional[int]

    class Config:
        orm_mode = True

class ImportHistoryCreate(BaseModel):
    filename: str
    user_id: Optional[int]

class ImportHistoryResponse(ImportHistoryBase):
    id: int




class UserActivity(BaseModel):
    recent_sales: List[SaleResponse]
    recent_products: List[ProductBase]
    statistics: Statistics






# # Schema for Category:
# class CategoryBase(BaseModel):
#     name: str
#     description: Optional[str] = None
#     icon: Optional[str] = None

# class CategoryCreate(CategoryBase):
#     pass

# class Category(CategoryBase):
#     id: int
#     product_count: Optional[int] = 0
#     popular_products: Optional[List[dict]] = []

#     class Config:
#         # orm_mode = True   # This will cause a warning in Pydantic V2
#         from_attributes = True  # Updated for Pydantic V2


# STKPush Schemas
# class STKPushBase(BaseModel):
#     amount: float = Field(..., gt=0)
#     phone: str = Field(..., pattern="^254\d{9}$")

# class STKPushCreate(STKPushBase):
#     pass

# class STKPushResponse(STKPushBase):
#     id: int
#     merchant_request_id: str
#     checkout_request_id: str
#     trans_id: Optional[str] = None
#     created_at: datetime

#     class Config:
#         from_attributes = True


class PaymentBase(BaseModel):
    sale_id: int
    amount: float = Field(..., gt=0)
    mode: str
    trans_code: str

class PaymentCreate(PaymentBase):
    pass

class PaymentResponse(PaymentBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


# # STK Push Check Response
# class STKPushCheckResponse(BaseModel):
#     success: bool
#     message: str
#     data: Optional[STKPushResponse] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str

    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        if not re.search(r"[A-Za-z]", v):
            raise ValueError('Password must contain at least one letter')
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Password must contain at least one special character')
        return v


class UpdateSale(BaseModel):
    pid: int
    quantity: int
    user_id: int
    price: float
    date: datetime = Field(default_factory=datetime.now)

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class PaymentConfirmation(BaseModel):
    payment_mode: str  # e.g., "mpesa", "cash", "card"
    transaction_code: str



# MPESA Transaction Schemas
# STK Push Schemas
class STKPushCreate(BaseModel):
    phone_number: str
    amount: float

    @validator('phone_number')
    def validate_phone(cls, v):
        try:
            return format_phone_number(v)
        except ValueError as e:
            raise ValueError(str(e))

class STKPushResponse(BaseModel):
    checkout_request_id: str
    merchant_request_id: str
    status: str
    response_code: str = "0"  # Default value
    response_description: str = "Success. Request accepted for processing"  # Default value
    customer_message: str = "Please check your phone to complete the payment"  # Default value

class STKPushCheckResponse(BaseModel):
    success: bool
    message: str
    status: Optional[str] = None


class MPESACallback(BaseModel):
    merchant_request_id: str
    checkout_request_id: str
    result_code: str
    result_desc: str

