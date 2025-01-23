from pydantic import BaseModel, EmailStr, validator, Field
from datetime import date
from typing import Optional, List, Dict, Any
from datetime import datetime
import re
from app.utils.mpesa import format_phone_number
from enum import Enum
from datetime import timedelta



# Pydantic model for user creation
class UserBase(BaseModel):
    """المخطط الأساسي للمستخدم"""
    email: EmailStr
    first_name: str
    last_name: str
    phone: str
    is_admin: bool = False

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
    company_role: Optional[str] = None

    @validator('company_role')
    def validate_company_role(cls, v):
        if v:
            valid_roles = ['owner', 'admin', 'staff']
            if v.lower() not in valid_roles:
                raise ValueError(f'Role must be one of: {", ".join(valid_roles)}')
            return v.lower()
        return v

    @validator('email')
    def validate_email(cls, v):
        if v:
            return v.lower().strip()
        return v

    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        if v and not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip() if v else v

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

class UserResponse(BaseModel):
    """مخطط استجابة بيانات المستخدم مع معلومات الشركة"""
    id: int
    email: str
    first_name: str
    last_name: str
    phone: str
    is_admin: bool
    company_role: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

# New schema for user with detailed company info
class UserWithCompany(UserResponse):
    """مخطط المستخدم مع تفاصيل الشركة الكاملة"""
    company: Optional['CompanyResponse'] = None

    class Config:
        from_attributes = True

# New schema for user role in company
class UserCompanyRole(BaseModel):
    """مخطط دور المستخدم في الشركة"""
    role: str = Field(..., description="User's role in the company (owner, admin, staff)")
    permissions: list[str] = []

    @validator('role')
    def validate_role(cls, v):
        valid_roles = ['owner', 'admin', 'staff']
        if v.lower() not in valid_roles:
            raise ValueError(f'Role must be one of: {", ".join(valid_roles)}')
        return v.lower()
    

class UserCompanyAssignment(BaseModel):
    """مخطط تعيين المستخدم للشركة"""
    user_id: int
    company_id: int
    role: str = Field(..., description="User's role in the company")

    @validator('role')
    def validate_role(cls, v):
        valid_roles = ['owner', 'admin', 'staff']
        if v.lower() not in valid_roles:
            raise ValueError(f'Role must be one of: {", ".join(valid_roles)}')
        return v.lower()

# New schema for company user list
class CompanyUser(BaseModel):
    """مخطط مستخدم الشركة"""
    user_id: int
    email: EmailStr
    first_name: str
    last_name: str
    role: str
    joined_at: datetime

    class Config:
        from_attributes = True


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
    company_id: Optional[int] = None

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

# First, create a simplified vendor schema for product responses
class VendorInProduct(BaseModel):
    id: int
    name: str
    contact_person: Optional[str] = None
    email: Optional[str] = None  # No validation here
    phone: Optional[str] = None
    address: Optional[str] = None

    class Config:
        from_attributes = True

# Update the ProductResponse schema to use the simplified vendor schema
class ProductResponse(BaseModel):
    id: int
    product_name: str
    product_price: int
    selling_price: int
    stock_quantity: int
    description: Optional[str] = None
    image_url: Optional[str] = None
    vendor_id: Optional[int] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    vendor: Optional[VendorInProduct] = None
    company_id: int

    class Config:
        from_attributes = True


# Vendor Schema:
class VendorBase(BaseModel):
    name: str
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    company_id: Optional[int] = None

    @validator('email')
    def validate_email(cls, v):
        if v is not None and v != "":
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
                raise ValueError('Invalid email format')
        return v

class VendorCreate(BaseModel):
    name: str
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None

class VendorUpdate(BaseModel):
    name: Optional[str] = None
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None

class Vendor(BaseModel):
    id: int
    name: str
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    company_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class VendorResponse(BaseModel):
    id: int
    name: str
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    company_id: int
    created_at: datetime

    class Config:
        from_attributes = True




# Base Schema for Sale Input
class SaleCreate(BaseModel):
    pid: int
    quantity: int
    user_id: int
    company_id: Optional[int] = None

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
    company_id: int
    status: str
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
    company_id: int
    sales: List[SaleResponse]

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

class ContactCreate(BaseModel):
    name: str
    email: str
    subject: str
    message: str

class ContactResponse(BaseModel):
    id: int
    name: str
    email: str
    subject: str
    message: str
    status: str
    response: Optional[str]
    company_id: int
    created_at: datetime
    updated_at: Optional[datetime]
    responded_by: Optional[int]

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
    company_id: Optional[int]

    class Config:
        orm_mode = True

class ImportHistoryCreate(BaseModel):
    filename: str
    user_id: Optional[int]

class ImportHistoryResponse(BaseModel):
    id: int
    filename: str
    status: str
    total_rows: int
    successful_rows: int
    failed_rows: int
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True

class ImportHistoryDetailResponse(ImportHistoryResponse):
    errors: Optional[List[dict]]
    company_id: int
    user_id: int

    class Config:
        from_attributes = True

class UserActivity(BaseModel):
    recent_sales: List[SaleResponse]
    recent_products: List[ProductBase]
    statistics: Statistics



class PaymentType(str, Enum): #.
    SALE = "sale"
    SUBSCRIPTION = "subscription"

class PaymentStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

class PaymentBase(BaseModel): #.
    amount: float
    mode: str
    transaction_code: Optional[str] = None
    payment_type: PaymentType
    status: PaymentStatus = PaymentStatus.PENDING

class PaymentCreate(PaymentBase): #.
    sale_id: Optional[int] = None
    subscription_id: Optional[int] = None

class Payment(PaymentBase): #.
    id: int
    created_at: datetime
    sale_id: Optional[int]
    subscription_id: Optional[int]

    class Config:
        from_attributes = True



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
    quantity: int
    price: float
    date: datetime
    user_id: int
    pid: int

class StockUpdateInfo(BaseModel):
    product_id: int
    product_name: str
    new_stock: int

class SaleUpdateResponse(BaseModel):
    message: str
    sale: dict
    stock_update: StockUpdateInfo

    class Config:
        from_attributes = True

class PaymentConfirmation(BaseModel):
    payment_mode: str
    transaction_code: str

class PaymentResponse(BaseModel):
    mode: str
    transaction_code: str
    created_at: datetime

    class Config:
        from_attributes = True

class TransactionConfirmResponse(BaseModel):
    id: int
    total_amount: float
    status: str
    company_id: int
    payment: PaymentResponse
    sales_count: int
    updated_at: datetime

    class Config:
        from_attributes = True


# MPESA Transaction Schemas
# STK Push Schemas
class STKPushCreate(BaseModel): #.
    phone_number: str
    amount: float

    @validator('phone_number')
    def validate_phone(cls, v):
        try:
            return format_phone_number(v)
        except ValueError as e:
            raise ValueError(str(e))

class STKPushResponse(BaseModel): #.
    checkout_request_id: str
    merchant_request_id: str
    status: str
    response_code: str = "0"  # Default value
    response_description: str = "Success. Request accepted for processing"  # Default value
    customer_message: str = "Please check your phone to complete the payment"  # Default value

class STKPushCheckResponse(BaseModel): #.
    success: bool
    message: str
    status: Optional[str] = None


# MPESACallback schema
class MPESACallback(BaseModel):
    MerchantRequestID: str
    CheckoutRequestID: str
    ResultCode: int
    ResultDesc: str
    
    class Config:
        from_attributes = True


# Start schemas for Company 
class CompanyBase(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    location: Optional[str] = None
    description: Optional[str] = None

class CompanyCreate(CompanyBase):
    pass

class CompanyUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    location: Optional[str] = None

class CompanyResponse(BaseModel):
    id: int
    name: str
    phone: str
    email: str
    location: str
    user_id: int
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

# End company schemas


# Start schemas for Subscription
class SubscriptionPlanBase(BaseModel):
    name: str
    price: float
    description: Optional[str] = None
    features: Optional[str] = None

class SubscriptionPlanCreate(SubscriptionPlanBase):
    pass

class SubscriptionPlan(SubscriptionPlanBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class SubscriptionBase(BaseModel):
    company_id: int
    plan_id: int

class SubscriptionCreate(SubscriptionBase):
    pass

class Subscription(BaseModel):
    id: int
    company_id: int
    plan_id: int
    start_date: datetime
    end_date: datetime
    status: str
    created_by: int
    created_at: datetime
    plan: SubscriptionPlan  # Include the plan details in the response

    class Config:
        from_attributes = True

class SubscriptionResponse(Subscription):
    pass

class SaleItemResponse(BaseModel):
    id: int
    product_id: int
    quantity: int
    unit_price: float
    total: float
    status: str

class TransactionInfo(BaseModel):
    id: int
    status: str
    total_amount: float
    company_id: int
    created_at: datetime
    updated_at: datetime

class SaleConfirmationResponse(BaseModel):
    message: str
    transaction: TransactionInfo
    sales: List[SaleItemResponse]
    stock_updates: List[StockUpdateInfo]

    class Config:
        from_attributes = True

class TransactionCancelResponse(BaseModel):
    message: str
    transaction: dict

class SaleDetailResponse(BaseModel):
    id: int
    pid: int
    user_id: int
    first_name: str
    quantity: int
    created_at: datetime
    product_name: str
    product_price: float
    total_amount: float
    company_id: int
    status: str

    class Config:
        from_attributes = True

class UserSaleResponse(BaseModel):
    id: int
    pid: int
    user_id: int
    first_name: str
    quantity: int
    created_at: datetime
    total_amount: float
    company_id: int
    status: str

    class Config:
        from_attributes = True

class StatusUpdate(BaseModel):
    status: str

class ImportError(BaseModel):
    row: Optional[int]
    product_name: Optional[str]
    error: str

class ImportResponse(BaseModel):
    import_id: int
    message: str
    total_processed: int
    successful: int
    failed: int
    errors: Optional[List[ImportError]]
    company_id: int

    class Config:
        from_attributes = True

class ValidationError(BaseModel):
    row: Optional[int] = None
    product: Optional[str] = None
    message: Optional[str] = None
    errors: Optional[List[str]] = None

class ImportValidationResponse(BaseModel):
    valid: bool
    total_rows: int
    errors: Optional[List[ValidationError]] = None

class ProductBasic(BaseModel):
    id: int
    product_name: str
    product_price: float
    selling_price: float
    stock_quantity: int
    created_at: datetime

    class Config:
        from_attributes = True

class VendorDetailResponse(BaseModel):
    id: int
    name: str
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    company_id: int
    created_at: datetime
    products: List['ProductBasic']

    class Config:
        from_attributes = True

class MessageResponse(BaseModel):
    message: str
    status: bool = True
    data: Optional[Any] = None

    class Config:
        from_attributes = True

