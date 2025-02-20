from app.database import Base 
from sqlalchemy import Column, Integer, String,DateTime,ForeignKey,Text,func,JSON,Boolean,Enum,Float,Index,CheckConstraint
from datetime import datetime
from sqlalchemy.orm import relationship,validates
import enum # The enum module is used to define an enumeration of possible values for a column.
from sqlalchemy.orm import Session



# Company table:
class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    email = Column(String, nullable=False)
    location = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="active")  # active, inactive, suspended
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))  # Owner of the company
    trial_start = Column(DateTime, nullable=True)
    trial_end = Column(DateTime, nullable=True)
    is_trial = Column(Boolean, default=False)
    
    # Relationships
    users = relationship("Users", back_populates="company", foreign_keys="[Users.company_id]")
    products = relationship("Products", back_populates="company")
    sales = relationship("Sales", back_populates="company")
    transactions = relationship("Transactions", back_populates="company")
    payments = relationship("Payment", back_populates="company")
    imports = relationship("ImportHistory", back_populates="company")
    vendors = relationship("Vendor", back_populates="company")
    audit_logs = relationship("AuditLog", back_populates="company")
    contacts = relationship("Contact", back_populates="company")
    subscription = relationship("Subscription", back_populates="company")
    mpesa_transactions = relationship("MPESATransaction", back_populates="company")


# User table:
class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    full_name = Column(String, nullable=False)
    # phone = Column(String)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    company_role = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    company_id = Column(Integer, ForeignKey('companies.id'), nullable=True)
    
    # Relationships
    sales = relationship("Sales", back_populates='users')
    reset_tokens = relationship("PasswordResetTokens", back_populates="user", cascade="all, delete-orphan")
    transactions = relationship("Transactions", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    imports = relationship("ImportHistory", back_populates="user")
    
    # Single relationship to company with explicit foreign key
    company = relationship("Company", back_populates="users", foreign_keys=[company_id])





class PasswordResetTokens(Base):
    __tablename__ = "password_reset_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    
    user = relationship("Users", back_populates="reset_tokens")


# Products table:
class Products(Base):
    __tablename__ = 'products'
    id = Column(Integer, primary_key=True)
    product_name = Column(String(100), nullable=False)
    product_price = Column(Integer, nullable=False)
    selling_price = Column(Integer, nullable=False)
    description = Column(Text, nullable=True) 
    image_url = Column(String(255), nullable=True) 
    vendor_id = Column(Integer, ForeignKey('vendors.id'), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    vendor = relationship("Vendor", back_populates="products")
    sales = relationship("Sales", back_populates="products")
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    company = relationship("Company", back_populates="products")
    stock = relationship("ProductStock", uselist=False, back_populates="product")

    @validates('company_id')
    def validate_company(self, key, company_id):
        if not company_id:
            raise ValueError("Company ID is required")
        return company_id
    
# Product Stock table:
class ProductStock(Base):
    __tablename__ = 'product_stocks'
    id = Column(Integer, primary_key=True)
    product_id = Column(Integer, ForeignKey('products.id'), nullable=False)
    stock_quantity = Column(Integer, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    product = relationship("Products", back_populates="stock")



class Vendor(Base):
    __tablename__ = "vendors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    contact_person = Column(String, nullable=True)
    email = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    address = Column(String, nullable=True)
    company_id = Column(Integer, ForeignKey("companies.id"))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    company = relationship("Company", back_populates="vendors")

    #
    products = relationship("Products", back_populates="vendor")



# Sales table:
class Sales(Base):
    __tablename__ = "sales"

    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, ForeignKey("products.id"))
    quantity = Column(Integer)
    unit_price = Column(Float, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, nullable=False, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)

    # Add relationships
    products = relationship("Products", back_populates="sales")
    users = relationship("Users", back_populates="sales")
    payments = relationship("Payment", back_populates="sale")
    transactions = relationship("Transactions", 
                                secondary="transaction_sales",
                                backref="sales")
    company = relationship("Company", back_populates="sales")


# Transactions table:
class Transactions(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    company_id = Column(Integer, ForeignKey("companies.id"))
    total_amount = Column(Float)
    status = Column(String)  # pending, completed, cancelled
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("Users", back_populates="transactions")
    company = relationship("Company", back_populates="transactions")


# Join table for transactions and sales
class TransactionSales(Base):
    __tablename__ = "transaction_sales"

    transaction_id = Column(Integer, ForeignKey("transactions.id"), primary_key=True)
    sale_id = Column(Integer, ForeignKey("sales.id"), primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Add relationships
    company = relationship("Company")

    __table_args__ = (
        Index('idx_transaction_sale', transaction_id, sale_id),
    )


# Contact table:
class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String)
    subject = Column(String)
    message = Column(Text)
    response = Column(Text, nullable=True)
    status = Column(String, default="open")
    company_id = Column(Integer, ForeignKey("companies.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    responded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    company = relationship("Company", back_populates="contacts")
    responder = relationship("Users", foreign_keys=[responded_by])
    updater = relationship("Users", foreign_keys=[updated_by])


# ImportHistory table:
class ImportHistory(Base):
    __tablename__ = "import_history"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    status = Column(String)  # processing, completed, failed
    total_rows = Column(Integer, default=0)
    successful_rows = Column(Integer, default=0)
    failed_rows = Column(Integer, default=0)
    errors = Column(JSON, nullable=True)
    company_id = Column(Integer, ForeignKey("companies.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    company = relationship("Company", back_populates="imports")
    user = relationship("Users", back_populates="imports")





class PaymentType(str, enum.Enum):
    SALE = "sale"
    SUBSCRIPTION = "subscription"

class PaymentStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

class Payment(Base):
    __tablename__ = "payments"
    
    id = Column(Integer, primary_key=True, index=True)
    sale_id = Column(Integer, ForeignKey("sales.id"), nullable=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=True)
    amount = Column(Float, nullable=False)
    mode = Column(String, nullable=False)  # mpesa, cash, card
    transaction_code = Column(String, nullable=True)
    payment_type = Column(Enum(PaymentType), nullable=False, default=PaymentType.SALE)
    status = Column(Enum(PaymentStatus), default=PaymentStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    company_id = Column(Integer, ForeignKey('companies.id'), nullable=False)
    
    # Relationships
    company = relationship("Company", back_populates="payments")
    sale = relationship("Sales", back_populates="payments")
    subscription = relationship("Subscription", back_populates="payment")



#  Enum class
class MPESAStatus(str, enum.Enum):
    PENDING = 'pending'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'
    TIMEOUT = 'timeout'

class MPESATransaction(Base):
    __tablename__ = "mpesa_transactions"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True)
    
    # MPESA Request Identifiers
    checkout_request_id = Column(String, unique=True)
    merchant_request_id = Column(String, unique=True)
    
    # Transaction Details
    phone_number = Column(String)
    amount = Column(Float)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    
    # Status Tracking
    status = Column(
        Enum(MPESAStatus, name='mpesa_status_enum'),
        default=MPESAStatus.PENDING,
        nullable=False
    )
    
    # MPESA Response Details
    result_code = Column(String, nullable=True)
    result_desc = Column(String, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    company = relationship("Company", back_populates="mpesa_transactions")






# Subscription Status Enum:
class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    PENDING = "pending"


# Subscription Plan table:
class SubscriptionPlan(Base):
    __tablename__ = "subscription_plans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    description = Column(String)
    features = Column(String)  
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    subscriptions = relationship("Subscription", back_populates="plan")


# Subscription table:
class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    plan_id = Column(Integer, ForeignKey("subscription_plans.id"), nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    status = Column(String, default="active")  # active, expired, cancelled
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    company = relationship("Company", back_populates="subscription")
    plan = relationship("SubscriptionPlan", back_populates="subscriptions")
    created_by_user = relationship("Users", foreign_keys=[created_by])
    payment = relationship("Payment", back_populates="subscription", uselist=False)










# class STKPush(Base):
#     __tablename__ = "stk_push"
    
#     id = Column(Integer, primary_key=True, index=True)
#     merchant_request_id = Column(String)
#     checkout_request_id = Column(String)
#     amount = Column(Float)
#     phone = Column(String)
#     trans_id = Column(String, nullable=True)
#     created_at = Column(DateTime, default=datetime.utcnow)














    
# Category table
# class Category(Base):
#     __tablename__ = "categories"

#     id = Column(Integer, primary_key=True, index=True)
#     name = Column(String(100), unique=True, index=True)
#     description = Column(Text)
#     icon = Column(String(255))  # رابط الأيقونة
#     products = relationship("Products", back_populates="category")


# class Category(Base):
#     __tablename__ = 'categories'

#     id = Column(Integer, primary_key=True, index=True)
#     name = Column(String, unique=True, index=True, nullable=False)
#     description = Column(String, nullable=True)
#     created_at =  Column(DateTime, onupdate=datetime.utcnow, default=datetime.utcnow)
#     updated_at =  Column(DateTime, onupdate=datetime.utcnow, default=datetime.utcnow)





class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    action = Column(String, nullable=False)  # "create", "update", "delete", etc.
    entity_type = Column(String, nullable=False)  # "product", "user", "sale", etc.
    entity_id = Column(Integer)
    details = Column(JSON, nullable=True)  # Store any additional info as JSON
    
    # Who did it and which company
    user_id = Column(Integer, ForeignKey("users.id"))
    company_id = Column(Integer, ForeignKey("companies.id"))
    
    # When it happened
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("Users", back_populates="audit_logs")
    company = relationship("Company", back_populates="audit_logs")

# its a simple method to create a log entry 
    @classmethod
    def log(cls, db: Session, **kwargs):
        """Simple method to create a log entry"""
        try:
            log = cls(**kwargs)
            db.add(log)
            db.commit()
        except Exception as e:
            print(f"Error logging action: {str(e)}")














    
# Category table
# class Category(Base):
#     __tablename__ = "categories"

#     id = Column(Integer, primary_key=True, index=True)
#     name = Column(String(100), unique=True, index=True)
#     description = Column(Text)
#     icon = Column(String(255))  # رابط الأيقونة
#     products = relationship("Products", back_populates="category")


# class Category(Base):
#     __tablename__ = 'categories'

#     id = Column(Integer, primary_key=True, index=True)
#     name = Column(String, unique=True, index=True, nullable=False)
#     description = Column(String, nullable=True)
#     created_at =  Column(DateTime, onupdate=datetime.utcnow, default=datetime.utcnow)
#     updated_at =  Column(DateTime, onupdate=datetime.utcnow, default=datetime.utcnow)










