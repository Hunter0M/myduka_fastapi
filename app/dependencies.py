from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
import app.models as models
from app.database import get_db
from app.auth import get_current_user
from app.schemas import UserResponse

async def get_current_company(
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    company = db.query(models.Company).filter(
        models.Company.user_id == current_user.id,
        models.Company.status == "active"
    ).first()
    
    if not company:
        raise HTTPException(
            status_code=404,
            detail="No active company found for current user"
        )
    
    # Check if subscription is active
    active_subscription = db.query(models.Subscription).filter(
        models.Subscription.company_id == company.id,
        models.Subscription.status == "active"
    ).first()
    
    if not active_subscription:
        raise HTTPException(
            status_code=403,
            detail="No active subscription found. Please subscribe to continue."
        )
    
    return company 