from datetime import datetime, timezone
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
    # First, check if user has a company_id
    if not current_user.company_id:
        raise HTTPException(
            status_code=404,
            detail="User is not associated with any company"
        )

    # Debug: Print company_id
    print(f"Looking for company with ID: {current_user.company_id}")
    
    # Query the company
    company = db.query(models.Company).filter(
        models.Company.id == current_user.company_id
    ).first()
    
    if not company:
        raise HTTPException(
            status_code=404,
            detail="Company not found"
        )
    
    # Check if company is active
    if company.status != "active":
        raise HTTPException(
            status_code=403,
            detail=f"Company is not active. Status: {company.status}"
        )

    # Get trial subscription instead of using company.trial_end
    if company.is_trial:
        trial_subscription = db.query(models.Subscription).filter(
            models.Subscription.company_id == company.id,
            models.Subscription.status == "active"
        ).first()

        if trial_subscription and trial_subscription.end_date:
            # Make both timestamps timezone-aware
            now = datetime.now(timezone.utc)
            end_date = trial_subscription.end_date
            
            # Make end_date timezone-aware if it isn't already
            if end_date.tzinfo is None:
                end_date = end_date.replace(tzinfo=timezone.utc)
            
            if now > end_date:
                # Trial has expired
                trial_subscription.status = "expired"
                company.is_trial = False
                db.commit()
                raise HTTPException(
                    status_code=403,
                    detail="Trial period has expired. Please subscribe to continue."
                )
        else:
            # No valid trial subscription found
            company.is_trial = False
            db.commit()
    
    # Check for active paid subscription if not in trial
    if not company.is_trial:
        active_subscription = db.query(models.Subscription).filter(
            models.Subscription.company_id == company.id,
            models.Subscription.status == "active",
            models.Subscription.end_date > datetime.now(timezone.utc)
        ).first()
        
        if not active_subscription:
            raise HTTPException(
                status_code=403,
                detail="No active subscription found. Please subscribe to continue."
            )
    
    return company 