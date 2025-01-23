import requests
import base64
from datetime import datetime
from ..mpesa_config import (
    CONSUMER_KEY, 
    CONSUMER_SECRET, 
    BUSINESS_SHORT_CODE, 
    PASS_KEY, 
    BASE_URL, 
    CALLBACK_URL
)
from fastapi import HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
from app import models

def validate_mpesa_config():
    """Validate MPESA configuration"""
    missing_vars = []
    if not CONSUMER_KEY:
        missing_vars.append("CONSUMER_KEY")
    if not CONSUMER_SECRET:
        missing_vars.append("CONSUMER_SECRET")
    if not BUSINESS_SHORT_CODE:
        missing_vars.append("BUSINESS_SHORT_CODE")
    if not PASS_KEY:
        missing_vars.append("PASS_KEY")
    if not CALLBACK_URL:
        missing_vars.append("CALLBACK_URL")
    
    if missing_vars:
        raise ValueError(f"Missing required MPESA configuration: {', '.join(missing_vars)}")

# Call validation on module load
try:
    validate_mpesa_config()
except ValueError as e:
    print(f"MPESA Configuration Error: {str(e)}")

# Print configuration for debugging (remove in production)
print("Using MPESA configuration:")
print(f"CONSUMER_KEY: ...{CONSUMER_KEY[-4:] if CONSUMER_KEY else 'None'}")
print(f"BUSINESS_SHORT_CODE: {BUSINESS_SHORT_CODE}")
print(f"CALLBACK_URL: {CALLBACK_URL}")

# Get OAuth access token from Safaricom
async def get_access_token() -> str:
    """Get access token from Safaricom"""
    try:
        validate_mpesa_config()
        
        auth = base64.b64encode(f"{CONSUMER_KEY}:{CONSUMER_SECRET}".encode()).decode('utf-8')
        headers = {
            'Authorization': f'Basic {auth}'
        }
        
        response = requests.get(
            f'{BASE_URL}/oauth/v1/generate?grant_type=client_credentials',
            headers=headers,
            timeout=30
        )
        
        print("Token Response Status:", response.status_code)
        print("Token Response Body:", response.text)
        
        if response.status_code == 200:
            result = response.json()
            if 'access_token' in result:
                return result['access_token']
            else:
                raise ValueError("Access token not found in response")
        else:
            raise ValueError(f"Failed to get access token: {response.text}")
            
    except Exception as e:
        raise ValueError(f"Failed to get MPESA access token: {str(e)}")

# Generate password for STK Push
def generate_password() -> str:
    """Generate the password for the STK push"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    data_to_encode = f"{BUSINESS_SHORT_CODE}{PASS_KEY}{timestamp}"
    return base64.b64encode(data_to_encode.encode()).decode('utf-8')

# Format phone number to required format (254XXXXXXXXX)
def format_phone_number(phone: str) -> str:
    """
    Format phone number to required format (254XXXXXXXXX)
    Accepts formats:
    - +254799911154
    - 254799911154
    - 0799911154
    - 799911154
    """
    try:
        # Remove any whitespace
        phone = phone.strip()
        
        # Remove any special characters
        phone = phone.replace("+", "").replace(" ", "").replace("-", "")
        
        # Check if the number starts with 254
        if phone.startswith("254"):
            # Already in correct format
            formatted_number = phone
            
        # Check if the number starts with 0
        elif phone.startswith("0"):
            # Remove 0 and add 254
            formatted_number = "254" + phone[1:]
            
        # Check if it's just the core number (9 digits)
        elif len(phone) == 9:
            # Add 254 prefix
            formatted_number = "254" + phone
            
        else:
            raise ValueError("Invalid phone number format")

        # Validate the final format
        if not formatted_number.startswith("254") or len(formatted_number) != 12:
            raise ValueError("Invalid phone number format")

        return formatted_number

    except Exception as e:
        raise ValueError(f"Invalid phone number: {str(e)}")

async def initiate_stk_push_request(phone_number: str, amount: float, access_token: str) -> Dict[str, Any]:
    """Initiate STK push request to Safaricom"""
    try:
        validate_mpesa_config()
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password = base64.b64encode(f"{BUSINESS_SHORT_CODE}{PASS_KEY}{timestamp}".encode()).decode('utf-8')
        
        # Format phone number
        formatted_phone = phone_number
        if phone_number.startswith('0'):
            formatted_phone = '254' + phone_number[1:]
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "BusinessShortCode": BUSINESS_SHORT_CODE,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(amount),
            "PartyA": formatted_phone,
            "PartyB": BUSINESS_SHORT_CODE,
            "PhoneNumber": formatted_phone,
            "CallBackURL": CALLBACK_URL,
            "AccountReference": "MyDuka",
            "TransactionDesc": "Payment for goods/services" 
        }
        
        print("STK Push Request Payload:", payload)
        print("STK Push Headers:", headers)
        
        response = requests.post(
            f'{BASE_URL}/mpesa/stkpush/v1/processrequest',
            json=payload,
            headers=headers,
            timeout=30
        )
        
        print("STK Push Response Status:", response.status_code)
        print("STK Push Response Body:", response.text)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise ValueError(f"MPESA API error: {response.text}")
            
    except Exception as e:
        raise ValueError(str(e))

def check_transaction_status(merchant_request_id: str, checkout_request_id: str, db):
    """Check the status of an MPESATransaction"""
    transaction = db.query(models.MPESATransaction).filter(
        models.MPESATransaction.merchant_request_id == merchant_request_id,
        models.MPESATransaction.checkout_request_id == checkout_request_id).first()
    
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    return transaction

async def process_stk_push_callback(
    callback_data: Dict[str, Any],
    db: Session, 
    company_id: int
) -> Dict[str, Any]:
    """Process STK push callback from Safaricom"""
    try:
        from app.models import MPESATransaction, MPESAStatus
        
        # Find the transaction
        transaction = db.query(MPESATransaction).filter(
            MPESATransaction.checkout_request_id == callback_data["CheckoutRequestID"],
            MPESATransaction.company_id == company_id
        ).first()
        
        if not transaction:
            return {
                "success": False,
                "message": "Transaction not found"
            }
            
        # Update transaction status
        if callback_data["ResultCode"] == 0:
            transaction.status = MPESAStatus.COMPLETED
        else:
            transaction.status = MPESAStatus.FAILED
            
        transaction.result_code = str(callback_data["ResultCode"])
        transaction.result_desc = callback_data["ResultDesc"]
        
        db.commit()
        
        return {
            "success": True,
            "message": "Callback processed successfully"
        }
        
    except Exception as e:
        db.rollback()
        print(f"Error processing callback: {str(e)}")
        return {
            "success": False,
            "message": f"Error processing callback: {str(e)}"
        }

# # This is on function that sends the STK Push request to Safaricom >>   
# def stk_push_sender(mobile, amount):
#     try:
#         encoded_credentials = base64.b64encode(f"{consumer_key}:{consumer_secret}".encode()).decode()
#         headers = {"Authorization": f"Basic {encoded_credentials}","Content-Type": "application/json"}
#         url = saf_url+"/oauth/v1/generate?grant_type=client_credentials"
#         #Send the request and parse the response
#         response = requests.get(url, headers=headers).json()

#         # Check for errors and return the access token
#         if "access_token" in response:
#             token = response["access_token"]
#         else:
#             raise Exception("Failed to get access token: " + response["error_description"])
#     except Exception as e:
#         raise Exception("Failed to get access token: " + str(e)) 

#     timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

#     stk_password = base64.b64encode((short_code + pass_key + timestamp).encode('utf-8')).decode()

#     url = saf_url + "mpesa/stkpush/v1/processrequest"
#     headers = {'Authorization': 'Bearer ' + token,'Content-Type': 'application/json'}

#     request = {"BusinessShortCode": short_code,"Password": stk_password , "Timestamp": timestamp,
#                "TransactionType": "CustomerPayBillOnline","Amount": str(amount), "PartyA": str(mobile),
#                "PartyB": short_code, "PhoneNumber": str(mobile), "CallBackURL": callback_url,
#                "AccountReference" : "myduka1", "TransactionDesc" : "Testing STK Push"}

#     response = requests.post(url, json = request, headers = headers)
#     return response.text

# stk_push_sender("254714056473", 1)































# def check_transaction_status(merchant_request_id: str, checkout_request_id: str, db):
#     """Check the status of an MPESATransaction"""
#     transaction = db.query(models.MPESATransaction).filter(
#         models.MPESATransaction.merchant_request_id == merchant_request_id,
#         models.MPESATransaction.checkout_request_id == checkout_request_id
#     ).first()
    
#     if not transaction:
#         return None
    
#     return transaction