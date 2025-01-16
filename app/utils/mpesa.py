import requests
from base64 import b64encode
from datetime import datetime
from ..mpesa_config import *
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app import models
from app import schemas

# Get OAuth access token from Safaricom
def get_access_token():
    """Get OAuth access token from Safaricom"""
    try:
        if not CONSUMER_KEY or not CONSUMER_SECRET:
            raise ValueError("CONSUMER_KEY or CONSUMER_SECRET not set")

        credentials = b64encode(f"{CONSUMER_KEY}:{CONSUMER_SECRET}".encode()).decode()
        
        headers = {
            "Authorization": f"Basic {credentials}"
        }
        
        url = f"{BASE_URL}/oauth/v1/generate?grant_type=client_credentials"
        
        
        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )

        if response.status_code != 200:
            raise Exception(f"Auth failed: {response.status_code} - {response.text}")
            
        json_response = response.json()
        access_token = json_response.get("access_token")
        if not access_token:
            raise Exception("No access token in response")
            
        return access_token

    except Exception as e:
        print(f"Error getting access token: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get access token: {str(e)}")

# Generate password for STK Push
def generate_password(timestamp):
    """Generate password for STK Push"""
    try:
        data_to_encode = f"{BUSINESS_SHORT_CODE}{PASSKEY}{timestamp}"
        encoded_password = b64encode(data_to_encode.encode()).decode()
        print(f"Password generation data: {data_to_encode}")
        print(f"Generated password: {encoded_password}")
        return encoded_password
    except Exception as e:
        print(f"Error generating password: {str(e)}")
        raise

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

async def initiate_stk_push_request(phone_number: str, amount: float, access_token: str):
    """Handle the STK push request to Safaricom"""
    try:
        phone = format_phone_number(phone_number)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        password = generate_password(timestamp)
        
        payload = {
            "BusinessShortCode": str(BUSINESS_SHORT_CODE),
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(amount),
            "PartyA": phone,
            "PartyB": str(BUSINESS_SHORT_CODE),
            "PhoneNumber": phone,
            "CallBackURL": CALLBACK_URL,
            "AccountReference": "TestPay",
            "TransactionDesc": "Test Payment"
        }

        url = f"{BASE_URL}/mpesa/stkpush/v1/processrequest"
        
        

        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=30
        )
        
        
        if response.status_code != 200:
            error_msg = f"{response.status_code}: MPESA API error: {response.text}"
            print(f"Error: {error_msg}")
            raise HTTPException(status_code=response.status_code, detail=error_msg)
            
        return response.json()

    except HTTPException as he:
        raise he
    except Exception as e:
        error_msg = f"STK Push error: {str(e)}"
        print(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)


def check_transaction_status(merchant_request_id: str, checkout_request_id: str, db):
    """Check the status of an MPESATransaction"""
    transaction = db.query(models.MPESATransaction).filter(
        models.MPESATransaction.merchant_request_id == merchant_request_id,
        models.MPESATransaction.checkout_request_id == checkout_request_id).first()
    
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    return transaction




async def process_stk_push_callback(callback_data, db: Session):
    from app.schemas import MPESACallback 
    try:
        # Check if the transaction exists
        transaction = db.query(models.MPESATransaction).filter(
            models.MPESATransaction.merchant_request_id == callback_data.merchant_request_id,
            models.MPESATransaction.checkout_request_id == callback_data.checkout_request_id
        ).first()
        
        if not transaction:
            raise HTTPException(status_code=404, detail="Transaction not found")
        
        # Update transaction status
        if callback_data.result_code != "0":
            transaction.status = models.MPESAStatus.FAILED
            transaction.result_code = callback_data.result_code
            transaction.result_desc = callback_data.result_desc
            db.commit()
            return {
                "status": "failure",
                "message": "Transaction failed",
                "result_code": callback_data.result_code,
                "result_desc": callback_data.result_desc
            }
        
        # Success case
        transaction.status = models.MPESAStatus.COMPLETED
        transaction.result_code = callback_data.result_code
        transaction.result_desc = callback_data.result_desc
        db.commit()
        return {
            "status": "success",
            "message": "Transaction completed"
        }
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))




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