import os
from dotenv import load_dotenv

load_dotenv()

# M-PESA API Configuration
CONSUMER_KEY = os.getenv('MPESA_CONSUMER_KEY', "5EIATIon4GVbYHDlT4LZGaPZGPuFGTvy5tGMQD9C1wnsMExo")
CONSUMER_SECRET = os.getenv('MPESA_CONSUMER_SECRET', "eqG2w8rfONEEsVEMIitYAsU7pJWKYZvVjZnG1WqtynsHjhYwRHjbTm4aorXpNlQH")
BUSINESS_SHORT_CODE = os.getenv('MPESA_BUSINESS_SHORT_CODE', "174379")
PASS_KEY = os.getenv('MPESA_PASS_KEY', "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919")
BASE_URL = "https://sandbox.safaricom.co.ke"

# Callback URLs
CALLBACK_URL = os.getenv('MPESA_CALLBACK_URL', "https://your-domain.com/api/mpesa-callback")

# Export all variables
__all__ = [
    'CONSUMER_KEY',
    'CONSUMER_SECRET',
    'BUSINESS_SHORT_CODE',
    'PASS_KEY',
    'BASE_URL',
    'CALLBACK_URL'
]