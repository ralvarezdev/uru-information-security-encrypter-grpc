import os

from dotenv import load_dotenv

from crypto import (
	load_private_key_from_file,
	BASE_DIR,
)

# Load environment variables from a .env file
load_dotenv()

# Load company's private key from PEM file
COMPANY_PRIVATE_KEY_FILENAME = "company_private_key.pem"
COMPANY_PRIVATE_KEY = load_private_key_from_file(os.path.join(BASE_DIR, COMPANY_PRIVATE_KEY_FILENAME))