import os

from dotenv import load_dotenv

from crypto.ed25519.load import load_private_key_from_file, load_public_key_from_file

# Load environment variables from a .env file
load_dotenv()

# Get the base directory of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

# Load company's private key from PEM file
COMPANY_PRIVATE_KEY_FILENAME = "company_private_key.pem"
COMPANY_PRIVATE_KEY = load_private_key_from_file(os.path.join(BASE_DIR, COMPANY_PRIVATE_KEY_FILENAME))

# Load tender's public key from PEM file
TENDER_PUBLIC_KEY_FILENAME = "tender_public_key.pem"
TENDER_PUBLIC_KEY = load_public_key_from_file(os.path.join(BASE_DIR, TENDER_PUBLIC_KEY_FILENAME))