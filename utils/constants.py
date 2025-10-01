import os

from dotenv import load_dotenv
from cryptography import x509
from cryptography.x509.oid import NameOID

from utils.certificate import load_private_key_from_file, load_public_key_from_file

# Load environment variables from a .env file
load_dotenv()

# Load issuer's private key from PEM file
issuer_private_key = load_private_key_from_file(os.getenv("PRIVATE_KEY_PATH"))

# Load issuer's public key from PEM file
issuer_public_key = load_public_key_from_file(os.getenv("PUBLIC_KEY_PATH"))

# Load issuer details from environment variables
issuer_common_name = os.getenv("ISSUER_COMMON_NAME")
issuer_organization = os.getenv("ISSUER_ORGANIZATION")
issuer_organizational_unit = os.getenv("ISSUER_ORGANIZATIONAL_UNIT")
issuer_locality = os.getenv("ISSUER_LOCALITY")
issuer_state = os.getenv("ISSUER_STATE")
issuer_country = os.getenv("ISSUER_COUNTRY")

issuer_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, issuer_country),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, issuer_state),
	x509.NameAttribute(NameOID.LOCALITY_NAME, issuer_locality),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_organization),
	x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, issuer_organizational_unit),
	x509.NameAttribute(NameOID.COMMON_NAME, issuer_common_name),
])

# Load certificate validity period from environment variables
certificate_validity_days = int(os.getenv("CERTIFICATE_VALIDITY_DAYS"))

# Data path
data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "data")