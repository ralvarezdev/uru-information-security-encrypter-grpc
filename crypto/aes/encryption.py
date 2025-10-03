import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_key(length: int = 32) -> bytes:
	"""
    Generate a random AES symmetric key.

    Args:
        length (int): Length of the key in bytes. Default is 32 (256 bits).

    Returns:
        bytes: The generated AES symmetric key.
    """
	return base64.urlsafe_b64encode(os.urandom(length))

def generate_256_bits_key() -> bytes:
	"""
	Generate a random AES-256 symmetric key.

	Returns:
	    bytes: The generated AES-256 symmetric key.
	"""
	return generate_key(32)

def encrypt_file_with_symmetric_key(file_bytes: bytes, key: bytes) -> bytes:
	"""
    Encrypt file bytes using a symmetric key (Fernet/AES).

    Args:
        file_bytes (bytes): The file content to encrypt.
        key (bytes): The symmetric key (32 bytes for Fernet).

    Returns:
        bytes: The encrypted file content.
    """
	f = Fernet(key)
	encrypted = f.encrypt(file_bytes)
	return encrypted

def encrypt_symmetric_key_with_public_key(symmetric_key: bytes, public_key) -> bytes:
	"""
	Encrypt a symmetric key using a public key.

	Args:
		symmetric_key (bytes): The symmetric key to encrypt.
		public_key: The public key object for encryption.

	Returns:
		bytes: The encrypted symmetric key.
	"""
	encrypted_key = public_key.encrypt(
		symmetric_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	return encrypted_key