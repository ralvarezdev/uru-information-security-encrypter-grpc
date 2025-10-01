from typing import LiteralString

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt_file_bytes(
	file_bytes: bytes,
	public_key,
	):
	"""
	Encrypt a file using the provided public key.

	Args:
		file_bytes (bytes): The file content to encrypt.
		public_key: The public key object for encryption.

	Returns:
		bytes: The encrypted file content.
	"""
	# Encrypt the file using ED25519 public key
	encrypted = public_key.encrypt(
		file_bytes,
	)
	return encrypted

def encrypt_and_save_file(
	file_path: LiteralString | str | bytes,
	public_key,
	certificate_bytes: bytes,
	output_file_path: LiteralString | str | bytes,
	output_cert_path: LiteralString | str | bytes,
	):
	"""
	Encrypt a file and save the encrypted content to a new file.

	Args:
		file_path (str): Path to the input file to encrypt.
		public_key: The public key object for encryption.
		certificate_bytes (bytes): The certificate bytes to include with the encrypted file.
		output_file_path (str): Path to save the encrypted file.
		output_cert_path (str, optional): Path to save the certificate file.
		
	Returns:
		None
	"""
	# Read the file content
	with open(file_path, 'rb') as f:
		file_bytes = f.read()

	# Encrypt the file content
	encrypted_file_bytes = encrypt_file_bytes(file_bytes, public_key)

	# Save the encrypted content to a new file
	with open(output_file_path, 'wb') as f:
		f.write(encrypted_file_bytes)
		
	# Encrypt the certificate bytes
	encrypted_cert_bytes = encrypt_file_bytes(certificate_bytes, public_key)
		
	# Save the certificate bytes to a separate file
	with open(output_cert_path, 'wb') as f:
		f.write(encrypted_cert_bytes)
	