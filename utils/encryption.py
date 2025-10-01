from typing import LiteralString

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt_file(
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
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None,
			)
		)
	return encrypted

def encrypt_and_save_file(
	file_path: LiteralString | str | bytes,
	public_key,
	output_path: LiteralString | str | bytes,
	):
	"""
	Encrypt a file and save the encrypted content to a new file.

	Args:
		file_path (str): Path to the input file to encrypt.
		public_key: The public key object for encryption.
		output_path (str): Path to save the encrypted file.

	Returns:
		None
	"""
	# Read the file content
	with open(file_path, 'rb') as f:
		file_bytes = f.read()

	# Encrypt the file content
	encrypted_bytes = encrypt_file(file_bytes, public_key)

	# Save the encrypted content to a new file
	with open(output_path, 'wb') as f:
		f.write(encrypted_bytes)