import hashlib


def sign_file_with_private_key(file_bytes: bytes, private_key) -> bytes:
	"""
	Sign a file using the provided private key.

	Args:
		file_bytes: The file to sign.
		private_key: The private key object for signing.

	Returns:
		bytes: The signature of the file.
	"""
	# Hash its contents
	file_hash = hashlib.sha256(file_bytes).digest()

	# Sign the hash
	signature = private_key.sign(file_hash)
	return signature
