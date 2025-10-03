from argparse import ArgumentParser
from concurrent import futures
import logging
import base64

import grpc

from ralvarezdev import encrypter_pb2
from ralvarezdev import encrypter_pb2_grpc
from ralvarezdev import decrypter_pb2
from crypto.aes.encryption import (
	encrypt_file_with_symmetric_key,
	generate_256_bits_key,
	encrypt_symmetric_key_with_public_key,
)
from crypto.ed25519 import (
	TENDER_PUBLIC_KEY,
	COMPANY_PRIVATE_KEY,
)
from microservice.grpc.decrypter import create_grpc_client
from microservice.grpc import (
	DECRYPTER_GRPC_HOST,
	DECRYPTER_GRPC_PORT
)
from crypto.sha.signature import sign_file_with_private_key

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EncrypterServicer(encrypter_pb2_grpc.EncrypterServicer):
	def SendEncryptedFile(self, request_iterator, context):
		# Get the certificate bytes from metadata
		cert_bytes = None
		for key, value in context.invocation_metadata():
			if key == 'certificate':
				cert_bytes = base64.b64decode(value)
				break
		if not cert_bytes:
			context.set_code(grpc.StatusCode.UNAUTHENTICATED)
			context.set_details('Certificate metadata is required')
			logger.error("Missing certificate metadata")
			return encrypter_pb2.Empty()

		# Accumulate file chunks
		file_bytes = bytearray()
		filename = ""

		# Process each chunk in the stream
		for request in request_iterator:
			# Validate request
			if not request.filename or not request.content:
				context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
				context.set_details('Filename and content are required')
				logger.error("Invalid request: missing filename or content")
				return encrypter_pb2.Empty()

			# Ensure all chunks belong to the same file
			if not filename:
				filename = request.filename
			elif filename != request.filename:
				context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
				context.set_details('All chunks must have the same filename')
				logger.error("All chunks must have the same filename")
				return encrypter_pb2.Empty

			# Append chunk to the file bytes
			file_bytes.extend(request.content)
			if not file_bytes:
				context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
				context.set_details('No file data received')
				logger.error("No file data received")
				return encrypter_pb2.Empty()

		# Iterate over received files and print their sizes
		total_bytes = len(file_bytes)
		logger.info(f"Received file: {filename}, Size: {total_bytes} bytes")

		# Generate AES symmetric key
		symmetric_key = generate_256_bits_key()

		# Encrypt the file with the symmetric key
		encrypted_file_bytes = encrypt_file_with_symmetric_key(
			file_bytes=file_bytes,
			key=symmetric_key,
		)

		# Encrypt the symmetric key with the tender's public key
		encrypted_symmetric_key = encrypt_symmetric_key_with_public_key(
			symmetric_key=symmetric_key,
			public_key=TENDER_PUBLIC_KEY,
		)

		# Calculate content hash (simple length-based hash for demonstration)
		content_signature = sign_file_with_private_key(
			file_bytes=file_bytes,
			private_key=COMPANY_PRIVATE_KEY,
		)

		# Send encrypted file to Decrypter service
		client = create_grpc_client(
			host=DECRYPTER_GRPC_HOST,
			port=DECRYPTER_GRPC_PORT,
		)

		# Prepare the request
		metadata = (('certificate', base64.b64encode(encrypted_file_bytes).decode('ascii')),
		            ('encrypted_aes_256_key', encrypted_symmetric_key.hex()))

		request = decrypter_pb2.ReceiveFileRequest(
			filename=filename,
			encrypted_content=encrypted_file_bytes,
			content_signature=content_signature,
		)

		# Call the Decrypter service
		try:
			client.ReceiveEncryptedFile(request, metadata=metadata)
		except grpc.RpcError as e:
			context.set_code(e.code())
			context.set_details(e.details())
			logger.error(f"gRPC error from Decrypter service: {e.code()} - {e.details()}")
			return encrypter_pb2.Empty()

		# Close the gRPC client
		client.close()

		# Return success response
		logger.info(f"File {filename} encrypted and sent successfully")
		return encrypter_pb2.Empty()

def serve(host: str, port: int):
	"""
	Start the gRPC server.

	Args:
		host (str): Host to listen on.
		port (int): Port to listen on.
	"""
	# Create gRPC server
	server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

	# Register the servicer
	encrypter_pb2_grpc.add_EncrypterServicer_to_server(
		EncrypterServicer(),
		server,
		)
	server.add_insecure_port(host + ':' + str(port))
	server.start()
	server.wait_for_termination()


if __name__ == '__main__':
	# Get port from arguments
	parser = ArgumentParser()
	parser.add_argument(
		'--host',
		type=str,
		default='localhost',
		help='Host to listen on',
		)
	parser.add_argument('--port', type=int, help='Port to listen on')
	args = parser.parse_args()
	logger.info(f'Starting server on {args.host}:{args.port}')

	# Start the gRPC server
	serve(args.host, args.port)
