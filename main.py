from argparse import ArgumentParser
from concurrent import futures
import os
import uuid

import grpc

import ralvarezdev.encrypter_pb2 as encrypter_pb2
import ralvarezdev.encrypter_pb2_grpc as encrypter_pb2_grpc
from ed25519.certificate import generate_certificate_from_public_key
from ed25519.encryption import encrypt_and_save_file
from ed25519 import issuer_public_key, data_path, issuer_subject, certificate_validity_days

class EncrypterServicer(encrypter_pb2_grpc.EncrypterServicer):
	def EncryptFile(self, request_iterator, context):
		# Accumulate file chunks
		files_bytes = dict()

		# Process each chunk in the stream
		for chunk in request_iterator:
			filename = chunk.filename
			if filename not in files_bytes:
				files_bytes[filename] = bytearray()
			files_bytes[filename].extend(chunk.content)

		# Iterate over received files and print their sizes
		for filename, file_bytes in files_bytes.items():
			total_bytes = len(file_bytes)
			print(f"Received file: {filename}, Size: {total_bytes} bytes")

			# Get the original extension
			_, ext = os.path.splitext(filename)
			if ext:
				ext = "." + ext.lstrip('.')
			else:
				ext = ""

			# Encrypt and save the file
			output_path = os.path.join(data_path, filename + "_" + str(uuid.uuid4()) + ext + ".enc")
			encrypt_and_save_file(
				file_path=os.path.join(data_path, filename),
				public_key=issuer_public_key,
				output_path=output_path,
				)
			print(f"Encrypted file saved to: {output_path}")

		# Respond with success message
		return encrypter_pb2.Empty()

	def GenerateCertificate(self, request, context):
		# Get the certificate subject from the request
		common_name = request.common_name
		organization = request.organization
		organizational_unit = request.organizational_unit
		locality = request.locality
		state = request.state
		country = request.country

		# Validate required fields
		required_fields = {
			"common_name": common_name,
			"organization": organization,
			"organizational_unit": organizational_unit,
			"locality": locality,
			"state": state,
			"country": country,
			}

		for field, value in required_fields.items():
			if not value:
				context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
				context.set_details(
					f"{field.replace('_', ' ').title()} is required"
					)
				print(f"Missing required field: {field}")
				yield encrypter_pb2.GenerateCertificateResponse()
				return

		# Generate the certificate
		cert_content = generate_certificate_from_public_key(
			public_key=issuer_public_key,
			issuer_subject=issuer_subject,
			common_name=common_name,
			organization=organization,
			organizational_unit=organizational_unit,
			locality=locality,
			state=state,
			country=country,
			certificate_validity_days=certificate_validity_days,
		)

		print(f"Generated certificate for {common_name}")

		# Return the certificate content
		yield encrypter_pb2.GenerateCertificateResponse(content=cert_content)

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
	parser.add_argument('--host', type=str, default='localhost', help='Host to listen on')
	parser.add_argument('--port', type=int, help='Port to listen on')
	args = parser.parse_args()
	print(f'Starting server on {args.host}:{args.port}')

	# Start the gRPC server
	serve(args.host, args.port)