from argparse import ArgumentParser
from concurrent import futures

import grpc

import ralvarezdev.encrypter_pb2 as encrypter_pb2
import ralvarezdev.encrypter_pb2_grpc as encrypter_pb2_grpc
from utils.certificate import generate_certificate_from_public_key
from utils.constants import issuer_public_key

class EncrypterServicer(encrypter_pb2_grpc.EncrypterServicer):
	def EncryptFile(self, request_iterator, context):
		total_bytes = 0
		filename = None
		for req in request_iterator:
			if filename is None:
				filename = req.filename
			total_bytes += len(req.content)
			# Here you would process or save the file chunk
		return encrypter_pb2.EncryptFileResponse(
			success=True,
			message=f"Received file {filename}",
			bytes_received=total_bytes,
			)

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
				yield encrypter_pb2.GenerateCertificateResponse()
				return

		# Generate the certificate
		cert_content = generate_certificate_from_public_key(
			public_key=issuer_public_key,
			common_name=common_name,
			organization=organization,
			organizational_unit=organizational_unit,
			locality=locality,
			state=state,
			country=country,
		)
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