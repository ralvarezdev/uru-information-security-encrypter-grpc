# uru-information-security-encrypter-grpc

**Note:** This repository is archived and read-only.

gRPC microservice for encrypting files, in Python.

Part of a set of Information Security college course (URU) projects forming a secure tender (bid) file submission system, all under `ralvarezdev`:

- **`uru-information-security-certificate-grpc`** — certificate authority gRPC service (port 50053)
- **`uru-information-security-encrypter-grpc`** — encrypts and signs bidder files, forwards them to the decrypter (50051)
- **`uru-information-security-decrypter-grpc`** — receives, stores and decrypts files for the tender owner (50052)
- **`uru-information-security-certificate-app`**, **`-bidder-app`**, **`-admin-app`** — Streamlit UIs to request certificates, submit files and manage files (8503, 8502, 8501)

## What it does

Service `Encrypter` in `proto/ralvarezdev/encrypter.proto` has one client-streaming RPC, `SendEncryptedFile`, returning `Empty`. The flow in `main.py`:

1. Read the bidder's certificate from the `certificate` request metadata (rejected if missing).
2. Accumulate the streamed chunks; all must share the same filename.
3. Generate a random AES-256 key and encrypt the file with it.
4. Encrypt that key with the tender's RSA public key (OAEP, SHA-256).
5. Sign the content with the Ed25519 key.
6. Forward the encrypted file, signature and wrapped key to the Decrypter service, which validates the certificate.

## Project structure

- **`main.py`** — gRPC server (`--host`, `--port`)
- **`crypto/`** — `aes`, `rsa`, `ed25519`, `sha` helpers
- **`microservice/grpc/decrypter.py`** — decrypter client
- **`decrypter-grpc`** — git submodule of uru-information-security-decrypter-grpc, for its proto and stubs
- **`generate_keys.bat`**, **`compile_proto.bat`**, **`update_submodules.bat`** — Windows helpers
- **`Dockerfile`** — python:3.11-slim, exposes 50051

## Configuration and running

Environment variables: `DECRYPTER_GRPC_HOST`, `DECRYPTER_GRPC_PORT`. PEM key files are expected next to the code; generate them with `generate_keys.bat` (OpenSSL required) and obtain the tender public key from the decrypter's key pair.

```bash
git submodule update --init
pip install -r requirements.txt    # UTF-16 encoded; convert if pip complains
python main.py --host "[::]" --port 50051
```

## License

GNU General Public License v3.0 (see `LICENSE`).
