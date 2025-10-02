@echo off

REM Check if OpenSSL is installed
where openssl >nul 2>&1
if errorlevel 1 (
    echo Error: OpenSSL is not installed or not found in PATH.
    exit /b 1
)

REM Generate keys using OpenSSL
echo Generating Ed25519 key pair...
openssl genpkey -algorithm ed25519 -out company_private_key.pem
openssl pkey -in company_private_key.pem -pubout -out company_public_key.pem
echo Keys generated: company_private_key.pem and company_public_key.pem"