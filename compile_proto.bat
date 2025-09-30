@echo off
setlocal

REM Get the script directory
set "SCRIPT_DIR=%~dp0"

REM Protobuf-related paths
set "PROTO_PATH=%SCRIPT_DIR%\proto"
set "PROTO_ENCRYPTER_PATH=%PROTO_PATH%\ralvarezdev\encrypter.proto"
set "PROTO_OUT_PATH=%SCRIPT_DIR%\"

REM Activate the virtual environment
call .venv\Scripts\activate.bat

REM Create output directory if it doesn't exist
if not exist "%PROTO_OUT_PATH%" (
    mkdir "%PROTO_OUT_PATH%"
)

REM Check if the protobuffer file exists
if not exist "%PROTO_ENCRYPTER_PATH%" (
    echo Error: Protobuf file "%PROTO_ENCRYPTER_PATH%" not found!
    exit /b 1
)

REM Compile the protobuf file
python -m grpc_tools.protoc -I="%PROTO_PATH%" --python_out="%PROTO_OUT_PATH%" --grpc_python_out="%PROTO_OUT_PATH%" "%PROTO_ENCRYPTER_PATH%"