FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 50051

CMD ["python", "main.py", "--host", "[::]", "--port", "50051"]