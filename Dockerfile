FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Trivy va a escanear esta imagen, así que Kali
# no necesitas nada extra acá
EXPOSE 5000

CMD ["python", "app.py"]