# Control Plane Dockerfile
FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install docker CLI
RUN apt-get update && \
    apt-get install -y docker.io && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY macds/ ./macds/

ENV PYTHONPATH=/app

ENTRYPOINT ["python", "-m", "macds.cli"]
