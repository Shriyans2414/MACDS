FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app

RUN mkdir -p /app/qtables

EXPOSE 8000

ENTRYPOINT ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
