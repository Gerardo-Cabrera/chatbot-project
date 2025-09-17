FROM python:3.11-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc libffi-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /install
COPY backend/requirements.txt /install/requirements.txt
RUN python -m pip install --upgrade pip && python -m pip install --prefix=/install -r /install/requirements.txt

FROM python:3.11-slim AS runtime
ENV PATH=/install/bin:$PATH PYTHONPATH=/install/lib/python3.11/site-packages PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 QA_DB_PATH=/app/data/chatbot_data.db
RUN groupadd -r app && useradd -r -g app app
WORKDIR /app
COPY --from=builder /install /install
COPY backend /app/backend
RUN chown -R app:app /app && chmod -R g+r /install
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--workers", "4"]
