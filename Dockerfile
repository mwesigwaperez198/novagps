# NOVA GPS — single-service Docker image (API + dashboard UI).
# Build context is the REPO ROOT (not backend/) so we can bundle both the
# FastAPI backend and the prebuilt frontend, which the API serves at "/".
# Used by Render (render.yaml). Not used by the docker-compose Kafka stack.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY backend/ /app/
# main.py resolves the UI at Path(__file__).parent.parent / "frontend" / "dist"
# i.e. /frontend/dist in this image.
COPY frontend/dist/ /frontend/dist/

EXPOSE 8000

# Render injects $PORT; default 8000 for local docker runs.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
