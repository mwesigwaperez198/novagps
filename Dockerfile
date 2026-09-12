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
    && apt-get install -y --no-install-recommends gcc g++ make cmake libpq-dev curl ca-certificates \
        nmap whois dnsutils netcat-openbsd openssl iproute2 iputils-ping traceroute \
    && rm -rf /var/lib/apt/lists/*

# llama-cpp-python builds from source: force a CPU-only build with no
# extended instruction sets. DLLAMA_AVX* flags must be explicitly OFF —
# llama's cmake auto-detects the BUILD host's CPU (which may have AVX2)
# and the resulting binary then crashes on Render's VM with SIGILL.
ENV CMAKE_ARGS="-DLLAMA_METAL=OFF -DLLAMA_BLAS=OFF -DLLAMA_AVX=OFF -DLLAMA_AVX2=OFF -DLLAMA_AVX512=OFF -DLLAMA_FMA=OFF -DLLAMA_F16C=OFF" \
    CFLAGS="-O2 -march=x86-64" \
    CXXFLAGS="-O2 -march=x86-64"

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && pip install --no-cache-dir llama-cpp-python==0.2.76 huggingface_hub==0.23.0 || \
       echo "[nova] llama-cpp-python unavailable — deterministic shield will be used"

COPY backend/ /app/
COPY nova_core/ /app/nova_core/
# main.py resolves the UI at Path(__file__).parent.parent / "frontend" / "dist"
# i.e. /frontend/dist in this image.
COPY frontend/dist/ /frontend/dist/

EXPOSE 8000

# Render injects $PORT; default 8000 for local docker runs.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
