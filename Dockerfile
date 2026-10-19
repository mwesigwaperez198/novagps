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
        git unzip zip xz-utils whatweb yara dirb masscan perl sublist3r \
    && mkdir -p /usr/share/wordlists \
    && ln -sfn /usr/share/dirb/wordlists /usr/share/wordlists/dirb \
    && rm -rf /var/lib/apt/lists/*

# llama-cpp-python: build with NO extended CPU instruction sets.
# All AVX/FMA/F16C flags must be explicitly disabled — llama's cmake
# auto-detects the build host CPU (AVX2 capable) and the resulting .so
# then crashes with SIGILL on Render's VM which lacks those instructions.
# Cache-bust token: v4
ENV CMAKE_ARGS="-DLLAMA_METAL=OFF -DLLAMA_BLAS=OFF -DLLAMA_AVX=OFF -DLLAMA_AVX2=OFF -DLLAMA_AVX512=OFF -DLLAMA_FMA=OFF -DLLAMA_F16C=OFF" \
    CFLAGS="-O2 -march=x86-64 -mno-avx -mno-avx2 -mno-sse4.1 -mno-sse4.2" \
    CXXFLAGS="-O2 -march=x86-64 -mno-avx -mno-avx2 -mno-sse4.1 -mno-sse4.2"

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Install llama-cpp-python in a fully isolated step with explicit no-AVX flags.
# The || true ensures a compile failure never blocks the image build.
RUN CMAKE_ARGS="-DLLAMA_METAL=OFF -DLLAMA_BLAS=OFF -DLLAMA_AVX=OFF -DLLAMA_AVX2=OFF -DLLAMA_AVX512=OFF -DLLAMA_FMA=OFF -DLLAMA_F16C=OFF" \
    CFLAGS="-O2 -march=x86-64 -mno-avx -mno-avx2 -mno-sse4.1 -mno-sse4.2" \
    CXXFLAGS="-O2 -march=x86-64 -mno-avx -mno-avx2 -mno-sse4.1 -mno-sse4.2" \
    pip install --no-cache-dir --force-reinstall llama-cpp-python==0.2.76 huggingface_hub==0.23.0 \
    || echo "[nova] llama-cpp-python unavailable — deterministic shield will be used"

# --- LAU skill toolkit ------------------------------------------------------
# Pinned prebuilt releases keep the image reproducible without shipping a Go
# toolchain. Only P0-P2 recon/OSINT skills are baked in; the P3 wireless/IDS
# tools stay out of a public container by design (they require NOVA_LAB_MODE
# and an authorised network).
RUN mkdir -p /tmp/skills \
    && (curl -fsSL --retry 3 -o /tmp/skills/nuclei.zip \
        https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip \
        && unzip -q /tmp/skills/nuclei.zip -d /tmp/skills/nuclei \
        && install -m 0755 /tmp/skills/nuclei/nuclei /usr/local/bin/nuclei) \
        || echo "[nova] nuclei unavailable" ; \
    (curl -fsSL --retry 3 -o /tmp/skills/httpx.zip \
        https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip \
        && unzip -q /tmp/skills/httpx.zip -d /tmp/skills/httpx \
        && install -m 0755 /tmp/skills/httpx/httpx /usr/local/bin/httpx) \
        || echo "[nova] httpx unavailable" ; \
    (curl -fsSL --retry 3 -o /tmp/skills/ffuf.tar.gz \
        https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz \
        && tar -xzf /tmp/skills/ffuf.tar.gz -C /tmp/skills \
        && install -m 0755 /tmp/skills/ffuf /usr/local/bin/ffuf) \
        || echo "[nova] ffuf unavailable" ; \
    (curl -fsSL --retry 3 -o /tmp/skills/trufflehog.tar.gz \
        https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.3/trufflehog_3.99.3_linux_amd64.tar.gz \
        && tar -xzf /tmp/skills/trufflehog.tar.gz -C /tmp/skills \
        && install -m 0755 /tmp/skills/trufflehog /usr/local/bin/trufflehog) \
        || echo "[nova] trufflehog unavailable" ; \
    (curl -fsSL --retry 3 -o /tmp/skills/phoneinfoga.tar.gz \
        https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz \
        && tar -xzf /tmp/skills/phoneinfoga.tar.gz -C /tmp/skills \
        && install -m 0755 /tmp/skills/phoneinfoga /usr/local/bin/phoneinfoga) \
        || echo "[nova] phoneinfoga unavailable" ; \
    /usr/local/bin/nuclei -update-templates -silent || echo "[nova] nuclei templates will download on first run" ; \
    rm -rf /tmp/skills

# Nikto is packaged in Debian non-free, which the slim image does not enable,
# so install the upstream tree and expose its Perl entrypoint instead.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -sfn /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    || echo "[nova] nikto unavailable"

# Python-based skills live in isolated pipx venvs so their pinned dependencies
# can never collide with the API requirements. theHarvester 4.6.0 is the last
# line that still supports Python 3.12 (upstream now requires 3.14).
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin
RUN pip install --no-cache-dir pipx==1.18.4 ; \
    pipx install sherlock-project==0.16.2 || echo "[nova] sherlock unavailable" ; \
    pipx install maigret==0.6.6 || echo "[nova] maigret unavailable" ; \
    pipx install sqlmap==1.10.10 || echo "[nova] sqlmap unavailable" ; \
    pipx install mitmproxy==12.2.3 || echo "[nova] mitmproxy unavailable" ; \
    pipx install "git+https://github.com/laramies/theHarvester.git@4.6.0" \
        || echo "[nova] theHarvester unavailable"

COPY backend/ /app/
COPY nova_core/ /app/nova_core/
# main.py resolves the UI at Path(__file__).parent.parent / "frontend" / "dist"
# i.e. /frontend/dist in this image.
COPY frontend/dist/ /frontend/dist/

EXPOSE 8000

# Render injects $PORT; default 8000 for local docker runs.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
