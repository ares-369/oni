# ONIOPS — Offensive Neural Intelligence
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app

# Minimal build deps for paramiko/cryptography wheels.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install -r requirements.txt \
    # Install the cloud SDKs too so the image supports every provider.
    && pip install "anthropic>=0.40" "google-genai>=0.3" "openai>=1.40"

COPY oniops/ ./oniops/
COPY webui.py ./
COPY templates/ ./templates/
COPY static/ ./static/

EXPOSE 8501

# config.yaml, .env, secrets/ and data/ are mounted at runtime (see compose).
CMD ["python", "-m", "oniops"]
