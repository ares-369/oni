# OniOps — Offensive Neural Intelligence
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app

# curl is needed by the local runner (oniops demo, grey-box checks).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install -r requirements.txt \
    # Install cloud SDKs + OIDC so the image supports every provider and SSO.
    && pip install "anthropic>=0.40" "google-genai>=0.3" "openai>=1.40" "authlib>=1.3"

COPY oniops/ ./oniops/
COPY webui.py ./
COPY playbooks/ ./playbooks/
COPY templates/ ./templates/
COPY static/ ./static/

EXPOSE 8501

# /healthz answers 200 without a login. Assumes the default oniops.bind_port (8501).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8501/healthz', timeout=4)" || exit 1

# config.yaml, .env, secrets/ and data/ are mounted at runtime (see compose).
CMD ["python", "-m", "oniops"]
