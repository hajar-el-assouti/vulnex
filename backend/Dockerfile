FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps needed to build asyncpg / cryptography-style wheels on slim.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Run as a non-root user -- this image will eventually sit next to
# pentest engines; no reason for the API container to run as root.
RUN useradd --create-home --uid 1000 appuser
COPY --chown=appuser:appuser . .
USER appuser

EXPOSE 8000

# --forwarded-allow-ips="": uvicorn's own ProxyHeadersMiddleware defaults
# to trusting X-Forwarded-For from 127.0.0.1 when this flag is left unset
# (CVE-class issue, not an app-level setting) -- it rewrites the ASGI
# scope's client address BEFORE the app's own _client_ip() in
# app/api/v1/endpoints/auth.py ever runs, silently defeating that
# function's correctly-secure trust_x_forwarded_for=False/trusted_proxies=[]
# defaults. The BFF (Next.js
# route.ts) already strips any client-supplied X-Forwarded-For before
# proxying, and sessions are cookie-based, not IP-based -- disabling this
# trust breaks nothing here.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--forwarded-allow-ips="]
