# syntax=docker/dockerfile:1.7
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y gosu && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 appuser && mkdir -p /app/data

# Install the hash-locked runtime set before copying source to preserve build caching.
COPY requirements.txt requirements.lock ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --disable-pip-version-check --require-hashes -r requirements.lock

# Runtime source is baked into the shared API/worker/webhook image.
COPY --chown=appuser:appuser . .

# The entrypoint repairs only the mounted data directory, then drops privileges.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
