# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder

ARG WHEELHOUSE=wheelhouse

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_FIND_LINKS=/opt/wheelhouse

WORKDIR /app

ARG INCLUDE_DEV_KEYS=false

COPY ${WHEELHOUSE}/ /opt/wheelhouse/
COPY requirements.txt ./

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runtime

ARG WHEELHOUSE=wheelhouse

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

ARG INCLUDE_DEV_KEYS=false

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libjpeg62-turbo \
        libxml2 \
        libxslt1.1 \
        fonts-liberation \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" reconscript

COPY --from=builder /opt/wheelhouse /opt/wheelhouse
COPY --from=builder /opt/venv /opt/venv
COPY . .

RUN if [ "$INCLUDE_DEV_KEYS" != "true" ]; then rm -f keys/dev_*; fi \
    && chown -R reconscript:reconscript /app

USER reconscript

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3)"

CMD ["python", "start.py"]
