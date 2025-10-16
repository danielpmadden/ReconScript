# syntax=docker/dockerfile:1
# Modified by codex: 2024-05-08

############################################################
# Builder image: installs dependencies and runs test suite #
############################################################
FROM python:3.11-slim AS builder

ARG INCLUDE_PDF=false

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build prerequisites only for this stage.
RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential \
    && if [ "$INCLUDE_PDF" = "true" ]; then \
        apt-get install --no-install-recommends -y \
            libcairo2 \
            libffi-dev \
            libgdk-pixbuf-2.0-0 \
            libpango-1.0-0 \
            libpangocairo-1.0-0 \
            libjpeg62-turbo \
            libxml2 \
            libxslt1.1 \
            fonts-liberation \
            shared-mime-info; \
      fi \
    && rm -rf /var/lib/apt/lists/*

# Copy project files required for installation and testing.
COPY pyproject.toml README.md CHANGELOG.md HELP.md ./
COPY reconscript ./reconscript
COPY recon_script.py ./
COPY examples ./examples
COPY tests ./tests

# Install the project with development extras for linting/testing utilities.
RUN pip install --upgrade pip \
    && if [ "$INCLUDE_PDF" = "true" ]; then \
        pip install --no-cache-dir .[dev,pdf]; \
       else \
        pip install --no-cache-dir .[dev]; \
       fi

# Execute the unit tests to ensure build integrity.
RUN pytest

# Build a wheel that will be consumed by the runtime stage.
RUN pip wheel --no-deps --wheel-dir /wheels .

##############################################
# Runtime image: minimal footprint container #
##############################################
FROM python:3.11-slim AS runtime

ARG INCLUDE_PDF=false

LABEL maintainer="Safe Recon Team <security@example.com>" \
      org.opencontainers.image.title="ReconScript" \
      org.opencontainers.image.description="Read-only reconnaissance helper with dry-run, throttling, and safety controls." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="0.4.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RECONSCRIPT_DEFAULT_SOCKET_TIMEOUT=3.0 \
    RECONSCRIPT_DEFAULT_HTTP_TIMEOUT=8.0 \
    RECONSCRIPT_DEFAULT_THROTTLE_MS=250.0 \
    RECONSCRIPT_DEFAULT_MAX_PORTS=12

# Set application directory before switching to non-root user.
WORKDIR /app

# Install runtime dependencies and optional PDF libraries.
RUN apt-get update \
    && if [ "$INCLUDE_PDF" = "true" ]; then \
        apt-get install --no-install-recommends -y \
            libcairo2 \
            libgdk-pixbuf-2.0-0 \
            libpango-1.0-0 \
            libpangocairo-1.0-0 \
            libjpeg62-turbo \
            libxml2 \
            libxslt1.1 \
            fonts-liberation \
            shared-mime-info; \
      fi \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels \
    && if [ "$INCLUDE_PDF" = "true" ]; then \
        pip install --no-cache-dir "weasyprint>=61.2,<62"; \
       fi

# Create and use an unprivileged user for execution safety.
RUN useradd -m appuser
USER appuser

# Copy documentation/examples that may help operators inside the container.
COPY --chown=appuser:appuser examples ./examples
COPY --chown=appuser:appuser HELP.md ./HELP.md

ENTRYPOINT ["python", "-m", "reconscript"]
CMD ["--help"]
