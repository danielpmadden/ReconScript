# syntax=docker/dockerfile:1

############################################################
# Builder image: installs dependencies and runs test suite #
############################################################
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build prerequisites only for this stage.
RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files required for installation and testing.
COPY pyproject.toml README.md ./
COPY reconscript ./reconscript
COPY recon_script.py ./
COPY examples ./examples
COPY tests ./tests

# Install the project with development extras for linting/testing utilities.
RUN pip install --upgrade pip \
    && pip install --no-cache-dir .[dev]

# Execute the unit tests to ensure build integrity.
RUN pytest

# Build a wheel that will be consumed by the runtime stage.
RUN pip wheel --no-deps --wheel-dir /wheels .

##############################################
# Runtime image: minimal footprint container #
##############################################
FROM python:3.11-slim AS runtime

LABEL maintainer="Safe Recon Team <security@example.com>" \
      org.opencontainers.image.title="ReconScript" \
      org.opencontainers.image.description="Read-only reconnaissance helper with dry-run, throttling, and safety controls." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="0.3.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RECONSCRIPT_DEFAULT_SOCKET_TIMEOUT=3.0 \
    RECONSCRIPT_DEFAULT_HTTP_TIMEOUT=8.0 \
    RECONSCRIPT_DEFAULT_THROTTLE_MS=250.0 \
    RECONSCRIPT_DEFAULT_MAX_PORTS=12

# Set application directory before switching to non-root user.
WORKDIR /app

# Install only runtime dependencies from the pre-built wheel set.
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

# Create and use an unprivileged user for execution safety.
RUN useradd -m appuser
USER appuser

# Copy documentation/examples that may help operators inside the container.
COPY --chown=appuser:appuser examples ./examples

ENTRYPOINT ["python", "-m", "reconscript"]
CMD ["--help"]
