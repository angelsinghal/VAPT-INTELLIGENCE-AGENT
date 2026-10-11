# ── Stage 1: dependency resolver ────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency manifests first for better layer caching
COPY pyproject.toml ./

# Install production dependencies (no dev extras)
RUN uv sync --no-dev --no-install-project

# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy uv binary
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy installed virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application source
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY knowledge/ ./knowledge/
COPY pyproject.toml ./

# Create data directory for ChromaDB
RUN mkdir -p /app/data/chroma

# Add .venv/bin to PATH
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('"'"'http://localhost:8000/health'"'"'); exit(0 if r.status_code == 200 else 1)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
