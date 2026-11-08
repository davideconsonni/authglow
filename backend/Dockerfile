FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Run as an unprivileged user (VAPT-095): /app/data holds users, keys and
# sessions and is volume-mounted at runtime.
RUN useradd --system --create-home --uid 1000 appuser \
    && mkdir -p /app/data /app/data/keys \
    && chown -R appuser:appuser /app/data
USER appuser

# Expose port (Cloud Run uses PORT env var, default to 8080)
ENV PORT=8080
EXPOSE 8080

# Uvicorn worker processes. Default 1 on purpose: every extra worker is a
# full Python process with its own caches and rate-limiter counters, so
# scaling replicas at the orchestrator stays the recommended path. Only
# raise this once shared cache/limiter backends are configured — see
# docs/internals/architecture/deployment.md ("Process Scaling").
ENV UVICORN_WORKERS=1

# Run application
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT} --workers ${UVICORN_WORKERS}
