FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so code edits don't invalidate the layer.
COPY pyproject.toml README.md ./
RUN pip install --upgrade pip && pip install -e .

COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY scripts ./scripts

# Runs as a non-root user; nothing here needs to write to the image.
RUN useradd --create-home --uid 10001 skylock && chown -R skylock:skylock /app
USER skylock

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
