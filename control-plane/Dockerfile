# Build context is the repo root (palisade/) so the image can carry detections/.
# Same image runs on a laptop, Proxmox VM, or the VPS — only env vars differ.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PALISADE_DETECTIONS_DIR=/app/detections

WORKDIR /app

COPY control-plane/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY control-plane/app ./app
COPY control-plane/alembic.ini ./alembic.ini
COPY control-plane/migrations ./migrations
COPY detections ./detections

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
