# Railway detects this Dockerfile automatically. No public HTTP port is required.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY bot.py ./

# Use Railway Variables: BOT_TOKEN, ADMIN_ID, CHANNEL_USERNAME, DB_PATH.
# Attach a persistent Railway volume at /data and set DB_PATH=/data/guard.db.
CMD ["python", "bot.py"]
