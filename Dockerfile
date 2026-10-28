# PhishShield production image (works on Hugging Face Spaces, Render, Railway, any Docker host).
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONWARNINGS=ignore \
    PORT=7860

RUN apt-get update && apt-get install -y --no-install-recommends libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Hugging Face Spaces runs containers as a non-root user with UID 1000.
RUN useradd -m -u 1000 app
WORKDIR /home/app/phishshield

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app . .
USER app

EXPOSE 7860
# One worker keeps memory under ~400 MB (fits free tiers); threads handle concurrent users.
# --preload loads the models once at start-up, so the first visitor isn't slow.
CMD gunicorn "app:create_app()" --preload --workers 1 --threads 4 --timeout 120 --bind 0.0.0.0:${PORT}
