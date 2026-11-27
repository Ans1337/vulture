FROM python:3.12-slim
WORKDIR /srv/api
# ssh client: SANDBOX_MODE=vultr drives each throwaway VM's Docker daemon over ssh
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/*.py ./
COPY dashboard /srv/dashboard
# Files may arrive owner-only (e.g. from a synced folder); make them readable to the app user.
RUN chmod -R a+rX /srv
RUN useradd -m vulture && mkdir /data && chown vulture /data   # scan history (SQLite) lives here: mount a volume
USER vulture
ENV PYTHONUNBUFFERED=1 VULTURE_DB=/data/vulture.db
EXPOSE 8000
# Server-side limits: drop idle connections fast, cap simultaneous connections, no server banner.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "5", \
     "--limit-concurrency", "100", "--no-server-header"]
