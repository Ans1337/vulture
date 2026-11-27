FROM python:3.12-slim
WORKDIR /srv/api
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/*.py ./
COPY dashboard /srv/dashboard
# Files may arrive owner-only (e.g. from a synced folder); make them readable to the app user.
RUN chmod -R a+rX /srv
RUN useradd -m vulture
USER vulture
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
