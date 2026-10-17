FROM node:22-bookworm-slim AS frontend-build

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETWATCH_AUTH_DB=/app/data/netwatch_auth.sqlite3 \
    PORT=10000

WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt \
    && useradd --create-home --shell /usr/sbin/nologin netwatch

COPY backend/ /app/backend/
COPY config/ /app/config/
COPY data/ /app/data/
COPY --from=frontend-build /build/frontend/dist/ /app/frontend/dist/
RUN chown -R netwatch:netwatch /app/data

USER netwatch
EXPOSE 10000
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
