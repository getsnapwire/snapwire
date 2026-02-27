FROM python:3.11.8-slim

WORKDIR /app

RUN pip install --no-cache-dir aiohttp && \
    groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

COPY sentinel/ ./sentinel/

RUN chown -R sentinel:sentinel /app

USER sentinel

EXPOSE 8080

CMD ["python", "-m", "sentinel"]
