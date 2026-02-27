FROM python:3.11.8-slim

WORKDIR /app

RUN pip install --no-cache-dir aiohttp

COPY sentinel/ ./sentinel/

EXPOSE 8080

CMD ["python", "-m", "sentinel"]
