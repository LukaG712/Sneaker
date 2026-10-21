FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"

COPY . .

EXPOSE 8086

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8086/health')" || exit 1

CMD ["python", "-m", "uvicorn", "sneaker.api:app", "--host", "0.0.0.0", "--port", "8086"]
