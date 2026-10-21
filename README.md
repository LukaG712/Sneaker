# Creeper

> *"These ghosts seem unassailable, don't worry they're still inhalable!"*
> ~ **Prof. E. Gadd**, on facing any challenge

**Creeper** is the observability service for the Evershade ecosystem. It collects metrics, traces, and logs from all services, providing a unified view of system health and performance.

**Luigi's Mansion origin:** *Creeper* ~ creeping ghosts from Luigi's Mansion: Dark Moon that slowly move along walls and floors, always watching.

## Features

- **Metrics** ~ Record and query time-series metrics with labels
- **Traces** ~ Distributed tracing with span relationships
- **Logs** ~ Centralized log aggregation with filtering

## Quick Start

```bash
# With Docker
docker compose up -d Creeper

# Direct
pip install -e ".[dev]"
python -m uvicorn creeper.api:app --host 0.0.0.0 --port 8086
```

## API

- **Swagger UI:** `http://localhost:8086/docs`
- **ReDoc:** `http://localhost:8086/redoc`

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | `Creeper-dev-key-change-me` | API authentication key |
| `PORT` | `8086` | Server port |

## License

MIT
