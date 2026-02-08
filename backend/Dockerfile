FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates docker-cli \
  && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml /app/pyproject.toml
COPY backend/src /app/src
COPY backend/ghidra_scripts /app/ghidra_scripts

RUN pip install --no-cache-dir -U pip setuptools \
  && pip install --no-cache-dir .

ENV PYTHONPATH=/app/src

CMD ["uvicorn", "ghidra_agent.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
