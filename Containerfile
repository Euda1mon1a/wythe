# Minimal rootless/micro-VM scanner image for isolated read-only Wythe runs (`wythe:local`).
# Build with:
#   docker build -t wythe:local -f Containerfile .
#   podman build -t wythe:local -f Containerfile .
#   container build -t wythe:local -f Containerfile .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WYTHE_STATE_DIR=/tmp/wythe-state

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/wythe
COPY backend /opt/wythe/backend

RUN pip install --no-cache-dir "/opt/wythe/backend[treesitter]" \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin wythe

USER 10001:10001
WORKDIR /workspace
CMD ["wythe", "--help"]
