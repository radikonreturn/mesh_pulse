# Stage 1: Build stage
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install system dependencies required for building python wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project definition and source code
COPY pyproject.toml requirements.txt README.md ./
COPY mesh_pulse ./mesh_pulse

# Build wheels for app and all transitive dependencies
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt .

# Stage 2: Runtime stage
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color

WORKDIR /app

# Install runtime system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install wheels
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels mesh-pulse \
    && rm -rf /wheels

# Copy remaining project files
COPY . .

# Expose ports
# 37020/udp: Peer discovery broadcast
# 5000/tcp: File transfer
EXPOSE 37020/udp
EXPOSE 5000/tcp

# Run the application
CMD ["python", "-m", "mesh_pulse"]