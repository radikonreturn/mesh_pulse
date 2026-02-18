# Use official Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

# Set working directory
WORKDIR /app

# Install system dependencies (needed for psutil and network tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose ports
# 37020/udp: Peer discovery broadcast
# 5000/tcp: File transfer
EXPOSE 37020/udp
EXPOSE 5000/tcp

# Run the application
ENTRYPOINT ["python", "-m", "mesh_pulse"]
