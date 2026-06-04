# =====================================================================
# 🐳 CYBEROPS PLATFORM DOCKER ENGINE
# =====================================================================
FROM python:3.11-slim

# Set environment system flags
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Set working directory inside container
WORKDIR /app

# Install system dependencies needed for compiling python extensions (like mysqlclient / pillow)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    pkg-config \
    default-libmysqlclient-dev \
    libmariadb-dev-compat \
    python3-dev \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire platform application code into the image working directory
COPY . /app/

# Grant executable permission to entrypoint script
RUN chmod +x /app/entrypoint.sh

# Expose default HTTP socket port
EXPOSE 8000

# Set dynamic runtime entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
