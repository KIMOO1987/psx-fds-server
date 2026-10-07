FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create persistent data directory
RUN mkdir -p /app/data

# Copy application source
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Start production server
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
