FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY *.py ./
COPY vendors.json ./

# Create a non-root user for security
RUN groupadd -r cveuser && useradd -r -g cveuser cveuser
RUN chown -R cveuser:cveuser /app
USER cveuser

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default command - can be overridden
CMD ["python", "runner.py", "--timeframe", "TODAY"]