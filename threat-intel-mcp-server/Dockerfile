FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY threat_intel_mcp_server/ ./threat_intel_mcp_server/
COPY config.yaml .

# Create intel logs directory
RUN mkdir -p /app/intel_logs

# Create non-root user
RUN useradd -m -u 1001 inteluser && chown -R inteluser:inteluser /app
USER inteluser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import asyncio; asyncio.run(__import__('threat_intel_mcp_server.main').main())" || exit 1

# Expose port for metrics/health
EXPOSE 9090

# Run the MCP server
CMD ["python", "-m", "threat_intel_mcp_server.main"]