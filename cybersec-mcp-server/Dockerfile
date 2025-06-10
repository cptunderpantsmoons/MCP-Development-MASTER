FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY cybersec_mcp_server/ ./cybersec_mcp_server/
COPY config.yaml .

# Create audit logs directory
RUN mkdir -p /app/audit_logs

# Create non-root user
RUN useradd -m -u 1000 mcpuser && chown -R mcpuser:mcpuser /app
USER mcpuser

# Expose port (if running HTTP interface)
EXPOSE 8080

# Run the MCP server
CMD ["python", "-m", "cybersec_mcp_server.main"]