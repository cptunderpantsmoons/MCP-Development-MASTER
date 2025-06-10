# Cybersecurity Tools MCP Server

A secure Model Context Protocol (MCP) server that provides AI models with access to professional penetration testing tools in isolated environments.

## 🔒 Security First

This server implements multiple security layers:
- **Container Isolation**: Each tool runs in isolated Docker containers
- **Command Validation**: Input sanitization and whitelisting
- **Audit Logging**: Complete execution tracking
- **Rate Limiting**: Prevents abuse and resource exhaustion
- **Authorization**: Token-based access control for sensitive tools

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Docker and Docker Compose
- 8GB+ RAM (for tool containers)
- Linux/macOS (Windows with WSL2)

### 1. Clone and Setup

```bash
git clone <your-repo-url>
cd cybersec-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit configuration
nano config.yaml
```

### 3. Start with Docker Compose

```bash
# Pull required images
docker-compose pull

# Start the server
docker-compose up -d

# Check logs
docker-compose logs -f cybersec-mcp-server
```

### 4. Test the Installation

```bash
# Test MCP server directly
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | python -m cybersec_mcp_server.main

# Or use with compatible MCP client
claude-mcp-client --server ./cybersec_mcp_server/main.py
```

## 🛠️ Available Tools

### Network Discovery
- **nmap** - Network discovery and port scanning
- **masscan** - High-speed port scanner
- **enum4linux** - SMB enumeration

### Web Application Testing
- **nikto** - Web vulnerability scanner
- **gobuster** - Directory/file enumeration
- **sqlmap** - SQL injection testing
- **wpscan** - WordPress security scanner

### Reconnaissance
- **searchsploit** - Exploit database search
- **theharvester** - Email/subdomain enumeration
- **amass** - Asset discovery

## 📋 Usage Examples

### Basic Tool Execution

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "nmap",
    "arguments": {
      "target": "scanme.nmap.org",
      "preset": "quick_scan"
    }
  }
}
```

### Custom Command Arguments

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "nikto",
    "arguments": {
      "target": "https://example.com",
      "custom_args": "-h https://example.com -ssl -Format txt"
    }
  }
}
```

### SQL Injection Testing (Requires Authorization)

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "sqlmap",
    "arguments": {
      "target": "https://testsite.com/vulnerable.php?id=1",
      "preset": "basic_test",
      "authorization": "your-auth-token"
    }
  }
}
```

## 🔧 Configuration

### Security Configuration (`config.yaml`)

```yaml
security:
  max_execution_time: 300        # Max tool runtime (seconds)
  require_authorization: true    # Require auth tokens
  log_all_executions: true      # Complete audit trail
  container_timeout: 600        # Container max lifetime
  allowed_targets:              # Restrict target scope
    - "*.testdomain.com"
    - "10.0.0.0/8"
    - "192.168.0.0/16"

docker:
  base_image: "kalilinux/kali-rolling"
  memory_limit: "512m"          # Container RAM limit
  cpu_limit: 0.5               # Container CPU limit (50%)
  
tools:
  enabled:                     # Enable specific tools
    - nmap
    - nikto
    - gobuster
    - searchsploit
  disabled:                    # Disable dangerous tools
    - sqlmap
    - metasploit
```

### Environment Variables (`.env`)

```bash
# Authentication
MCP_REQUIRE_AUTH=true
MCP_AUTH_TOKEN=your-secure-token-here

# Rate Limiting
MAX_REQUESTS_PER_MINUTE=60
MAX_CONCURRENT_EXECUTIONS=5

# Security
ALLOWED_PRIVATE_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
BLOCKED_TARGETS=localhost,127.0.0.1,0.0.0.0

# Logging
LOG_LEVEL=INFO
AUDIT_RETENTION_DAYS=90
```

## 🏗️ Integration with AI Models

### Claude/ChatGPT Integration

```python
# Example: Using with OpenAI API
import openai
from mcp_client import MCPClient

# Initialize MCP client
mcp = MCPClient("cybersec-tools")

# AI-guided penetration testing
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[
        {"role": "system", "content": "You are a penetration tester with access to cybersecurity tools via MCP."},
        {"role": "user", "content": "Perform a security assessment of example.com"}
    ],
    tools=mcp.get_available_tools()
)
```

### REDLOG_AI Integration

```python
# Integration with your existing platform
class REDLOGAIIntegration:
    def __init__(self):
        self.mcp_client = MCPClient("cybersec-tools")
        
    async def execute_security_assessment(self, target, engagement_id):
        # Use MCP server for tool execution
        nmap_result = await self.mcp_client.call_tool(
            "nmap", 
            {"target": target, "preset": "comprehensive"}
        )
        
        # Parse and integrate with your workflow
        return self.integrate_results(nmap_result, engagement_id)
```

## 📊 Monitoring and Auditing

### Audit Logs

All tool executions are logged in JSON format:

```json
{
  "timestamp": "2024-06-09T10:30:00Z",
  "tool_name": "nmap",
  "command": "nmap -T4 -F scanme.nmap.org",
  "target": "scanme.nmap.org",
  "exit_code": 0,
  "execution_time": 12.45,
  "user_agent": "mcp-cybersec-server",
  "arguments": {"target": "scanme.nmap.org", "preset": "quick_scan"}
}
```

### Viewing Logs

```bash
# View today's audit logs
docker-compose exec cybersec-mcp-server cat /app/audit_logs/audit_$(date +%Y%m%d).json

# Real-time monitoring
docker-compose logs -f cybersec-mcp-server

# Get logs via MCP
echo '{"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "audit://logs"}}' | python -m cybersec_mcp_server.main
```

## 🔐 Security Best Practices

### Production Deployment

1. **Use Strong Authentication**
   ```bash
   # Generate secure token
   openssl rand -hex 32
   ```

2. **Network Isolation**
   ```yaml
   # docker-compose.yml
   networks:
     cybersec-network:
       driver: bridge
       internal: true  # No external access
   ```

3. **Resource Limits**
   ```yaml
   services:
     cybersec-mcp-server:
       deploy:
         resources:
           limits:
             memory: 1G
             cpus: '1.0'
   ```

4. **Regular Updates**
   ```bash
   # Update Kali tools
   docker pull kalilinux/kali-rolling
   
   # Update server
   git pull origin main
   docker-compose build --no-cache
   ```

### Target Validation

```yaml
# Restrict to specific environments
security:
  allowed_targets:
    - "*.internal.company.com"  # Internal test domains
    - "10.0.0.0/8"             # Private networks only
    - "testbed.example.com"     # Dedicated test environment
```

## 🚨 Legal and Ethical Usage

⚠️ **IMPORTANT**: Only use this server for:
- **Authorized penetration testing**
- **Your own systems and networks**
- **Explicit permission from system owners**
- **Compliance with local laws and regulations**

### Usage Agreement

By deploying this server, you agree to:
1. Only target systems you own or have explicit permission to test
2. Comply with all applicable laws and regulations
3. Implement appropriate access controls and monitoring
4. Regularly review and audit tool usage
5. Take responsibility for all actions performed through this server

## 🤝 Integration Examples

### Slack Bot Integration

```python
# Example Slack bot using MCP server
from slack_bolt import App
from mcp_client import MCPClient

app = App(token="your-slack-token")
mcp = MCPClient("cybersec-tools")

@app.command("/scan")
def handle_scan_command(ack, command, say):
    ack()
    
    target = command['text']
    
    # Execute scan via MCP
    result = mcp.call_tool("nmap", {"target": target, "preset": "quick_scan"})
    
    say(f"Scan results for {target}:\n```{result}```")
```

### API Wrapper

```python
# FastAPI wrapper for HTTP access
from fastapi import FastAPI, HTTPException
from mcp_client import MCPClient

app = FastAPI()
mcp = MCPClient("cybersec-tools")

@app.post("/scan/{tool}")
async def execute_tool(tool: str, request: ToolRequest):
    try:
        result = await mcp.call_tool(tool, request.dict())
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

## 📚 Advanced Usage

### Custom Tool Integration

```python
# Add custom tools to the server
class CustomToolsExtension:
    def __init__(self, server):
        self.server = server
        
    def register_custom_tool(self, name, config):
        self.server.tools_config[name] = {
            "description": config["description"],
            "container_image": config.get("image", "kalilinux/kali-rolling"),
            "safety_checks": config.get("safety_checks", []),
            "output_parser": config.get("parser", "default"),
            "presets": config.get("presets", {})
        }

# Example: Add custom reconnaissance tool
custom_tools = CustomToolsExtension(server)
custom_tools.register_custom_tool("subfinder", {
    "description": "Fast subdomain discovery",
    "presets": {
        "basic": "subfinder -d {domain}",
        "verbose": "subfinder -d {domain} -v"
    }
})
```

### Batch Processing

```python
# Process multiple targets
async def batch_scan(targets, tools):
    results = {}
    
    for target in targets:
        target_results = {}
        
        for tool in tools:
            result = await mcp.call_tool(tool, {"target": target})
            target_results[tool] = result
            
        results[target] = target_results
    
    return results

# Usage
targets = ["example1.com", "example2.com", "10.0.0.1"]
tools = ["nmap", "nikto", "gobuster"]
results = await batch_scan(targets, tools)
```

## 🐛 Troubleshooting

### Common Issues

**Docker Permission Errors**
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**Container Resource Issues**
```bash
# Check available resources
docker system df
docker system prune

# Monitor resource usage
docker stats
```

**Tool Execution Timeouts**
```yaml
# Increase timeouts in config.yaml
security:
  max_execution_time: 600  # 10 minutes
  container_timeout: 900   # 15 minutes
```

**Network Connectivity Issues**
```bash
# Test container networking
docker run --rm kalilinux/kali-rolling ping -c 3 google.com

# Check DNS resolution
docker run --rm kalilinux/kali-rolling nslookup example.com
```

### Debug Mode

```bash
# Run with debug logging
export LOG_LEVEL=DEBUG
python -m cybersec_mcp_server.main

# Enable MCP debug
export MCP_DEBUG=1
```

## 📈 Performance Tuning

### Optimize for High Throughput

```yaml
# docker-compose.yml
services:
  cybersec-mcp-server:
    environment:
      - MAX_CONCURRENT_EXECUTIONS=10
      - WORKER_PROCESSES=4
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'
```

### Container Optimization

```dockerfile
# Optimized Dockerfile for faster container startup
FROM kalilinux/kali-rolling

# Pre-install common tools
RUN apt-get update && apt-get install -y \
    nmap nikto gobuster sqlmap masscan \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Warm up tool caches
RUN nmap --version && nikto -Version
```

## 🔄 Updates and Maintenance

### Automated Updates

```bash
#!/bin/bash
# update-server.sh

# Pull latest code
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Pull latest tool images
docker-compose pull

# Restart services
docker-compose down
docker-compose up -d

# Verify health
curl -f http://localhost:8080/health || exit 1
```

### Health Monitoring

```python
# Health check endpoint
@app.get("/health")
async def health_check():
    try:
        # Test Docker connectivity
        client = docker.from_env()
        client.ping()
        
        # Test tool availability
        test_result = await execute_tool("nmap", {"target": "127.0.0.1", "preset": "quick_scan"})
        
        return {"status": "healthy", "timestamp": datetime.now()}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
```

## 📞 Support

For issues and feature requests:
- GitHub Issues: [Link to your repository]
- Documentation: [Link to docs]
- Security Issues: security@yourcompany.com

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Kali Linux team for the tool ecosystem
- MCP protocol developers
- Docker team for containerization technology
- Open source security community