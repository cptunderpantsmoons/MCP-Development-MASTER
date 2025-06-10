# 🔍 Threat Intelligence MCP Server - API Reference

## Overview

Complete API reference for the Threat Intelligence MCP Server. This server provides professional-grade threat intelligence analysis through the Model Context Protocol (MCP).

## Connection

The server communicates via MCP over stdio. Compatible with any MCP client including Claude, ChatGPT, and custom implementations.

```bash
python -m threat_intel_mcp_server.main
```

## Available Tools

### 1. IP Reputation Analysis

**Tool:** `ip_reputation`

Comprehensive IP address reputation analysis using multiple threat intelligence sources.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call", 
  "params": {
    "name": "ip_reputation",
    "arguments": {
      "indicator": "192.168.1.1",
      "sources": ["virustotal", "abuseipdb", "greynoise"],
      "include_raw": false
    }
  }
}
```

**Parameters:**
- `indicator` (required): IP address to analyze
- `sources` (optional): Specific intelligence sources to query
- `include_raw` (optional): Include raw API responses

**Sources Used:**
- VirusTotal - Malware detection and URL analysis
- AbuseIPDB - IP abuse confidence scoring
- GreyNoise - Internet scanner detection
- Shodan - Service and vulnerability information

### 2. Domain Reputation Analysis

**Tool:** `domain_reputation`

Domain reputation and DNS intelligence analysis.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "domain_reputation", 
    "arguments": {
      "indicator": "suspicious-domain.com",
      "sources": ["virustotal", "urlvoid", "whois"]
    }
  }
}
```

**Sources Used:**
- VirusTotal - Domain reputation and associated malware
- URLVoid - Domain blacklist checking
- WHOIS - Registration and ownership information

### 3. URL Safety Analysis

**Tool:** `url_analysis`

Comprehensive URL safety and reputation analysis.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "url_analysis",
    "arguments": {
      "indicator": "https://suspicious-site.com/malware.exe"
    }
  }
}
```

**Sources Used:**
- VirusTotal - URL scanning and malware detection
- URLVoid - URL reputation checking

### 4. File Hash Lookup

**Tool:** `hash_lookup`

File hash reputation and malware analysis.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "hash_lookup",
    "arguments": {
      "indicator": "d41d8cd98f00b204e9800998ecf8427e"
    }
  }
}
```

**Supported Hash Types:**
- MD5 (32 characters)
- SHA1 (40 characters)  
- SHA256 (64 characters)

**Sources Used:**
- VirusTotal - File reputation and malware analysis
- AlienVault OTX - Community threat intelligence

### 5. Email Breach Check

**Tool:** `email_breach_check`

Check if email address appears in known data breaches.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "email_breach_check",
    "arguments": {
      "indicator": "user@example.com"
    }
  }
}
```

**Sources Used:**
- Have I Been Pwned - Breach database checking

### 6. Shodan Internet Search

**Tool:** `shodan_search`

Search Shodan for internet-connected devices and services.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "shodan_search",
    "arguments": {
      "indicator": "apache 2.4.7",
      "api_key": "your-shodan-key"
    }
  }
}
```

**Search Examples:**
- `"apache 2.4.7"` - Find servers running Apache 2.4.7
- `"port:22"` - Find devices with SSH open
- `"country:US city:Chicago"` - Geo-targeted searches

### 7. IOC Enrichment

**Tool:** `ioc_enrichment`

Enrich indicators of compromise with comprehensive threat intelligence.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "ioc_enrichment",
    "arguments": {
      "indicator": "malicious-domain.com",
      "sources": ["virustotal", "otx", "abuseipdb"]
    }
  }
}
```

### 8. Company OSINT

**Tool:** `company_osint`

Open source intelligence gathering for companies and domains.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "company_osint",
    "arguments": {
      "indicator": "target-company.com"
    }
  }
}
```

**Intelligence Gathered:**
- Domain registration information
- SSL certificate details
- Internet-facing services
- Subdomain enumeration

### 9. Threat Hunting

**Tool:** `threat_hunting`

Proactive threat hunting using multiple intelligence sources.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "tools/call",
  "params": {
    "name": "threat_hunting",
    "arguments": {
      "indicator": "apt28 tactics"
    }
  }
}
```

### 10. Certificate Analysis

**Tool:** `certificate_analysis`

SSL/TLS certificate transparency and analysis.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "certificate_analysis",
    "arguments": {
      "indicator": "example.com"
    }
  }
}
```

## Bulk Analysis Tools

### Bulk IOC Analysis

**Tool:** `bulk_ioc_analysis`

Analyze multiple indicators of compromise in batch.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "tools/call",
  "params": {
    "name": "bulk_ioc_analysis",
    "arguments": {
      "indicators": [
        "192.168.1.100",
        "evil-domain.com", 
        "https://malicious-url.com",
        "d41d8cd98f00b204e9800998ecf8427e"
      ],
      "output_format": "summary"
    }
  }
}
```

**Output Formats:**
- `summary` - Condensed results overview
- `detailed` - Full analysis for each indicator
- `csv` - Comma-separated values for import

### Threat Feed Monitor

**Tool:** `threat_feed_monitor`

Monitor threat feeds for specific indicators or patterns.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "tools/call",
  "params": {
    "name": "threat_feed_monitor",
    "arguments": {
      "watch_terms": ["apt28", "cobalt strike", "company-domain.com"],
      "feed_sources": ["otx", "abuse_ch"],
      "alert_threshold": 75
    }
  }
}
```

## Response Format

### Standard Response Structure

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    {
      "type": "text",
      "text": "# 🔍 Threat Intelligence Analysis\n\n**Indicator:** `8.8.8.8`\n**Type:** IP\n**Analysis Time:** 2024-06-09 14:30:22 UTC\n\n**Reputation Score:** 95.2/100\n**Confidence Level:** 85.0%\n\n## ✅ No Immediate Threats Detected\n\n## 📊 Intelligence Sources\n\n### VirusTotal\n- **Status:** success\n- **Summary:** Detected by 0/84 engines\n- **Key Findings:**\n  - Clean reputation across all engines\n\n### AbuseIPDB\n- **Status:** success\n- **Summary:** Abuse confidence: 0%\n- **Key Findings:**\n  - No abuse reports in last 90 days\n\n## 💡 Recommendations\n- Continue monitoring as part of routine threat intelligence\n- No immediate action required\n\n---\n*Analysis generated by Threat Intelligence MCP Server*"
    }
  ]
}
```

### Response Components

#### Threat Assessment
- **Reputation Score**: 0-100 scale (higher = better reputation)
- **Confidence Level**: Analysis confidence based on source count
- **Threat Types**: Detected threat categories (malware, abuse, scanner, breach)

#### Intelligence Sources
- **Status**: Success/failure for each source
- **Summary**: Key findings from each source
- **Key Findings**: Important discoveries per source

#### Recommendations
- Immediate actions based on threat level
- Context-specific guidance
- Follow-up investigation suggestions

## Resource Access

### List Resources

**Method:** `resources/list`

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "resources/list"
}
```

**Available Resources:**
- `intel://logs` - Intelligence query logs
- `feeds://active` - Active threat feed status
- `iocs://watchlist` - IOC monitoring watchlist
- `reports://summary` - Intelligence summary reports

### Read Resource

**Method:** `resources/read`

```json
{
  "jsonrpc": "2.0", 
  "id": 2,
  "method": "resources/read",
  "params": {
    "uri": "intel://logs"
  }
}
```

## Error Handling

### Error Response Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "API rate limit exceeded",
    "data": {
      "api": "virustotal",
      "retry_after": 60,
      "current_limit": 4,
      "suggestion": "Upgrade to premium API plan or enable caching"
    }
  }
}
```

### Error Codes

| Code | Message | Description |
|------|---------|-------------|
| -32001 | API rate limit exceeded | Too many requests to external API |
| -32002 | Invalid indicator format | Malformed IP, domain, URL, or hash |
| -32003 | API key required | Premium API access needed |
| -32004 | Indicator type not supported | Tool doesn't support this indicator type |
| -32005 | External API error | Third-party service unavailable |

## Rate Limiting

### API Rate Limits

| Service | Free Tier | Premium |
|---------|-----------|---------|
| VirusTotal | 4 req/min | 1000 req/min |
| Shodan | 100 req/month | Varies |
| Have I Been Pwned | 10 req/min | 100 req/min |
| AbuseIPDB | 1000 req/day | 10000+ req/day |
| GreyNoise | Community free | 1000+ req/day |

### Rate Limit Handling

The server automatically:
- Respects API rate limits
- Queues requests when limits reached
- Provides retry-after guidance
- Uses intelligent caching to reduce API calls

## Authentication

### API Key Management

Set API keys in `.env` file:

```bash
VIRUSTOTAL_API_KEY=your-vt-key-here
SHODAN_API_KEY=your-shodan-key-here
HIBP_API_KEY=your-hibp-key-here
ABUSEIPDB_API_KEY=your-abuseipdb-key-here
# ... other API keys
```

### Server Authentication

For production deployment, enable server authentication:

```bash
REQUIRE_AUTHENTICATION=true
INTEL_SERVER_API_KEY=your-secure-server-key
```

Include in requests:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "ip_reputation",
    "arguments": {
      "indicator": "8.8.8.8",
      "api_key": "your-secure-server-key"
    }
  }
}
```

## Performance Optimization

### Caching

Enable intelligent caching to reduce API costs:

```yaml
# config.yaml
caching:
  enable_caching: true
  cache_ttl_by_type:
    ip: 30        # 30 minutes
    domain: 60    # 1 hour
    hash: 1440    # 24 hours
    email: 60     # 1 hour
```

### Bulk Processing

Use bulk analysis for multiple indicators:

```json
{
  "name": "bulk_ioc_analysis",
  "arguments": {
    "indicators": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
    "output_format": "summary"
  }
}
```

Benefits:
- Reduced API overhead
- Parallel processing
- Consolidated reporting
- Cost optimization

## Integration Examples

### Python Client

```python
import json
import subprocess

class ThreatIntelClient:
    def __init__(self):
        self.server_process = None
        
    def start_server(self):
        self.server_process = subprocess.Popen(
            ["python", "-m", "threat_intel_mcp_server.main"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    
    def analyze_ip(self, ip_address):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "ip_reputation",
                "arguments": {
                    "indicator": ip_address
                }
            }
        }
        
        self.server_process.stdin.write(json.dumps(request) + '\n')
        self.server_process.stdin.flush()
        
        response = self.server_process.stdout.readline()
        return json.loads(response)

# Usage
client = ThreatIntelClient()
client.start_server()
result = client.analyze_ip("8.8.8.8")
print(result)
```

### Node.js Client

```javascript
const { spawn } = require('child_process');

class ThreatIntelClient {
    constructor() {
        this.server = spawn('python', ['-m', 'threat_intel_mcp_server.main']);
    }
    
    async analyzeIndicator(tool, indicator) {
        return new Promise((resolve, reject) => {
            const request = {
                jsonrpc: "2.0",
                id: Date.now(),
                method: "tools/call",
                params: {
                    name: tool,
                    arguments: { indicator }
                }
            };
            
            this.server.stdin.write(JSON.stringify(request) + '\n');
            
            this.server.stdout.once('data', (data) => {
                try {
                    const response = JSON.parse(data.toString());
                    resolve(response);
                } catch (error) {
                    reject(error);
                }
            });
        });
    }
}

// Usage
const client = new ThreatIntelClient();
client.analyzeIndicator('domain_reputation', 'example.com')
    .then(result => console.log(result));
```

## Best Practices

### 1. Indicator Validation

Always validate indicators before analysis:

```python
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain):
    return re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain) is not None
```

### 2. API Key Management

- Store API keys securely (environment variables, secret managers)
- Rotate keys regularly
- Monitor API usage and costs
- Use free tiers efficiently

### 3. Rate Limit Handling

- Implement exponential backoff
- Cache results to reduce API calls
- Use bulk analysis when possible
- Monitor rate limit metrics

### 4. Error Handling

```python
def safe_intel_query(tool, indicator):
    try:
        result = call_intel_tool(tool, indicator)
        return result
    except RateLimitError as e:
        # Wait and retry
        time.sleep(e.retry_after)
        return call_intel_tool(tool, indicator)
    except APIKeyError as e:
        # Log error and continue with other sources
        logger.warning(f"API key error for {tool}: {e}")
        return None
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Unexpected error: {e}")
        return None
```

### 5. Performance Optimization

- Use appropriate cache TTLs
- Implement request prioritization
- Monitor response times
- Optimize bulk processing batches

## Troubleshooting

### Common Issues

#### "API key required" Error
```bash
# Check API key configuration
grep VIRUSTOTAL_API_KEY .env

# Verify key format
echo $VIRUSTOTAL_API_KEY | wc -c  # Should be 64 characters for VT
```

#### Rate Limit Exceeded
```bash
# Check current rate limits
curl http://localhost:9090/metrics | grep rate_limit

# Enable caching to reduce API calls
export ENABLE_CACHING=true
```

#### Connection Timeout
```bash
# Increase timeout values
export REQUEST_TIMEOUT=60

# Check network connectivity
curl -I https://www.virustotal.com/vtapi/v2/
```

#### Memory Usage
```bash
# Monitor memory usage
docker stats threat-intel-mcp-server

# Adjust cache settings
export MAX_CACHE_ENTRIES=5000
```

## Support & Resources

### Documentation
- [GitHub Repository](your-repo-url)
- [Installation Guide](../README.md)
- [Configuration Reference](../config.yaml)

### Community
- [Discord Server](your-discord)
- [GitHub Discussions](your-discussions)
- [Stack Overflow Tag](threat-intel-mcp)

### Professional Support
- Email: support@redlog-ai.com
- Enterprise Support: enterprise@redlog-ai.com
- Security Issues: security@redlog-ai.com

---

*Threat Intelligence MCP Server API Reference v1.0.0*
