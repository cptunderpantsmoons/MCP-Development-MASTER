# MCP API Documentation

## Overview

This document describes the Model Context Protocol (MCP) API for the Cybersecurity Tools Server.

## Connection

The server communicates via MCP over stdio. Connect using any MCP-compatible client.

### Example Connection
```bash
python -m cybersec_mcp_server.main
```

## Available Methods

### 1. List Tools

**Method:** `tools/list`

Returns all available cybersecurity tools and their configurations.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    {
      "name": "nmap",
      "description": "Network discovery and security auditing",
      "inputSchema": {
        "type": "object",
        "properties": {
          "target": {"type": "string", "description": "Target URL, IP, or domain"},
          "preset": {"type": "string", "description": "Preset configuration"},
          "custom_args": {"type": "string", "description": "Custom command arguments"},
          "authorization": {"type": "string", "description": "Authorization token"}
        },
        "required": ["target"]
      }
    }
  ]
}
```

### 2. Call Tool

**Method:** `tools/call`

Executes a cybersecurity tool with specified parameters.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
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

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": [
    {
      "type": "text",
      "text": "# NMAP Execution Results\n\n**Command:** `nmap -T4 -F scanme.nmap.org`\n**Execution Time:** 12.45 seconds\n**Exit Code:** 0\n\n## Structured Results\n\n### Open Ports\n\n- **22/tcp** (ssh) - open\n- **80/tcp** (http) - open\n\n## Raw Output\n\n```\nStarting Nmap 7.91...\n```"
    }
  ]
}
```

### 3. List Resources

**Method:** `resources/list`

Returns available resources like logs and documentation.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "resources/list"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": [
    {
      "uri": "audit://logs",
      "name": "Audit Logs",
      "description": "Security audit and execution logs",
      "mimeType": "application/json"
    },
    {
      "uri": "config://security",
      "name": "Security Configuration",
      "description": "Current security settings and policies",
      "mimeType": "application/json"
    }
  ]
}
```

### 4. Read Resource

**Method:** `resources/read`

Retrieves the content of a specific resource.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "resources/read",
  "params": {
    "uri": "audit://logs"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "contents": [
      {
        "type": "text",
        "text": "[{\"timestamp\":\"2024-06-09T10:30:00Z\",\"tool_name\":\"nmap\",\"command\":\"nmap -T4 -F scanme.nmap.org\",\"target\":\"scanme.nmap.org\",\"exit_code\":0,\"execution_time\":12.45}]"
      }
    ]
  }
}
```

## Tool-Specific Parameters

### Nmap

**Available Presets:**
- `quick_scan`: Fast TCP scan (`nmap -T4 -F {target}`)
- `service_scan`: Service version detection (`nmap -sV -sC {target}`)
- `vuln_scan`: Vulnerability scanning (`nmap --script vuln {target}`)
- `stealth_scan`: Stealth TCP scan (`nmap -sS -T1 -f {target}`)

**Example:**
```json
{
  "name": "nmap",
  "arguments": {
    "target": "192.168.1.1",
    "preset": "service_scan"
  }
}
```

### Nikto

**Available Presets:**
- `standard`: Standard web scan (`nikto -h {url}`)
- `comprehensive`: Comprehensive scan (`nikto -h {url} -C all`)
- `ssl_check`: SSL-specific tests (`nikto -h {url} -ssl`)

**Example:**
```json
{
  "name": "nikto",
  "arguments": {
    "target": "https://example.com",
    "preset": "comprehensive"
  }
}
```

### Gobuster

**Available Presets:**
- `dir_enum`: Directory enumeration
- `subdomain`: Subdomain discovery
- `files`: File enumeration with extensions

**Example:**
```json
{
  "name": "gobuster",
  "arguments": {
    "target": "https://example.com",
    "preset": "dir_enum"
  }
}
```

### SQLMap

**Available Presets:**
- `basic_test`: Basic SQL injection test
- `enumerate_dbs`: Database enumeration
- `dump_table`: Table data extraction

**Example (Requires Authorization):**
```json
{
  "name": "sqlmap",
  "arguments": {
    "target": "https://vulnerable-site.com/page.php?id=1",
    "preset": "basic_test",
    "authorization": "your-auth-token"
  }
}
```

### Searchsploit

**Available Presets:**
- `search`: Search for exploits
- `cve_lookup`: CVE-specific search
- `examine`: Examine specific exploit

**Example:**
```json
{
  "name": "searchsploit",
  "arguments": {
    "target": "apache 2.4",
    "preset": "search"
  }
}
```

### Masscan

**Available Presets:**
- `fast_tcp`: High-speed TCP scan
- `top_ports`: Scan common ports only

**Example:**
```json
{
  "name": "masscan",
  "arguments": {
    "target": "192.168.1.0/24",
    "preset": "top_ports"
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
    "code": -32000,
    "message": "Tool execution failed",
    "data": {
      "tool": "nmap",
      "reason": "Target validation failed",
      "details": "Target '127.0.0.1' not in allowed list"
    }
  }
}
```

### Common Error Codes

- `-32000`: Tool execution error
- `-32001`: Authentication required
- `-32002`: Rate limit exceeded
- `-32003`: Invalid target
- `-32004`: Tool not available

## Rate Limiting

The server implements rate limiting to prevent abuse:

- **Default**: 60 requests per minute per client
- **Tool execution**: 5 concurrent executions maximum
- **Heavy tools** (masscan, nmap with large ranges): Additional restrictions

## Authentication

For tools requiring authorization (SQLMap, Metasploit):

1. Obtain authorization token from administrator
2. Include token in `authorization` parameter
3. All authorized actions are logged for audit

```json
{
  "name": "sqlmap",
  "arguments": {
    "target": "https://test-site.com/vulnerable.php?id=1",
    "preset": "basic_test",
    "authorization": "sk-auth-token-here"
  }
}
```

## Best Practices

### 1. Target Validation
Always ensure you have permission to scan the target:
```json
{
  "target": "your-authorized-domain.com"
}
```

### 2. Use Appropriate Presets
Choose presets based on your testing requirements:
- `quick_scan` for initial reconnaissance
- `comprehensive` for thorough assessment
- `stealth` for evasive testing

### 3. Monitor Resource Usage
- Use lighter scans first
- Avoid aggressive scans on production systems
- Monitor execution times and resource consumption

### 4. Handle Results Properly
- Parse structured output for automation
- Preserve raw output for evidence
- Follow up on identified vulnerabilities

## Integration Examples

### Python Client
```python
import json
import subprocess

def call_mcp_tool(tool_name, arguments):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    
    process = subprocess.Popen(
        ["python", "-m", "cybersec_mcp_server.main"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    stdout, stderr = process.communicate(json.dumps(request))
    return json.loads(stdout)

# Usage
result = call_mcp_tool("nmap", {
    "target": "scanme.nmap.org",
    "preset": "quick_scan"
})
```

### Node.js Client
```javascript
const { spawn } = require('child_process');

function callMCPTool(toolName, arguments) {
    return new Promise((resolve, reject) => {
        const child = spawn('python', ['-m', 'cybersec_mcp_server.main']);
        
        const request = {
            jsonrpc: "2.0",
            id: 1,
            method: "tools/call",
            params: {
                name: toolName,
                arguments: arguments
            }
        };
        
        child.stdin.write(JSON.stringify(request));
        child.stdin.end();
        
        let output = '';
        child.stdout.on('data', (data) => {
            output += data;
        });
        
        child.on('close', (code) => {
            resolve(JSON.parse(output));
        });
    });
}

// Usage
callMCPTool('nmap', {
    target: 'scanme.nmap.org',
    preset: 'quick_scan'
}).then(result => {
    console.log(result);
});
```

## Support

For API questions and support:
- Documentation: [GitHub Wiki]
- Issues: [GitHub Issues]
- Community: [Discord/Slack Channel]
