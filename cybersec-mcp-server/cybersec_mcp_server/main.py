#!/usr/bin/env python3
"""
Cybersecurity Tools MCP Server
A Model Context Protocol server for secure integration with penetration testing tools.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
import docker
import aiofiles
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ToolExecution(BaseModel):
    """Model for tool execution results"""
    tool_name: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    timestamp: datetime
    parsed_output: Optional[Dict[str, Any]] = None

class SecurityConfig(BaseModel):
    """Security configuration for tool execution"""
    max_execution_time: int = 300  # 5 minutes
    allowed_targets: List[str] = []
    require_authorization: bool = True
    log_all_executions: bool = True
    container_timeout: int = 600

class CybersecMCPServer:
    """MCP Server for cybersecurity tools integration"""
    
    def __init__(self):
        self.server = Server("cybersec-tools")
        self.docker_client = docker.from_env()
        self.security_config = SecurityConfig()
        self.audit_log_path = Path("./audit_logs")
        self.audit_log_path.mkdir(exist_ok=True)
        
        # Tool configurations
        self.tools_config = {
            "nmap": {
                "description": "Network discovery and security auditing",
                "container_image": "kalilinux/kali-rolling",
                "safety_checks": ["validate_target", "check_rate_limits"],
                "output_parser": "parse_nmap_output",
                "presets": {
                    "quick_scan": "nmap -T4 -F {target}",
                    "service_scan": "nmap -sV -sC {target}",
                    "vuln_scan": "nmap --script vuln {target}",
                    "stealth_scan": "nmap -sS -T1 -f {target}"
                }
            },
            "nikto": {
                "description": "Web server scanner for vulnerabilities",
                "container_image": "kalilinux/kali-rolling",
                "safety_checks": ["validate_url", "check_permissions"],
                "output_parser": "parse_nikto_output",
                "presets": {
                    "standard": "nikto -h {url}",
                    "comprehensive": "nikto -h {url} -C all",
                    "ssl_check": "nikto -h {url} -ssl"
                }
            },
            "gobuster": {
                "description": "Directory and file enumeration tool",
                "container_image": "kalilinux/kali-rolling",
                "safety_checks": ["validate_url"],
                "output_parser": "parse_gobuster_output",
                "presets": {
                    "dir_enum": "gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt",
                    "subdomain": "gobuster dns -d {domain} -w /usr/share/wordlists/dnsrecon/subdomains-top1mil-20.txt",
                    "files": "gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js"
                }
            },
            "sqlmap": {
                "description": "SQL injection detection and exploitation",
                "container_image": "kalilinux/kali-rolling",
                "safety_checks": ["validate_url", "require_authorization", "log_database_access"],
                "output_parser": "parse_sqlmap_output",
                "presets": {
                    "basic_test": "sqlmap -u '{url}' --batch --level=1 --risk=1",
                    "enumerate_dbs": "sqlmap -u '{url}' --batch --dbs",
                    "dump_table": "sqlmap -u '{url}' --batch -D {database} -T {table} --dump"
                }
            },
            "searchsploit": {
                "description": "Exploit database search",
                "container_image": "kalilinux/kali-rolling",
                "safety_checks": [],
                "output_parser": "parse_searchsploit_output",
                "presets": {
                    "search": "searchsploit {search_term}",
                    "cve_lookup": "searchsploit --cve {cve}",
                    "examine": "searchsploit -x {exploit_id}"
                }
            },
            "masscan": {
                "description": "High-speed port scanner",
                "container_image": "kalilinux/kali-rolling",
                "safety_checks": ["validate_target", "check_rate_limits"],
                "output_parser": "parse_masscan_output",
                "presets": {
                    "fast_tcp": "masscan -p1-65535 {target} --rate=1000",
                    "top_ports": "masscan -p80,443,22,21,25,53,110,993,995 {target} --rate=5000"
                }
            }
        }
        
        self._register_handlers()

    def _register_handlers(self):
        """Register MCP handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available cybersecurity tools"""
            tools = []
            
            for tool_name, config in self.tools_config.items():
                # Add base tool
                tools.append(Tool(
                    name=tool_name,
                    description=config["description"],
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target URL, IP, or domain"},
                            "preset": {"type": "string", "description": f"Preset configuration: {', '.join(config['presets'].keys())}"},
                            "custom_args": {"type": "string", "description": "Custom command arguments"},
                            "authorization": {"type": "string", "description": "Authorization token for restricted tools"}
                        },
                        "required": ["target"]
                    }
                ))
                
                # Add preset tools
                for preset_name, preset_cmd in config["presets"].items():
                    tools.append(Tool(
                        name=f"{tool_name}_{preset_name}",
                        description=f"{config['description']} - {preset_name} preset",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "target": {"type": "string", "description": "Target URL, IP, or domain"},
                                "authorization": {"type": "string", "description": "Authorization token"}
                            },
                            "required": ["target"]
                        }
                    ))
            
            return tools

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Execute cybersecurity tools"""
            try:
                # Parse tool name and preset
                if "_" in name and name.split("_")[0] in self.tools_config:
                    tool_parts = name.split("_", 1)
                    tool_name = tool_parts[0]
                    preset = tool_parts[1] if len(tool_parts) > 1 else None
                else:
                    tool_name = name
                    preset = arguments.get("preset")
                
                if tool_name not in self.tools_config:
                    return [TextContent(
                        type="text",
                        text=f"Error: Unknown tool '{tool_name}'"
                    )]
                
                # Execute tool
                result = await self._execute_tool(tool_name, arguments, preset)
                
                # Format response
                response_text = self._format_tool_response(result)
                
                return [TextContent(type="text", text=response_text)]
                
            except Exception as e:
                logger.error(f"Tool execution error: {e}")
                return [TextContent(
                    type="text",
                    text=f"Error executing tool: {str(e)}"
                )]

        @self.server.list_resources()
        async def handle_list_resources() -> List[Resource]:
            """List available resources"""
            return [
                Resource(
                    uri="audit://logs",
                    name="Audit Logs",
                    description="Security audit and execution logs",
                    mimeType="application/json"
                ),
                Resource(
                    uri="config://security",
                    name="Security Configuration",
                    description="Current security settings and policies",
                    mimeType="application/json"
                ),
                Resource(
                    uri="tools://documentation",
                    name="Tools Documentation",
                    description="Documentation for all available tools",
                    mimeType="text/markdown"
                )
            ]

        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Read resource content"""
            if uri == "audit://logs":
                return await self._get_audit_logs()
            elif uri == "config://security":
                return json.dumps(self.security_config.dict(), indent=2)
            elif uri == "tools://documentation":
                return self._generate_tools_documentation()
            else:
                raise ValueError(f"Unknown resource: {uri}")

    async def _execute_tool(self, tool_name: str, arguments: Dict[str, Any], preset: Optional[str] = None) -> ToolExecution:
        """Execute a cybersecurity tool in isolated container"""
        config = self.tools_config[tool_name]
        target = arguments.get("target", "")
        custom_args = arguments.get("custom_args", "")
        authorization = arguments.get("authorization", "")
        
        # Security checks
        await self._perform_security_checks(tool_name, config, arguments)
        
        # Build command
        if preset and preset in config["presets"]:
            command = config["presets"][preset].format(
                target=target,
                url=target,
                domain=target,
                **arguments
            )
        elif custom_args:
            command = f"{tool_name} {custom_args}"
        else:
            command = f"{tool_name} {target}"
        
        # Execute in container
        start_time = datetime.now()
        try:
            result = await self._run_in_container(
                config["container_image"],
                command,
                timeout=self.security_config.max_execution_time
            )
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Parse output
            parsed_output = await self._parse_tool_output(tool_name, result["stdout"])
            
            execution = ToolExecution(
                tool_name=tool_name,
                command=command,
                exit_code=result["exit_code"],
                stdout=result["stdout"],
                stderr=result["stderr"],
                execution_time=execution_time,
                timestamp=start_time,
                parsed_output=parsed_output
            )
            
            # Log execution
            await self._log_execution(execution, arguments)
            
            return execution
            
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ToolExecution(
                tool_name=tool_name,
                command=command,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                timestamp=start_time
            )

    async def _run_in_container(self, image: str, command: str, timeout: int = 300) -> Dict[str, Any]:
        """Run command in isolated Docker container"""
        container_name = f"cybersec-tool-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        try:
            # Create and run container
            container = self.docker_client.containers.run(
                image,
                command=f"bash -c '{command}'",
                name=container_name,
                detach=True,
                remove=True,
                network_mode="bridge",
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000,  # 50% CPU limit
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                cap_add=["NET_RAW"],  # For network tools
                read_only=True,
                tmpfs={"/tmp": "noexec,nosuid,size=100m"}
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=timeout)
                logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
                
                return {
                    "exit_code": result["StatusCode"],
                    "stdout": logs,
                    "stderr": ""
                }
            except Exception as e:
                container.kill()
                raise TimeoutError(f"Container execution timed out: {e}")
                
        except Exception as e:
            logger.error(f"Container execution failed: {e}")
            raise

    async def _perform_security_checks(self, tool_name: str, config: Dict[str, Any], arguments: Dict[str, Any]):
        """Perform security validations before tool execution"""
        target = arguments.get("target", "")
        
        for check in config.get("safety_checks", []):
            if check == "validate_target":
                await self._validate_target(target)
            elif check == "validate_url":
                await self._validate_url(target)
            elif check == "require_authorization":
                await self._check_authorization(arguments.get("authorization", ""))
            elif check == "check_rate_limits":
                await self._check_rate_limits(tool_name)
            elif check == "log_database_access":
                await self._log_database_access(target)

    async def _validate_target(self, target: str):
        """Validate that target is allowed"""
        if not target:
            raise ValueError("Target is required")
        
        # Check against allowed targets if configured
        if self.security_config.allowed_targets:
            if not any(allowed in target for allowed in self.security_config.allowed_targets):
                raise ValueError(f"Target '{target}' not in allowed list")

    async def _validate_url(self, url: str):
        """Validate URL format"""
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")

    async def _check_authorization(self, auth_token: str):
        """Check authorization for restricted tools"""
        if self.security_config.require_authorization and not auth_token:
            raise ValueError("Authorization required for this tool")

    async def _check_rate_limits(self, tool_name: str):
        """Check rate limits for tool usage"""
        # Implement rate limiting logic
        pass

    async def _log_database_access(self, target: str):
        """Log database access attempts"""
        logger.warning(f"Database tool access attempt for target: {target}")

    async def _parse_tool_output(self, tool_name: str, output: str) -> Optional[Dict[str, Any]]:
        """Parse tool output into structured format"""
        try:
            if tool_name == "nmap":
                return self._parse_nmap_output(output)
            elif tool_name == "nikto":
                return self._parse_nikto_output(output)
            elif tool_name == "gobuster":
                return self._parse_gobuster_output(output)
            elif tool_name == "searchsploit":
                return self._parse_searchsploit_output(output)
            elif tool_name == "masscan":
                return self._parse_masscan_output(output)
            else:
                return {"raw_output": output}
        except Exception as e:
            logger.error(f"Output parsing failed for {tool_name}: {e}")
            return {"error": str(e), "raw_output": output}

    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output"""
        result = {
            "hosts": [],
            "open_ports": [],
            "summary": {}
        }
        
        lines = output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Parse host information
            if "Nmap scan report for" in line:
                current_host = line.split("for ")[-1]
                result["hosts"].append({"host": current_host, "ports": []})
            
            # Parse port information
            elif "/" in line and ("open" in line or "closed" in line or "filtered" in line):
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    
                    if current_host and result["hosts"]:
                        result["hosts"][-1]["ports"].append(port_info)
                    
                    if port_info["state"] == "open":
                        result["open_ports"].append(port_info)
        
        return result

    def _parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """Parse nikto output"""
        result = {
            "vulnerabilities": [],
            "target_info": {},
            "summary": {}
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse vulnerabilities
            if line.startswith('+') and 'OSVDB' in line:
                vuln = {
                    "description": line,
                    "severity": "medium"  # Default, could be enhanced
                }
                result["vulnerabilities"].append(vuln)
            
            # Parse target info
            elif "Target IP:" in line:
                result["target_info"]["ip"] = line.split(":")[-1].strip()
            elif "Target Hostname:" in line:
                result["target_info"]["hostname"] = line.split(":")[-1].strip()
        
        result["summary"]["total_findings"] = len(result["vulnerabilities"])
        
        return result

    def _parse_gobuster_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output"""
        result = {
            "found_paths": [],
            "status_codes": {},
            "summary": {}
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse found paths
            if line.startswith('/') and ('Status:' in line or 'Size:' in line):
                parts = line.split()
                if len(parts) >= 3:
                    path_info = {
                        "path": parts[0],
                        "status": parts[2] if 'Status:' in line else "unknown",
                        "size": parts[4] if 'Size:' in line else "unknown"
                    }
                    result["found_paths"].append(path_info)
                    
                    # Count status codes
                    status = path_info["status"]
                    result["status_codes"][status] = result["status_codes"].get(status, 0) + 1
        
        result["summary"]["total_paths"] = len(result["found_paths"])
        
        return result

    def _parse_searchsploit_output(self, output: str) -> Dict[str, Any]:
        """Parse searchsploit output"""
        result = {
            "exploits": [],
            "summary": {}
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip headers and separators
            if line.startswith('-') or 'Exploit Title' in line or not line:
                continue
            
            # Parse exploit entries
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    exploit = {
                        "title": parts[0].strip(),
                        "path": parts[1].strip()
                    }
                    result["exploits"].append(exploit)
        
        result["summary"]["total_exploits"] = len(result["exploits"])
        
        return result

    def _parse_masscan_output(self, output: str) -> Dict[str, Any]:
        """Parse masscan output"""
        result = {
            "open_ports": [],
            "hosts": set(),
            "summary": {}
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse discovered ports
            if 'Discovered open port' in line:
                parts = line.split()
                if len(parts) >= 5:
                    port_info = {
                        "port": parts[3].split('/')[0],
                        "protocol": parts[3].split('/')[1] if '/' in parts[3] else "tcp",
                        "host": parts[5]
                    }
                    result["open_ports"].append(port_info)
                    result["hosts"].add(parts[5])
        
        result["hosts"] = list(result["hosts"])
        result["summary"]["total_open_ports"] = len(result["open_ports"])
        result["summary"]["total_hosts"] = len(result["hosts"])
        
        return result

    async def _log_execution(self, execution: ToolExecution, arguments: Dict[str, Any]):
        """Log tool execution for audit purposes"""
        log_entry = {
            "timestamp": execution.timestamp.isoformat(),
            "tool_name": execution.tool_name,
            "command": execution.command,
            "target": arguments.get("target", ""),
            "exit_code": execution.exit_code,
            "execution_time": execution.execution_time,
            "user_agent": "mcp-cybersec-server",
            "arguments": arguments
        }
        
        log_file = self.audit_log_path / f"audit_{datetime.now().strftime('%Y%m%d')}.json"
        
        try:
            async with aiofiles.open(log_file, 'a') as f:
                await f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def _format_tool_response(self, execution: ToolExecution) -> str:
        """Format tool execution response"""
        response = f"# {execution.tool_name.upper()} Execution Results\n\n"
        response += f"**Command:** `{execution.command}`\n"
        response += f"**Execution Time:** {execution.execution_time:.2f} seconds\n"
        response += f"**Exit Code:** {execution.exit_code}\n\n"
        
        if execution.parsed_output:
            response += "## Structured Results\n\n"
            
            # Format based on tool type
            if execution.tool_name == "nmap":
                self._format_nmap_response(response, execution.parsed_output)
            elif execution.tool_name == "nikto":
                self._format_nikto_response(response, execution.parsed_output)
            elif execution.tool_name == "gobuster":
                self._format_gobuster_response(response, execution.parsed_output)
            elif execution.tool_name == "searchsploit":
                self._format_searchsploit_response(response, execution.parsed_output)
            else:
                response += f"```json\n{json.dumps(execution.parsed_output, indent=2)}\n```\n\n"
        
        if execution.stdout:
            response += "## Raw Output\n\n"
            response += f"```\n{execution.stdout}\n```\n\n"
        
        if execution.stderr:
            response += "## Errors\n\n"
            response += f"```\n{execution.stderr}\n```\n\n"
        
        return response

    def _format_nmap_response(self, response: str, parsed: Dict[str, Any]) -> str:
        """Format nmap response"""
        if parsed.get("open_ports"):
            response += "### Open Ports\n\n"
            for port in parsed["open_ports"]:
                response += f"- **{port['port']}** ({port['service']}) - {port['state']}\n"
            response += "\n"
        
        if parsed.get("hosts"):
            response += "### Host Details\n\n"
            for host in parsed["hosts"]:
                response += f"**{host['host']}:**\n"
                for port in host.get("ports", []):
                    response += f"  - {port['port']} ({port['service']}) - {port['state']}\n"
                response += "\n"

    def _format_nikto_response(self, response: str, parsed: Dict[str, Any]) -> str:
        """Format nikto response"""
        if parsed.get("vulnerabilities"):
            response += f"### Vulnerabilities Found: {len(parsed['vulnerabilities'])}\n\n"
            for vuln in parsed["vulnerabilities"]:
                response += f"- {vuln['description']}\n"
            response += "\n"

    def _format_gobuster_response(self, response: str, parsed: Dict[str, Any]) -> str:
        """Format gobuster response"""
        if parsed.get("found_paths"):
            response += f"### Discovered Paths: {len(parsed['found_paths'])}\n\n"
            for path in parsed["found_paths"]:
                response += f"- **{path['path']}** (Status: {path['status']}, Size: {path['size']})\n"
            response += "\n"

    def _format_searchsploit_response(self, response: str, parsed: Dict[str, Any]) -> str:
        """Format searchsploit response"""
        if parsed.get("exploits"):
            response += f"### Exploits Found: {len(parsed['exploits'])}\n\n"
            for exploit in parsed["exploits"]:
                response += f"- **{exploit['title']}**\n  Path: `{exploit['path']}`\n"
            response += "\n"

    async def _get_audit_logs(self) -> str:
        """Get recent audit logs"""
        logs = []
        
        try:
            log_file = self.audit_log_path / f"audit_{datetime.now().strftime('%Y%m%d')}.json"
            if log_file.exists():
                async with aiofiles.open(log_file, 'r') as f:
                    content = await f.read()
                    for line in content.strip().split('\n'):
                        if line:
                            logs.append(json.loads(line))
            
            return json.dumps(logs[-50:], indent=2)  # Last 50 entries
        except Exception as e:
            return f"Error reading audit logs: {e}"

    def _generate_tools_documentation(self) -> str:
        """Generate tools documentation"""
        doc = "# Cybersecurity Tools MCP Server\n\n"
        doc += "This MCP server provides secure access to penetration testing tools.\n\n"
        
        doc += "## Available Tools\n\n"
        
        for tool_name, config in self.tools_config.items():
            doc += f"### {tool_name}\n\n"
            doc += f"{config['description']}\n\n"
            
            doc += "**Presets:**\n"
            for preset_name, preset_cmd in config['presets'].items():
                doc += f"- `{preset_name}`: {preset_cmd}\n"
            doc += "\n"
            
            doc += "**Safety Checks:**\n"
            for check in config.get('safety_checks', []):
                doc += f"- {check}\n"
            doc += "\n"
        
        return doc

async def main():
    """Main entry point"""
    server_instance = CybersecMCPServer()
    
    # Set up server options
    options = InitializationOptions(
        server_name="cybersec-tools",
        server_version="1.0.0",
        capabilities={
            "tools": {},
            "resources": {}
        }
    )
    
    async with stdio_server() as (read_stream, write_stream):
        await server_instance.server.run(
            read_stream,
            write_stream,
            options
        )

if __name__ == "__main__":
    asyncio.run(main())
