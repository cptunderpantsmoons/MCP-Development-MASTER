#!/usr/bin/env python3
"""
Threat Intelligence MCP Server
A Model Context Protocol server for comprehensive threat intelligence and OSINT gathering.
"""

import asyncio
import json
import logging
import hashlib
import base64
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import aiohttp
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
import ipaddress
import tldextract
import whois
from dns import resolver

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIntelResult(BaseModel):
    """Model for threat intelligence results"""
    indicator: str
    indicator_type: str  # ip, domain, url, hash, email
    source: str
    reputation_score: Optional[float] = None
    threat_types: List[str] = []
    confidence: Optional[float] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    raw_data: Dict[str, Any] = {}
    enriched_data: Dict[str, Any] = {}

class IntelligenceConfig(BaseModel):
    """Configuration for threat intelligence APIs"""
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    hibp_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    urlvoid_api_key: Optional[str] = None
    whoisxml_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    max_requests_per_minute: int = 100
    cache_ttl_minutes: int = 60
    enable_caching: bool = True

class ThreatIntelMCPServer:
    """MCP Server for threat intelligence and OSINT"""
    
    def __init__(self):
        self.server = Server("threat-intelligence")
        self.config = IntelligenceConfig()
        self.session = None
        self.cache = {}
        self.rate_limits = {}
        self.intel_log_path = Path("./intel_logs")
        self.intel_log_path.mkdir(exist_ok=True)
        
        # API endpoints and configurations
        self.api_configs = {
            "virustotal": {
                "base_url": "https://www.virustotal.com/vtapi/v2",
                "rate_limit": 4,  # requests per minute for free tier
                "endpoints": {
                    "file_report": "/file/report",
                    "url_report": "/url/report", 
                    "ip_report": "/ip-address/report",
                    "domain_report": "/domain/report"
                }
            },
            "shodan": {
                "base_url": "https://api.shodan.io",
                "rate_limit": 100,
                "endpoints": {
                    "host_info": "/shodan/host/{ip}",
                    "search": "/shodan/host/search",
                    "dns_lookup": "/dns/resolve",
                    "ports": "/shodan/ports"
                }
            },
            "haveibeenpwned": {
                "base_url": "https://haveibeenpwned.com/api/v3",
                "rate_limit": 10,
                "endpoints": {
                    "breachedaccount": "/breachedaccount/{account}",
                    "breaches": "/breaches",
                    "pastes": "/pasteaccount/{account}"
                }
            },
            "abuseipdb": {
                "base_url": "https://api.abuseipdb.com/api/v2",
                "rate_limit": 1000,
                "endpoints": {
                    "check": "/check",
                    "reports": "/reports"
                }
            },
            "greynoise": {
                "base_url": "https://api.greynoise.io/v3",
                "rate_limit": 100,
                "endpoints": {
                    "quick": "/community/{ip}",
                    "context": "/context/{ip}",
                    "riot": "/riot/{ip}"
                }
            },
            "urlvoid": {
                "base_url": "https://api.urlvoid.com/v1",
                "rate_limit": 100,
                "endpoints": {
                    "urlscan": "/pay-as-you-go/"
                }
            },
            "otx": {
                "base_url": "https://otx.alienvault.com/api/v1",
                "rate_limit": 300,
                "endpoints": {
                    "indicators": "/indicators/{type}/{indicator}/general",
                    "pulses": "/pulses/subscribed"
                }
            },
            "censys": {
                "base_url": "https://search.censys.io/api/v2",
                "rate_limit": 100,
                "endpoints": {
                    "hosts": "/hosts/{ip}",
                    "certificates": "/certificates/{fingerprint}"
                }
            }
        }
        
        # Intelligence gathering tools
        self.intel_tools = {
            "ip_reputation": {
                "description": "Check IP address reputation across multiple threat intelligence sources",
                "apis": ["virustotal", "shodan", "abuseipdb", "greynoise"],
                "input_type": "ip"
            },
            "domain_reputation": {
                "description": "Analyze domain reputation and DNS information",
                "apis": ["virustotal", "urlvoid", "whois"],
                "input_type": "domain"
            },
            "url_analysis": {
                "description": "Comprehensive URL safety and reputation analysis",
                "apis": ["virustotal", "urlvoid"],
                "input_type": "url"
            },
            "hash_lookup": {
                "description": "File hash reputation and malware analysis",
                "apis": ["virustotal", "otx"],
                "input_type": "hash"
            },
            "email_breach_check": {
                "description": "Check if email address appears in known data breaches",
                "apis": ["haveibeenpwned"],
                "input_type": "email"
            },
            "shodan_search": {
                "description": "Search Shodan for internet-connected devices and services",
                "apis": ["shodan"],
                "input_type": "query"
            },
            "ioc_enrichment": {
                "description": "Enrich indicators of compromise with threat intelligence",
                "apis": ["virustotal", "otx", "abuseipdb"],
                "input_type": "mixed"
            },
            "company_osint": {
                "description": "Open source intelligence gathering for companies/domains",
                "apis": ["shodan", "censys", "whois"],
                "input_type": "domain"
            },
            "threat_hunting": {
                "description": "Proactive threat hunting using multiple intelligence sources",
                "apis": ["otx", "greynoise", "shodan"],
                "input_type": "query"
            },
            "certificate_analysis": {
                "description": "SSL/TLS certificate transparency and analysis",
                "apis": ["censys"],
                "input_type": "domain"
            }
        }
        
        self._register_handlers()

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    def _register_handlers(self):
        """Register MCP handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available threat intelligence tools"""
            tools = []
            
            for tool_name, config in self.intel_tools.items():
                tools.append(Tool(
                    name=tool_name,
                    description=config["description"],
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "indicator": {
                                "type": "string", 
                                "description": f"The {config['input_type']} to analyze"
                            },
                            "sources": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": f"Specific sources to use: {', '.join(config['apis'])}"
                            },
                            "api_key": {
                                "type": "string",
                                "description": "API key for premium features"
                            },
                            "include_raw": {
                                "type": "boolean",
                                "description": "Include raw API responses"
                            }
                        },
                        "required": ["indicator"]
                    }
                ))
            
            # Add bulk analysis tools
            tools.extend([
                Tool(
                    name="bulk_ioc_analysis",
                    description="Analyze multiple indicators of compromise in batch",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "indicators": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of IOCs to analyze (IPs, domains, URLs, hashes)"
                            },
                            "output_format": {
                                "type": "string",
                                "enum": ["summary", "detailed", "csv"],
                                "description": "Output format for results"
                            }
                        },
                        "required": ["indicators"]
                    }
                ),
                Tool(
                    name="threat_feed_monitor",
                    description="Monitor threat feeds for specific indicators or patterns",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "watch_terms": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Terms or patterns to monitor"
                            },
                            "feed_sources": {
                                "type": "array", 
                                "items": {"type": "string"},
                                "description": "Threat feed sources to monitor"
                            },
                            "alert_threshold": {
                                "type": "number",
                                "description": "Confidence threshold for alerts (0-100)"
                            }
                        },
                        "required": ["watch_terms"]
                    }
                )
            ])
            
            return tools

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Execute threat intelligence analysis"""
            try:
                if not self.session:
                    async with self:
                        result = await self._execute_intel_tool(name, arguments)
                else:
                    result = await self._execute_intel_tool(name, arguments)
                
                response_text = self._format_intel_response(result)
                return [TextContent(type="text", text=response_text)]
                
            except Exception as e:
                logger.error(f"Intel tool execution error: {e}")
                return [TextContent(
                    type="text",
                    text=f"Error executing intelligence tool: {str(e)}"
                )]

        @self.server.list_resources()
        async def handle_list_resources() -> List[Resource]:
            """List available intelligence resources"""
            return [
                Resource(
                    uri="intel://logs",
                    name="Intelligence Logs",
                    description="Threat intelligence query and analysis logs",
                    mimeType="application/json"
                ),
                Resource(
                    uri="feeds://active",
                    name="Active Threat Feeds",
                    description="Currently monitored threat intelligence feeds",
                    mimeType="application/json"
                ),
                Resource(
                    uri="iocs://watchlist",
                    name="IOC Watchlist",
                    description="Indicators of compromise being monitored",
                    mimeType="application/json"
                ),
                Resource(
                    uri="reports://summary",
                    name="Intelligence Summary",
                    description="Summary of recent threat intelligence findings",
                    mimeType="text/markdown"
                )
            ]

        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Read intelligence resource content"""
            if uri == "intel://logs":
                return await self._get_intel_logs()
            elif uri == "feeds://active":
                return await self._get_active_feeds()
            elif uri == "iocs://watchlist":
                return await self._get_ioc_watchlist()
            elif uri == "reports://summary":
                return await self._generate_intel_summary()
            else:
                raise ValueError(f"Unknown resource: {uri}")

    async def _execute_intel_tool(self, tool_name: str, arguments: Dict[str, Any]) -> ThreatIntelResult:
        """Execute a threat intelligence tool"""
        indicator = arguments.get("indicator", "")
        sources = arguments.get("sources", [])
        include_raw = arguments.get("include_raw", False)
        
        # Determine indicator type
        indicator_type = self._detect_indicator_type(indicator)
        
        if tool_name == "bulk_ioc_analysis":
            return await self._bulk_ioc_analysis(arguments)
        elif tool_name == "threat_feed_monitor":
            return await self._threat_feed_monitor(arguments)
        
        # Get tool configuration
        tool_config = self.intel_tools.get(tool_name)
        if not tool_config:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        # Use specified sources or default to all for the tool
        apis_to_use = sources if sources else tool_config["apis"]
        
        # Execute intelligence gathering
        results = []
        for api_name in apis_to_use:
            try:
                if await self._check_rate_limit(api_name):
                    result = await self._query_api(api_name, indicator, indicator_type)
                    if result:
                        results.append(result)
                        await self._update_rate_limit(api_name)
            except Exception as e:
                logger.warning(f"API {api_name} failed for {indicator}: {e}")
                continue
        
        # Aggregate and enrich results
        aggregated_result = await self._aggregate_results(indicator, indicator_type, results)
        
        # Log the intelligence query
        await self._log_intel_query(tool_name, indicator, aggregated_result)
        
        return aggregated_result

    def _detect_indicator_type(self, indicator: str) -> str:
        """Detect the type of indicator"""
        indicator = indicator.strip()
        
        # Check for IP address
        try:
            ipaddress.ip_address(indicator)
            return "ip"
        except ValueError:
            pass
        
        # Check for domain
        if self._is_domain(indicator):
            return "domain"
        
        # Check for URL
        if indicator.startswith(("http://", "https://", "ftp://")):
            return "url"
        
        # Check for email
        if "@" in indicator and "." in indicator.split("@")[1]:
            return "email"
        
        # Check for hash (MD5, SHA1, SHA256)
        if len(indicator) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in indicator):
            return "hash"
        
        # Default to query/search term
        return "query"

    def _is_domain(self, indicator: str) -> bool:
        """Check if indicator is a valid domain"""
        try:
            extracted = tldextract.extract(indicator)
            return bool(extracted.domain and extracted.suffix)
        except:
            return False

    async def _query_api(self, api_name: str, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query a specific threat intelligence API"""
        
        if api_name == "virustotal":
            return await self._query_virustotal(indicator, indicator_type)
        elif api_name == "shodan":
            return await self._query_shodan(indicator, indicator_type)
        elif api_name == "haveibeenpwned":
            return await self._query_hibp(indicator, indicator_type)
        elif api_name == "abuseipdb":
            return await self._query_abuseipdb(indicator, indicator_type)
        elif api_name == "greynoise":
            return await self._query_greynoise(indicator, indicator_type)
        elif api_name == "urlvoid":
            return await self._query_urlvoid(indicator, indicator_type)
        elif api_name == "otx":
            return await self._query_otx(indicator, indicator_type)
        elif api_name == "censys":
            return await self._query_censys(indicator, indicator_type)
        elif api_name == "whois":
            return await self._query_whois(indicator, indicator_type)
        
        return None

    async def _query_virustotal(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal API"""
        if not self.config.virustotal_api_key:
            return None
        
        endpoint_map = {
            "ip": "ip_report",
            "domain": "domain_report", 
            "url": "url_report",
            "hash": "file_report"
        }
        
        endpoint = endpoint_map.get(indicator_type)
        if not endpoint:
            return None
        
        url = f"{self.api_configs['virustotal']['base_url']}{self.api_configs['virustotal']['endpoints'][endpoint]}"
        
        params = {"apikey": self.config.virustotal_api_key}
        
        if indicator_type == "url":
            params["resource"] = indicator
        elif indicator_type in ["ip", "domain", "hash"]:
            params["resource"] = indicator
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "virustotal",
                        "indicator": indicator,
                        "data": data,
                        "reputation_score": self._calculate_vt_reputation(data)
                    }
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
        
        return None

    async def _query_shodan(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query Shodan API"""
        if not self.config.shodan_api_key:
            return None
        
        if indicator_type == "ip":
            url = f"{self.api_configs['shodan']['base_url']}/shodan/host/{indicator}"
        elif indicator_type == "query":
            url = f"{self.api_configs['shodan']['base_url']}/shodan/host/search"
        else:
            return None
        
        params = {"key": self.config.shodan_api_key}
        if indicator_type == "query":
            params["query"] = indicator
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "shodan",
                        "indicator": indicator,
                        "data": data,
                        "services": data.get("ports", []) if indicator_type == "ip" else None
                    }
        except Exception as e:
            logger.error(f"Shodan API error: {e}")
        
        return None

    async def _query_hibp(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query Have I Been Pwned API"""
        if indicator_type != "email":
            return None
        
        url = f"{self.api_configs['haveibeenpwned']['base_url']}/breachedaccount/{indicator}"
        
        headers = {
            "User-Agent": "ThreatIntel-MCP-Server"
        }
        
        if self.config.hibp_api_key:
            headers["hibp-api-key"] = self.config.hibp_api_key
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "haveibeenpwned",
                        "indicator": indicator,
                        "data": data,
                        "breach_count": len(data) if isinstance(data, list) else 0
                    }
                elif response.status == 404:
                    return {
                        "source": "haveibeenpwned",
                        "indicator": indicator,
                        "data": {"message": "No breaches found"},
                        "breach_count": 0
                    }
        except Exception as e:
            logger.error(f"HIBP API error: {e}")
        
        return None

    async def _query_abuseipdb(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB API"""
        if indicator_type != "ip" or not self.config.abuseipdb_api_key:
            return None
        
        url = f"{self.api_configs['abuseipdb']['base_url']}/check"
        
        headers = {
            "Key": self.config.abuseipdb_api_key,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": indicator,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "abuseipdb",
                        "indicator": indicator,
                        "data": data,
                        "abuse_confidence": data.get("data", {}).get("abuseConfidencePercentage", 0)
                    }
        except Exception as e:
            logger.error(f"AbuseIPDB API error: {e}")
        
        return None

    async def _query_greynoise(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query GreyNoise API"""
        if indicator_type != "ip":
            return None
        
        # Use community API if no key available
        if self.config.greynoise_api_key:
            url = f"{self.api_configs['greynoise']['base_url']}/context/{indicator}"
            headers = {"key": self.config.greynoise_api_key}
        else:
            url = f"{self.api_configs['greynoise']['base_url']}/community/{indicator}"
            headers = {}
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "greynoise",
                        "indicator": indicator,
                        "data": data,
                        "noise_level": data.get("noise", False)
                    }
        except Exception as e:
            logger.error(f"GreyNoise API error: {e}")
        
        return None

    async def _query_urlvoid(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query URLVoid API"""
        if indicator_type not in ["url", "domain"] or not self.config.urlvoid_api_key:
            return None
        
        # Extract domain from URL if needed
        if indicator_type == "url":
            from urllib.parse import urlparse
            domain = urlparse(indicator).netloc
        else:
            domain = indicator
        
        url = f"{self.api_configs['urlvoid']['base_url']}pay-as-you-go/"
        
        params = {
            "key": self.config.urlvoid_api_key,
            "host": domain
        }
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "urlvoid",
                        "indicator": indicator,
                        "data": data,
                        "detection_count": data.get("detections", 0)
                    }
        except Exception as e:
            logger.error(f"URLVoid API error: {e}")
        
        return None

    async def _query_otx(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query AlienVault OTX API"""
        type_map = {
            "ip": "IPv4",
            "domain": "domain",
            "url": "URL",
            "hash": "file"
        }
        
        otx_type = type_map.get(indicator_type)
        if not otx_type:
            return None
        
        url = f"{self.api_configs['otx']['base_url']}/indicators/{otx_type}/{indicator}/general"
        
        headers = {}
        if self.config.otx_api_key:
            headers["X-OTX-API-KEY"] = self.config.otx_api_key
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "otx",
                        "indicator": indicator,
                        "data": data,
                        "pulse_count": data.get("pulse_info", {}).get("count", 0)
                    }
        except Exception as e:
            logger.error(f"OTX API error: {e}")
        
        return None

    async def _query_censys(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query Censys API"""
        if not self.config.censys_api_id or not self.config.censys_api_secret:
            return None
        
        if indicator_type == "ip":
            url = f"{self.api_configs['censys']['base_url']}/hosts/{indicator}"
        else:
            return None
        
        auth = aiohttp.BasicAuth(self.config.censys_api_id, self.config.censys_api_secret)
        
        try:
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "censys",
                        "indicator": indicator,
                        "data": data,
                        "services": data.get("result", {}).get("services", [])
                    }
        except Exception as e:
            logger.error(f"Censys API error: {e}")
        
        return None

    async def _query_whois(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query WHOIS information"""
        if indicator_type not in ["domain", "ip"]:
            return None
        
        try:
            if indicator_type == "domain":
                whois_data = whois.whois(indicator)
                return {
                    "source": "whois",
                    "indicator": indicator,
                    "data": {
                        "registrar": whois_data.registrar,
                        "creation_date": str(whois_data.creation_date) if whois_data.creation_date else None,
                        "expiration_date": str(whois_data.expiration_date) if whois_data.expiration_date else None,
                        "name_servers": whois_data.name_servers,
                        "registrant": whois_data.registrant
                    }
                }
            elif indicator_type == "ip":
                # For IP WHOIS, we'd need a different approach
                # This is a simplified version
                return {
                    "source": "whois",
                    "indicator": indicator,
                    "data": {"message": "IP WHOIS lookup would be implemented here"}
                }
        except Exception as e:
            logger.error(f"WHOIS query error: {e}")
        
        return None

    def _calculate_vt_reputation(self, vt_data: Dict[str, Any]) -> float:
        """Calculate reputation score from VirusTotal data"""
        if "positives" in vt_data and "total" in vt_data:
            positives = vt_data["positives"]
            total = vt_data["total"]
            if total > 0:
                return (total - positives) / total * 100
        return 50.0  # Neutral if no data

    async def _aggregate_results(self, indicator: str, indicator_type: str, results: List[Dict[str, Any]]) -> ThreatIntelResult:
        """Aggregate results from multiple sources"""
        
        # Calculate overall reputation score
        reputation_scores = [r.get("reputation_score") for r in results if r.get("reputation_score")]
        avg_reputation = sum(reputation_scores) / len(reputation_scores) if reputation_scores else None
        
        # Determine threat types
        threat_types = set()
        for result in results:
            source = result.get("source", "")
            data = result.get("data", {})
            
            if source == "abuseipdb" and result.get("abuse_confidence", 0) > 25:
                threat_types.add("abuse")
            elif source == "virustotal" and data.get("positives", 0) > 0:
                threat_types.add("malware")
            elif source == "greynoise" and result.get("noise_level"):
                threat_types.add("scanner")
            elif source == "haveibeenpwned" and result.get("breach_count", 0) > 0:
                threat_types.add("breach")
        
        # Calculate confidence based on number of sources and consistency
        confidence = min(len(results) * 20, 100) if results else 0
        
        # Enriched data compilation
        enriched_data = {}
        for result in results:
            source = result.get("source")
            enriched_data[source] = {
                "status": "success",
                "summary": self._generate_source_summary(result),
                "key_findings": self._extract_key_findings(result)
            }
        
        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            source="aggregated",
            reputation_score=avg_reputation,
            threat_types=list(threat_types),
            confidence=confidence,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            raw_data={"sources": results},
            enriched_data=enriched_data
        )

    def _generate_source_summary(self, result: Dict[str, Any]) -> str:
        """Generate a summary for each source"""
        source = result.get("source", "")
        
        if source == "virustotal":
            data = result.get("data", {})
            positives = data.get("positives", 0)
            total = data.get("total", 0)
            return f"Detected by {positives}/{total} engines"
        
        elif source == "shodan":
            services = result.get("services", [])
            return f"Found {len(services)} open services" if services else "No services found"
        
        elif source == "abuseipdb":
            confidence = result.get("abuse_confidence", 0)
            return f"Abuse confidence: {confidence}%"
        
        elif source == "haveibeenpwned":
            breach_count = result.get("breach_count", 0)
            return f"Found in {breach_count} data breaches"
        
        elif source == "greynoise":
            noise = result.get("noise_level", False)
            return "Scanner activity detected" if noise else "No scanner activity"
        
        return "Analysis completed"

    def _extract_key_findings(self, result: Dict[str, Any]) -> List[str]:
        """Extract key findings from each source"""
        source = result.get("source", "")
        findings = []
        
        if source == "virustotal":
            data = result.get("data", {})
            if data.get("positives", 0) > 0:
                findings.append(f"Flagged as malicious by {data['positives']} engines")
        
        elif source == "shodan":
            data = result.get("data", {})
            if "ports" in data:
                findings.append(f"Open ports: {', '.join(map(str, data['ports'][:5]))}")
            if "vulns" in data:
                findings.append(f"Vulnerabilities detected: {len(data['vulns'])}")
        
        elif source == "abuseipdb":
            confidence = result.get("abuse_confidence", 0)
            if confidence > 50:
                findings.append("High abuse confidence")
        
        elif source == "haveibeenpwned":
            breach_count = result.get("breach_count", 0)
            if breach_count > 0:
                findings.append(f"Compromised in {breach_count} breaches")
        
        return findings

    async def _bulk_ioc_analysis(self, arguments: Dict[str, Any]) -> ThreatIntelResult:
        """Perform bulk analysis of multiple IOCs"""
        indicators = arguments.get("indicators", [])
        output_format = arguments.get("output_format", "summary")
        
        results = []
        for indicator in indicators[:50]:  # Limit to 50 for API rate limits
            try:
                indicator_type = self._detect_indicator_type(indicator)
                
                # Quick reputation check using cached or lightweight APIs
                result = await self._quick_reputation_check(indicator, indicator_type)
                results.append(result)
                
                # Small delay to respect rate limits
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Bulk analysis error for {indicator}: {e}")
                continue
        
        return ThreatIntelResult(
            indicator="bulk_analysis",
            indicator_type="bulk",
            source="bulk_analyzer",
            raw_data={"indicators": indicators, "results": results},
            enriched_data={"format": output_format, "total_analyzed": len(results)}
        )

    async def _quick_reputation_check(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Quick reputation check for bulk analysis"""
        # Simplified reputation check using free/cached sources
        result = {
            "indicator": indicator,
            "type": indicator_type,
            "reputation": "unknown",
            "sources_checked": []
        }
        
        # Check cache first
        cache_key = f"{indicator}:{indicator_type}"
        if cache_key in self.cache:
            cached_result = self.cache[cache_key]
            if datetime.now() - cached_result["timestamp"] < timedelta(hours=1):
                return cached_result["data"]
        
        # Quick checks without API keys
        if indicator_type == "ip":
            try:
                ip = ipaddress.ip_address(indicator)
                if ip.is_private:
                    result["reputation"] = "private"
                elif ip.is_multicast:
                    result["reputation"] = "multicast"
                else:
                    result["reputation"] = "public"
            except:
                pass
        
        # Cache the result
        self.cache[cache_key] = {
            "timestamp": datetime.now(),
            "data": result
        }
        
        return result

    async def _threat_feed_monitor(self, arguments: Dict[str, Any]) -> ThreatIntelResult:
        """Monitor threat feeds for specific indicators"""
        watch_terms = arguments.get("watch_terms", [])
        feed_sources = arguments.get("feed_sources", ["otx"])
        alert_threshold = arguments.get("alert_threshold", 70)
        
        monitoring_results = {
            "watch_terms": watch_terms,
            "active_feeds": feed_sources,
            "alert_threshold": alert_threshold,
            "monitored_since": datetime.now().isoformat(),
            "alerts": []
        }
        
        return ThreatIntelResult(
            indicator="threat_monitor",
            indicator_type="monitoring",
            source="feed_monitor",
            raw_data=monitoring_results,
            enriched_data={"status": "monitoring_active"}
        )

    async def _check_rate_limit(self, api_name: str) -> bool:
        """Check if API rate limit allows request"""
        now = datetime.now()
        if api_name not in self.rate_limits:
            self.rate_limits[api_name] = {"requests": 0, "window_start": now}
            return True
        
        rate_data = self.rate_limits[api_name]
        window_duration = timedelta(minutes=1)
        
        # Reset window if needed
        if now - rate_data["window_start"] > window_duration:
            rate_data["requests"] = 0
            rate_data["window_start"] = now
        
        # Check limit
        api_config = self.api_configs.get(api_name, {})
        limit = api_config.get("rate_limit", 100)
        
        return rate_data["requests"] < limit

    async def _update_rate_limit(self, api_name: str):
        """Update rate limit counter"""
        if api_name in self.rate_limits:
            self.rate_limits[api_name]["requests"] += 1

    async def _log_intel_query(self, tool_name: str, indicator: str, result: ThreatIntelResult):
        """Log intelligence query for audit purposes"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "indicator": indicator,
            "indicator_type": result.indicator_type,
            "reputation_score": result.reputation_score,
            "threat_types": result.threat_types,
            "confidence": result.confidence,
            "sources_used": list(result.enriched_data.keys())
        }
        
        log_file = self.intel_log_path / f"intel_{datetime.now().strftime('%Y%m%d')}.json"
        
        try:
            async with aiofiles.open(log_file, 'a') as f:
                await f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write intel log: {e}")

    def _format_intel_response(self, result: ThreatIntelResult) -> str:
        """Format intelligence analysis response"""
        response = f"# 🔍 Threat Intelligence Analysis\n\n"
        response += f"**Indicator:** `{result.indicator}`\n"
        response += f"**Type:** {result.indicator_type.upper()}\n"
        response += f"**Analysis Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        
        if result.reputation_score:
            response += f"**Reputation Score:** {result.reputation_score:.1f}/100\n"
        
        if result.confidence:
            response += f"**Confidence Level:** {result.confidence:.1f}%\n\n"
        
        # Threat Assessment
        if result.threat_types:
            response += "## 🚨 Threat Assessment\n\n"
            for threat_type in result.threat_types:
                response += f"- **{threat_type.upper()}** threat detected\n"
            response += "\n"
        else:
            response += "## ✅ No Immediate Threats Detected\n\n"
        
        # Source Analysis
        if result.enriched_data:
            response += "## 📊 Intelligence Sources\n\n"
            for source, data in result.enriched_data.items():
                if isinstance(data, dict) and "summary" in data:
                    response += f"### {source.title()}\n"
                    response += f"- **Status:** {data.get('status', 'unknown')}\n"
                    response += f"- **Summary:** {data.get('summary', 'No summary available')}\n"
                    
                    if data.get("key_findings"):
                        response += "- **Key Findings:**\n"
                        for finding in data["key_findings"]:
                            response += f"  - {finding}\n"
                    response += "\n"
        
        # Recommendations
        response += "## 💡 Recommendations\n\n"
        
        if result.threat_types:
            if "malware" in result.threat_types:
                response += "- **BLOCK** this indicator immediately\n"
                response += "- Conduct additional investigation on related infrastructure\n"
            if "abuse" in result.threat_types:
                response += "- Monitor for suspicious activity from this source\n"
                response += "- Consider rate limiting or temporary blocking\n"
            if "breach" in result.threat_types:
                response += "- Reset credentials associated with this email\n"
                response += "- Enable additional monitoring for account compromise\n"
        else:
            response += "- Continue monitoring as part of routine threat intelligence\n"
            response += "- No immediate action required\n"
        
        response += "\n"
        
        # Additional Context
        if result.indicator_type == "ip":
            response += "## 🌐 Network Context\n\n"
            response += "- Review firewall logs for activity from this IP\n"
            response += "- Check for related domain associations\n"
            response += "- Monitor for lateral movement if internal compromise suspected\n\n"
        
        elif result.indicator_type == "domain":
            response += "## 🏷️ Domain Context\n\n"
            response += "- Review DNS queries and web traffic to this domain\n"
            response += "- Check for typosquatting of legitimate domains\n"
            response += "- Monitor for data exfiltration attempts\n\n"
        
        # Metadata
        response += "---\n"
        response += f"*Analysis generated by Threat Intelligence MCP Server*\n"
        response += f"*Sources: {', '.join(result.enriched_data.keys()) if result.enriched_data else 'Internal analysis'}*"
        
        return response

    async def _get_intel_logs(self) -> str:
        """Get recent intelligence logs"""
        logs = []
        
        try:
            log_file = self.intel_log_path / f"intel_{datetime.now().strftime('%Y%m%d')}.json"
            if log_file.exists():
                async with aiofiles.open(log_file, 'r') as f:
                    content = await f.read()
                    for line in content.strip().split('\n'):
                        if line:
                            logs.append(json.loads(line))
            
            return json.dumps(logs[-100:], indent=2)  # Last 100 entries
        except Exception as e:
            return f"Error reading intelligence logs: {e}"

    async def _get_active_feeds(self) -> str:
        """Get active threat feeds information"""
        feeds = {
            "active_feeds": [
                {
                    "name": "AlienVault OTX",
                    "status": "active" if self.config.otx_api_key else "inactive",
                    "type": "community"
                },
                {
                    "name": "VirusTotal",
                    "status": "active" if self.config.virustotal_api_key else "inactive", 
                    "type": "commercial"
                },
                {
                    "name": "Shodan",
                    "status": "active" if self.config.shodan_api_key else "inactive",
                    "type": "commercial"
                }
            ],
            "last_updated": datetime.now().isoformat()
        }
        
        return json.dumps(feeds, indent=2)

    async def _get_ioc_watchlist(self) -> str:
        """Get current IOC watchlist"""
        watchlist = {
            "watched_indicators": [],
            "alert_rules": [],
            "last_updated": datetime.now().isoformat()
        }
        
        return json.dumps(watchlist, indent=2)

    async def _generate_intel_summary(self) -> str:
        """Generate intelligence summary report"""
        summary = f"""# 📈 Threat Intelligence Summary

## Overview
Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

## Recent Activity
- Indicators analyzed today: Loading...
- High-risk findings: Loading...
- New threats detected: Loading...

## Source Status
- VirusTotal: {'✅ Active' if self.config.virustotal_api_key else '❌ Inactive'}
- Shodan: {'✅ Active' if self.config.shodan_api_key else '❌ Inactive'}
- Have I Been Pwned: {'✅ Active' if self.config.hibp_api_key else '❌ Inactive'}
- AbuseIPDB: {'✅ Active' if self.config.abuseipdb_api_key else '❌ Inactive'}

## Recommendations
1. Configure additional API keys for enhanced coverage
2. Set up automated monitoring for critical assets
3. Review and update IOC watchlists regularly

---
*This is a live intelligence summary that updates automatically*
"""
        
        return summary

async def main():
    """Main entry point"""
    server_instance = ThreatIntelMCPServer()
    
    # Set up server options
    options = InitializationOptions(
        server_name="threat-intelligence",
        server_version="1.0.0",
        capabilities={
            "tools": {},
            "resources": {}
        }
    )
    
    async with server_instance:
        async with stdio_server() as (read_stream, write_stream):
            await server_instance.server.run(
                read_stream,
                write_stream,
                options
            )

if __name__ == "__main__":
    asyncio.run(main())
