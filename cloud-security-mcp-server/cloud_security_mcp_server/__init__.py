"""
Cloud Security MCP Server
A comprehensive Model Context Protocol server for cloud security analysis,
Infrastructure as Code scanning, and multi-cloud security assessments.
"""

__version__ = "1.0.0"
__author__ = "Cloud Security Team"
__email__ = "security@example.com"
__description__ = "Cloud Security MCP Server for comprehensive cloud infrastructure security analysis"

from .main import CloudSecurityMCPServer
from .config import CloudSecurityMCPConfig, load_config
from .tools import SecurityToolManager
from .cloud_providers import MultiCloudSecurityManager

__all__ = [
    "CloudSecurityMCPServer",
    "CloudSecurityMCPConfig", 
    "load_config",
    "SecurityToolManager",
    "MultiCloudSecurityManager"
]
