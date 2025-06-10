import unittest
import asyncio
from unittest.mock import Mock, patch
from cybersec_mcp_server.main import CybersecMCPServer

class TestCybersecMCPServer(unittest.TestCase):
    """Test cases for the Cybersec MCP Server"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.server = CybersecMCPServer()
    
    def test_server_initialization(self):
        """Test server initializes correctly"""
        self.assertIsNotNone(self.server)
        self.assertEqual(self.server.server.name, "cybersec-tools")
        self.assertIn("nmap", self.server.tools_config)
        self.assertIn("nikto", self.server.tools_config)
    
    def test_tool_configuration(self):
        """Test tool configurations are valid"""
        for tool_name, config in self.server.tools_config.items():
            self.assertIn("description", config)
            self.assertIn("container_image", config)
            self.assertIn("presets", config)
            self.assertIsInstance(config["presets"], dict)
    
    @patch('docker.from_env')
    def test_docker_integration(self, mock_docker):
        """Test Docker client integration"""
        mock_client = Mock()
        mock_docker.return_value = mock_client
        
        server = CybersecMCPServer()
        self.assertIsNotNone(server.docker_client)
    
    def test_security_validation(self):
        """Test security validation functions"""
        # Test target validation
        async def test_validate_target():
            # Should not raise for valid targets
            await self.server._validate_target("example.com")
            await self.server._validate_target("192.168.1.1")
            
            # Should raise for empty target
            with self.assertRaises(ValueError):
                await self.server._validate_target("")
        
        asyncio.run(test_validate_target())
    
    def test_url_validation(self):
        """Test URL validation"""
        async def test_validate_url():
            # Valid URLs
            await self.server._validate_url("http://example.com")
            await self.server._validate_url("https://example.com")
            
            # Invalid URLs
            with self.assertRaises(ValueError):
                await self.server._validate_url("example.com")
            
            with self.assertRaises(ValueError):
                await self.server._validate_url("ftp://example.com")
        
        asyncio.run(test_validate_url())
    
    def test_nmap_output_parsing(self):
        """Test nmap output parsing"""
        sample_output = """
        Starting Nmap 7.91 ( https://nmap.org ) at 2024-06-09 10:30 UTC
        Nmap scan report for example.com (93.184.216.34)
        Host is up (0.086s latency).
        PORT     STATE SERVICE
        80/tcp   open  http
        443/tcp  open  https
        """
        
        result = self.server._parse_nmap_output(sample_output)
        self.assertIn("hosts", result)
        self.assertIn("open_ports", result)
        self.assertEqual(len(result["open_ports"]), 2)
    
    def test_nikto_output_parsing(self):
        """Test nikto output parsing"""
        sample_output = """
        - Nikto v2.1.6
        + Target IP:          93.184.216.34
        + Target Hostname:    example.com
        + Target Port:        80
        + OSVDB-3268: /admin/: Directory indexing found.
        + OSVDB-3092: /backup/: This might be interesting...
        """
        
        result = self.server._parse_nikto_output(sample_output)
        self.assertIn("vulnerabilities", result)
        self.assertIn("target_info", result)
        self.assertEqual(len(result["vulnerabilities"]), 2)

if __name__ == '__main__':
    unittest.main()
