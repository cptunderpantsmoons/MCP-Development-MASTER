import unittest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from threat_intel_mcp_server.main import ThreatIntelMCPServer, ThreatIntelResult

class TestThreatIntelMCPServer(unittest.TestCase):
    """Test cases for the Threat Intelligence MCP Server"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.server = ThreatIntelMCPServer()
    
    def test_server_initialization(self):
        """Test server initializes correctly"""
        self.assertIsNotNone(self.server)
        self.assertEqual(self.server.server.name, "threat-intelligence")
        self.assertIn("ip_reputation", self.server.intel_tools)
        self.assertIn("domain_reputation", self.server.intel_tools)
    
    def test_indicator_type_detection(self):
        """Test indicator type detection"""
        # Test IP detection
        self.assertEqual(self.server._detect_indicator_type("192.168.1.1"), "ip")
        self.assertEqual(self.server._detect_indicator_type("8.8.8.8"), "ip")
        
        # Test domain detection
        self.assertEqual(self.server._detect_indicator_type("example.com"), "domain")
        self.assertEqual(self.server._detect_indicator_type("malicious-site.org"), "domain")
        
        # Test URL detection
        self.assertEqual(self.server._detect_indicator_type("https://example.com"), "url")
        self.assertEqual(self.server._detect_indicator_type("http://test.com/path"), "url")
        
        # Test email detection
        self.assertEqual(self.server._detect_indicator_type("user@example.com"), "email")
        
        # Test hash detection
        self.assertEqual(self.server._detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e"), "hash")  # MD5
        self.assertEqual(self.server._detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), "hash")  # SHA1
        
        # Test query detection
        self.assertEqual(self.server._detect_indicator_type("apache server"), "query")
    
    def test_domain_validation(self):
        """Test domain validation"""
        self.assertTrue(self.server._is_domain("example.com"))
        self.assertTrue(self.server._is_domain("sub.example.com"))
        self.assertFalse(self.server._is_domain("not-a-domain"))
        self.assertFalse(self.server._is_domain("192.168.1.1"))
    
    def test_reputation_calculation(self):
        """Test VirusTotal reputation calculation"""
        # Test clean file
        vt_data_clean = {"positives": 0, "total": 60}
        score = self.server._calculate_vt_reputation(vt_data_clean)
        self.assertEqual(score, 100.0)
        
        # Test malicious file
        vt_data_malicious = {"positives": 45, "total": 60}
        score = self.server._calculate_vt_reputation(vt_data_malicious)
        self.assertEqual(score, 25.0)
        
        # Test no data
        vt_data_empty = {}
        score = self.server._calculate_vt_reputation(vt_data_empty)
        self.assertEqual(score, 50.0)
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        async def test_rate_limit_check():
            # First request should be allowed
            allowed = await self.server._check_rate_limit("test_api")
            self.assertTrue(allowed)
            
            # Update rate limit
            await self.server._update_rate_limit("test_api")
            
            # Check that rate limit was updated
            self.assertIn("test_api", self.server.rate_limits)
            self.assertEqual(self.server.rate_limits["test_api"]["requests"], 1)
        
        asyncio.run(test_rate_limit_check())
    
    @patch('aiohttp.ClientSession.get')
    def test_virustotal_query(self, mock_get):
        """Test VirusTotal API query"""
        async def test_vt_query():
            # Mock VirusTotal response
            mock_response = Mock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "positives": 0,
                "total": 60,
                "scan_date": "2024-06-09 10:30:00"
            })
            
            mock_get.return_value.__aenter__.return_value = mock_response
            
            # Set API key for testing
            self.server.config.virustotal_api_key = "test_key"
            
            # Create session for testing
            async with self.server:
                result = await self.server._query_virustotal("8.8.8.8", "ip")
                
                self.assertIsNotNone(result)
                self.assertEqual(result["source"], "virustotal")
                self.assertEqual(result["indicator"], "8.8.8.8")
                self.assertIn("reputation_score", result)
        
        asyncio.run(test_vt_query())
    
    def test_source_summary_generation(self):
        """Test source summary generation"""
        # Test VirusTotal summary
        vt_result = {
            "source": "virustotal",
            "data": {"positives": 2, "total": 60}
        }
        summary = self.server._generate_source_summary(vt_result)
        self.assertEqual(summary, "Detected by 2/60 engines")
        
        # Test AbuseIPDB summary
        abuse_result = {
            "source": "abuseipdb",
            "abuse_confidence": 75
        }
        summary = self.server._generate_source_summary(abuse_result)
        self.assertEqual(summary, "Abuse confidence: 75%")
        
        # Test HIBP summary
        hibp_result = {
            "source": "haveibeenpwned",
            "breach_count": 3
        }
        summary = self.server._generate_source_summary(hibp_result)
        self.assertEqual(summary, "Found in 3 data breaches")
    
    def test_threat_type_detection(self):
        """Test threat type detection in aggregation"""
        async def test_threat_detection():
            # Mock results indicating different threat types
            results = [
                {
                    "source": "abuseipdb",
                    "abuse_confidence": 80,
                    "data": {}
                },
                {
                    "source": "virustotal", 
                    "data": {"positives": 5, "total": 60},
                    "reputation_score": 75
                },
                {
                    "source": "haveibeenpwned",
                    "breach_count": 2,
                    "data": [{"Name": "Breach1"}, {"Name": "Breach2"}]
                }
            ]
            
            aggregated = await self.server._aggregate_results("test@example.com", "email", results)
            
            self.assertIn("abuse", aggregated.threat_types)
            self.assertIn("malware", aggregated.threat_types)
            self.assertIn("breach", aggregated.threat_types)
            self.assertGreater(aggregated.confidence, 0)
        
        asyncio.run(test_threat_detection())
    
    def test_bulk_analysis_structure(self):
        """Test bulk analysis result structure"""
        async def test_bulk_structure():
            arguments = {
                "indicators": ["8.8.8.8", "example.com", "user@test.com"],
                "output_format": "summary"
            }
            
            result = await self.server._bulk_ioc_analysis(arguments)
            
            self.assertEqual(result.indicator, "bulk_analysis")
            self.assertEqual(result.indicator_type, "bulk")
            self.assertEqual(result.source, "bulk_analyzer")
            self.assertIn("indicators", result.raw_data)
            self.assertIn("results", result.raw_data)
            self.assertEqual(result.enriched_data["format"], "summary")
        
        asyncio.run(test_bulk_structure())
    
    def test_response_formatting(self):
        """Test response formatting"""
        # Create a test result
        test_result = ThreatIntelResult(
            indicator="8.8.8.8",
            indicator_type="ip",
            source="test",
            reputation_score=85.5,
            threat_types=["scanner"],
            confidence=75.0,
            enriched_data={
                "virustotal": {
                    "status": "success",
                    "summary": "Clean reputation",
                    "key_findings": ["No malicious detections"]
                }
            }
        )
        
        formatted_response = self.server._format_intel_response(test_result)
        
        # Check that key elements are present in formatted response
        self.assertIn("Threat Intelligence Analysis", formatted_response)
        self.assertIn("8.8.8.8", formatted_response)
        self.assertIn("IP", formatted_response)
        self.assertIn("85.5", formatted_response)
        self.assertIn("75.0", formatted_response)
        self.assertIn("SCANNER", formatted_response)
        self.assertIn("VirusTotal", formatted_response)
        self.assertIn("Recommendations", formatted_response)
    
    def test_config_initialization(self):
        """Test configuration initialization"""
        config = self.server.config
        
        self.assertIsNotNone(config)
        self.assertEqual(config.max_requests_per_minute, 100)
        self.assertEqual(config.cache_ttl_minutes, 60)
        self.assertTrue(config.enable_caching)
        self.assertIsNone(config.virustotal_api_key)  # Should be None initially

if __name__ == '__main__':
    unittest.main()
