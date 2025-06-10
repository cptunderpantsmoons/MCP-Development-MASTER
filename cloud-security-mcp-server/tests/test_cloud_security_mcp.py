#!/usr/bin/env python3
"""
Test suite for Cloud Security MCP Server
"""

import pytest
import asyncio
import json
import tempfile
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from cloud_security_mcp_server.main import CloudSecurityMCPServer
from cloud_security_mcp_server.config import CloudSecurityMCPConfig
from cloud_security_mcp_server.tools import SecurityToolManager, ProwlerIntegration
from cloud_security_mcp_server.cloud_providers import AWSSecurityIntegration

@pytest.fixture
def sample_config():
    """Sample configuration for testing"""
    return {
        "aws_access_key_id": "test_access_key",
        "aws_secret_access_key": "test_secret_key",
        "aws_region": "us-east-1",
        "azure_subscription_id": "test_subscription",
        "gcp_project_id": "test_project"
    }

@pytest.fixture
def security_server():
    """Cloud Security MCP Server instance for testing"""
    return CloudSecurityMCPServer()

@pytest.fixture
def tool_manager(sample_config):
    """Security Tool Manager instance for testing"""
    return SecurityToolManager(sample_config)

class TestCloudSecurityMCPServer:
    """Test cases for the main MCP server"""
    
    def test_server_initialization(self, security_server):
        """Test server initializes correctly"""
        assert security_server.server is not None
        assert security_server.config is not None
        assert security_server.security_tools is not None
        assert isinstance(security_server.security_tools, dict)
    
    def test_security_tools_registration(self, security_server):
        """Test that security tools are properly registered"""
        expected_tools = [
            "aws_security_assessment",
            "azure_security_assessment", 
            "gcp_security_assessment",
            "iac_security_scan",
            "container_vulnerability_scan",
            "kubernetes_security_scan"
        ]
        
        for tool in expected_tools:
            assert tool in security_server.security_tools
    
    @pytest.mark.asyncio
    async def test_list_tools(self, security_server):
        """Test listing available tools"""
        tools = await security_server._list_tools()
        assert len(tools) > 0
        
        # Check that each tool has required properties
        for tool in tools:
            assert hasattr(tool, 'name')
            assert hasattr(tool, 'description')
            assert hasattr(tool, 'inputSchema')

class TestConfiguration:
    """Test cases for configuration management"""
    
    def test_config_initialization(self):
        """Test configuration initialization"""
        config = CloudSecurityMCPConfig()
        assert config.server_name == "cloud-security-mcp"
        assert config.server_version == "1.0.0"
        assert config.aws.region == "us-east-1"
    
    def test_config_from_dict(self, sample_config):
        """Test creating configuration from dictionary"""
        config = CloudSecurityMCPConfig(**{"aws": sample_config})
        assert config.aws.access_key_id == "test_access_key"
        assert config.aws.region == "us-east-1"
    
    def test_config_validation(self, sample_config):
        """Test configuration validation"""
        config = CloudSecurityMCPConfig()
        config.aws.access_key_id = sample_config["aws_access_key_id"]
        config.aws.secret_access_key = sample_config["aws_secret_access_key"]
        
        validation = config.validate_cloud_credentials()
        assert validation["aws"] is True
    
    def test_enabled_providers(self, sample_config):
        """Test getting enabled cloud providers"""
        config = CloudSecurityMCPConfig()
        config.aws.access_key_id = sample_config["aws_access_key_id"]
        config.aws.secret_access_key = sample_config["aws_secret_access_key"]
        
        enabled = config.get_enabled_cloud_providers()
        assert "aws" in enabled
    
    def test_config_file_operations(self, sample_config):
        """Test saving and loading configuration files"""
        config = CloudSecurityMCPConfig(**{"aws": sample_config})
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config.save_to_file(f.name)
            
            # Load config back
            loaded_config = CloudSecurityMCPConfig.from_file(f.name)
            assert loaded_config.aws.access_key_id == sample_config["aws_access_key_id"]
            
            # Cleanup
            Path(f.name).unlink()

class TestSecurityTools:
    """Test cases for security tool integrations"""
    
    def test_tool_manager_initialization(self, tool_manager):
        """Test security tool manager initialization"""
        assert tool_manager.config is not None
        assert "prowler" in tool_manager.tools
        assert "checkov" in tool_manager.tools
        assert "trivy" in tool_manager.tools
    
    def test_available_tools(self, tool_manager):
        """Test getting available tools"""
        tools = tool_manager.get_available_tools()
        expected_tools = ["prowler", "checkov", "trivy", "kube_hunter"]
        
        for tool in expected_tools:
            assert tool in tools
    
    @pytest.mark.asyncio
    @patch('subprocess.run')
    async def test_prowler_integration(self, mock_subprocess, sample_config):
        """Test Prowler integration"""
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = '{"Check_ID": "test", "Status": "PASS"}'
        
        prowler = ProwlerIntegration(sample_config)
        result = await prowler.run_scan("test-account")
        
        assert result["tool"] == "prowler"
        assert "findings" in result
        assert "summary" in result
    
    @pytest.mark.asyncio
    async def test_comprehensive_scan(self, tool_manager):
        """Test comprehensive security scan"""
        targets = {
            "aws": "test-account",
            "iac_path": "/test/path"
        }
        
        with patch.object(tool_manager, 'run_tool', return_value={"status": "completed", "findings": []}):
            result = await tool_manager.run_comprehensive_scan(targets)
            
            assert "comprehensive_scan" in result
            assert result["comprehensive_scan"] is True
            assert "results" in result
            assert "summary" in result

class TestCloudProviders:
    """Test cases for cloud provider integrations"""
    
    def test_aws_integration_initialization(self, sample_config):
        """Test AWS security integration initialization"""
        aws_integration = AWSSecurityIntegration(sample_config)
        assert aws_integration.config == sample_config
        assert aws_integration.session is not None
    
    @pytest.mark.asyncio
    @patch('boto3.Session')
    async def test_aws_security_hub_findings(self, mock_session, sample_config):
        """Test getting AWS Security Hub findings"""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.get_paginator.return_value.paginate.return_value = [
            {
                "Findings": [
                    {
                        "Id": "test-finding-1",
                        "Title": "Test Finding",
                        "Severity": {"Label": "HIGH"},
                        "Resources": [{"Id": "test-resource"}]
                    }
                ]
            }
        ]
        
        aws_integration = AWSSecurityIntegration(sample_config)
        findings = await aws_integration.get_security_hub_findings()
        
        assert len(findings) == 1
        assert findings[0]["id"] == "test-finding-1"
        assert findings[0]["severity"] == "high"
    
    @pytest.mark.asyncio
    @patch('boto3.Session')
    async def test_aws_iam_analysis(self, mock_session, sample_config):
        """Test AWS IAM security analysis"""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock IAM responses
        mock_client.list_users.return_value = {
            "Users": [
                {
                    "UserName": "test-user",
                    "CreateDate": "2023-01-01T00:00:00Z"
                }
            ]
        }
        mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
        mock_client.list_mfa_devices.return_value = {"MFADevices": []}
        mock_client.list_roles.return_value = {"Roles": []}
        
        aws_integration = AWSSecurityIntegration(sample_config)
        analysis = await aws_integration.analyze_iam_security()
        
        assert "users" in analysis
        assert "roles" in analysis
        assert "security_issues" in analysis
        assert len(analysis["users"]) == 1

class TestScanResults:
    """Test cases for scan result processing"""
    
    def test_risk_score_calculation(self, security_server):
        """Test risk score calculation"""
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"}
        ]
        
        risk_score = security_server._calculate_risk_score(findings)
        assert 0 <= risk_score <= 100
        assert risk_score > 0  # Should have some risk with these findings
    
    def test_compliance_status_calculation(self, security_server):
        """Test compliance status calculation"""
        findings = [
            {"status": "PASS"},
            {"status": "PASS"},
            {"status": "FAIL"}
        ]
        
        compliance = security_server._calculate_compliance_status(findings, "cis")
        assert compliance["framework"] == "cis"
        assert compliance["total_checks"] == 3
        assert compliance["passed_checks"] == 2
        assert compliance["failed_checks"] == 1
        assert compliance["compliance_percentage"] == 66.67
    
    def test_recommendations_generation(self, security_server):
        """Test security recommendations generation"""
        findings = [
            {"severity": "critical", "service": "s3"},
            {"severity": "high", "service": "iam"}
        ]
        
        recommendations = security_server._generate_recommendations(findings, "aws")
        assert len(recommendations) > 0
        assert any("critical" in rec.lower() for rec in recommendations)

class TestCompliance:
    """Test cases for compliance framework support"""
    
    def test_compliance_frameworks(self, security_server):
        """Test compliance framework definitions"""
        frameworks = security_server.compliance_frameworks
        
        expected_frameworks = ["cis", "nist_csf", "soc2", "pci_dss", "gdpr", "hipaa"]
        for framework in expected_frameworks:
            assert framework in frameworks
            assert "name" in frameworks[framework]
            assert "description" in frameworks[framework]
    
    def test_cis_benchmark_mapping(self, security_server):
        """Test CIS benchmark mappings"""
        cis_framework = security_server.compliance_frameworks["cis"]
        
        assert "aws_benchmarks" in cis_framework
        assert "azure_benchmarks" in cis_framework
        assert "gcp_benchmarks" in cis_framework
        assert "kubernetes_benchmarks" in cis_framework

class TestErrorHandling:
    """Test cases for error handling"""
    
    @pytest.mark.asyncio
    async def test_invalid_tool_execution(self, security_server):
        """Test handling of invalid tool execution"""
        with pytest.raises(ValueError):
            await security_server._execute_security_tool("invalid_tool", {})
    
    @pytest.mark.asyncio
    async def test_missing_credentials(self, tool_manager):
        """Test handling of missing cloud credentials"""
        # Remove credentials
        tool_manager.config = {}
        
        with pytest.raises(RuntimeError):
            await tool_manager.run_tool("prowler", "test-target")
    
    def test_invalid_configuration(self):
        """Test handling of invalid configuration"""
        with pytest.raises(ValueError):
            CloudSecurityMCPConfig(
                security_policy={"alert_severity_threshold": "invalid"}
            )

class TestIntegrationScenarios:
    """Integration test scenarios"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_aws_scan(self, security_server, sample_config):
        """Test end-to-end AWS security scan"""
        # Mock the scan execution
        with patch.object(security_server, '_run_prowler_scan') as mock_scan:
            mock_scan.return_value = {
                "scan_type": "aws_security_assessment",
                "cloud_provider": "aws",
                "findings": [
                    {
                        "check_id": "CKV_AWS_1",
                        "severity": "high",
                        "status": "FAIL",
                        "resource": "test-bucket"
                    }
                ],
                "compliance_status": {
                    "compliance_percentage": 80,
                    "status": "compliant"
                },
                "risk_score": 25.0
            }
            
            result = await security_server._execute_security_tool(
                "aws_security_assessment",
                {"target": "test-account"}
            )
            
            assert result.scan_type == "aws_security_assessment"
            assert result.cloud_provider == "aws"
            assert len(result.findings) == 1
            assert result.risk_score == 25.0
    
    @pytest.mark.asyncio
    async def test_multi_cloud_assessment(self, security_server):
        """Test multi-cloud security assessment"""
        with patch.object(security_server, '_analyze_attack_surface') as mock_analyze:
            mock_analyze.return_value = {
                "scan_type": "attack_surface_analysis",
                "cloud_provider": "multi",
                "findings": [],
                "risk_score": 0
            }
            
            result = await security_server._execute_security_tool(
                "cloud_attack_surface_analysis",
                {
                    "cloud_provider": "all",
                    "scan_scope": "public_resources"
                }
            )
            
            assert result.scan_type == "attack_surface_analysis"
            assert result.cloud_provider == "multi"

# Performance and load testing
class TestPerformance:
    """Performance test cases"""
    
    @pytest.mark.asyncio
    async def test_concurrent_scans(self, tool_manager):
        """Test concurrent scan execution"""
        targets = ["target1", "target2", "target3"]
        
        with patch.object(tool_manager, 'run_tool', return_value={"status": "completed"}):
            # Run multiple scans concurrently
            tasks = [
                tool_manager.run_tool("prowler", target)
                for target in targets
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All scans should complete successfully
            assert len(results) == len(targets)
            assert all(isinstance(result, dict) for result in results)
    
    def test_large_findings_processing(self, security_server):
        """Test processing large number of findings"""
        # Generate large number of findings
        findings = [
            {
                "severity": "medium",
                "status": "FAIL",
                "check_id": f"TEST_{i}"
            }
            for i in range(1000)
        ]
        
        # Should handle large datasets efficiently
        risk_score = security_server._calculate_risk_score(findings)
        assert isinstance(risk_score, float)
        assert 0 <= risk_score <= 100

# Utility functions for testing
def create_mock_finding(severity="medium", status="FAIL"):
    """Create a mock security finding"""
    return {
        "check_id": "TEST_CHECK",
        "title": "Test Security Finding",
        "severity": severity,
        "status": status,
        "resource": "test-resource",
        "description": "Test description"
    }

def create_mock_scan_result(findings_count=5):
    """Create a mock scan result"""
    findings = [create_mock_finding() for _ in range(findings_count)]
    return {
        "tool": "test_tool",
        "status": "completed",
        "findings": findings,
        "summary": {
            "total_findings": findings_count,
            "by_severity": {"medium": findings_count}
        }
    }

# Test fixtures for integration testing
@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials for testing"""
    return {
        "AWS_ACCESS_KEY_ID": "test_key",
        "AWS_SECRET_ACCESS_KEY": "test_secret",
        "AWS_DEFAULT_REGION": "us-east-1"
    }

@pytest.fixture
def mock_docker_client():
    """Mock Docker client for testing"""
    with patch('docker.from_env') as mock_docker:
        mock_client = Mock()
        mock_docker.return_value = mock_client
        yield mock_client

# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )

if __name__ == "__main__":
    pytest.main([__file__])
