#!/usr/bin/env python3
"""
Cloud Security Configuration Manager
Handles configuration loading and validation for the Cloud Security MCP Server
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv
import yaml

# Load environment variables
load_dotenv()

class AWSConfig(BaseModel):
    """AWS-specific configuration"""
    access_key_id: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_ACCESS_KEY_ID"))
    secret_access_key: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_SECRET_ACCESS_KEY"))
    session_token: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_SESSION_TOKEN"))
    region: str = Field(default_factory=lambda: os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    profile: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_PROFILE"))
    
    class Config:
        env_prefix = "AWS_"

class AzureConfig(BaseModel):
    """Azure-specific configuration"""
    subscription_id: Optional[str] = Field(default_factory=lambda: os.getenv("AZURE_SUBSCRIPTION_ID"))
    tenant_id: Optional[str] = Field(default_factory=lambda: os.getenv("AZURE_TENANT_ID"))
    client_id: Optional[str] = Field(default_factory=lambda: os.getenv("AZURE_CLIENT_ID"))
    client_secret: Optional[str] = Field(default_factory=lambda: os.getenv("AZURE_CLIENT_SECRET"))
    
    class Config:
        env_prefix = "AZURE_"

class GCPConfig(BaseModel):
    """GCP-specific configuration"""
    project_id: Optional[str] = Field(default_factory=lambda: os.getenv("GCP_PROJECT_ID"))
    credentials_file: Optional[str] = Field(default_factory=lambda: os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))
    service_account_key: Optional[str] = Field(default_factory=lambda: os.getenv("GCP_SERVICE_ACCOUNT_KEY"))
    
    class Config:
        env_prefix = "GCP_"

class KubernetesConfig(BaseModel):
    """Kubernetes-specific configuration"""
    kubeconfig_path: str = Field(default_factory=lambda: os.getenv("KUBECONFIG_PATH", "~/.kube/config"))
    namespace: str = Field(default_factory=lambda: os.getenv("KUBERNETES_NAMESPACE", "default"))
    
    class Config:
        env_prefix = "KUBERNETES_"

class SecurityToolConfig(BaseModel):
    """Security tool configuration"""
    enable_container_scanning: bool = Field(default_factory=lambda: os.getenv("ENABLE_CONTAINER_SCANNING", "true").lower() == "true")
    enable_iac_scanning: bool = Field(default_factory=lambda: os.getenv("ENABLE_IAC_SCANNING", "true").lower() == "true")
    enable_compliance_checks: bool = Field(default_factory=lambda: os.getenv("ENABLE_COMPLIANCE_CHECKS", "true").lower() == "true")
    max_scan_time_minutes: int = Field(default_factory=lambda: int(os.getenv("MAX_SCAN_TIME_MINUTES", "30")))
    max_concurrent_scans: int = Field(default_factory=lambda: int(os.getenv("MAX_CONCURRENT_SCANS", "5")))
    scan_timeout_seconds: int = Field(default_factory=lambda: int(os.getenv("SCAN_TIMEOUT_SECONDS", "1800")))
    result_retention_days: int = Field(default_factory=lambda: int(os.getenv("RESULT_RETENTION_DAYS", "90")))

class ComplianceConfig(BaseModel):
    """Compliance framework configuration"""
    frameworks: List[str] = Field(default_factory=lambda: os.getenv("COMPLIANCE_FRAMEWORKS", "cis,nist,soc2").split(","))
    
    @validator('frameworks')
    def validate_frameworks(cls, v):
        supported_frameworks = ["cis", "nist", "soc2", "pci_dss", "gdpr", "hipaa", "iso27001", "fedramp"]
        invalid_frameworks = [f for f in v if f.strip() not in supported_frameworks]
        if invalid_frameworks:
            raise ValueError(f"Unsupported compliance frameworks: {invalid_frameworks}")
        return [f.strip() for f in v]

class SecurityPolicyConfig(BaseModel):
    """Security policy configuration"""
    allowed_regions: List[str] = Field(default_factory=lambda: os.getenv("ALLOWED_REGIONS", "").split(",") if os.getenv("ALLOWED_REGIONS") else [])
    excluded_resources: List[str] = Field(default_factory=lambda: os.getenv("EXCLUDED_RESOURCES", "").split(",") if os.getenv("EXCLUDED_RESOURCES") else [])
    alert_severity_threshold: str = Field(default_factory=lambda: os.getenv("ALERT_SEVERITY_THRESHOLD", "high"))
    
    @validator('alert_severity_threshold')
    def validate_severity(cls, v):
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if v not in valid_severities:
            raise ValueError(f"Invalid severity threshold: {v}. Must be one of {valid_severities}")
        return v

class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    format: str = Field(default_factory=lambda: os.getenv("LOG_FORMAT", "json"))
    file: Optional[str] = Field(default_factory=lambda: os.getenv("LOG_FILE"))
    
    @validator('level')
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.upper()

class AlertingConfig(BaseModel):
    """Alerting configuration"""
    slack_webhook_url: Optional[str] = Field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL"))
    email_notifications: Optional[str] = Field(default_factory=lambda: os.getenv("EMAIL_NOTIFICATIONS"))
    enable_webhooks: bool = Field(default_factory=lambda: os.getenv("ENABLE_WEBHOOKS", "false").lower() == "true")

class DatabaseConfig(BaseModel):
    """Database configuration"""
    url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///cloud_security.db"))
    redis_url: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))

class CloudSecurityMCPConfig(BaseModel):
    """Main configuration class for Cloud Security MCP Server"""
    
    # Cloud provider configurations
    aws: AWSConfig = Field(default_factory=AWSConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    gcp: GCPConfig = Field(default_factory=GCPConfig)
    kubernetes: KubernetesConfig = Field(default_factory=KubernetesConfig)
    
    # Tool and security configurations
    security_tools: SecurityToolConfig = Field(default_factory=SecurityToolConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    security_policy: SecurityPolicyConfig = Field(default_factory=SecurityPolicyConfig)
    
    # System configurations
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    # Server configuration
    server_name: str = "cloud-security-mcp"
    server_version: str = "1.0.0"
    api_rate_limit: int = Field(default_factory=lambda: int(os.getenv("API_RATE_LIMIT", "100")))
    api_timeout_seconds: int = Field(default_factory=lambda: int(os.getenv("API_TIMEOUT_SECONDS", "30")))
    
    @classmethod
    def from_file(cls, config_path: str) -> "CloudSecurityMCPConfig":
        """Load configuration from a file"""
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        if config_file.suffix.lower() in ['.yaml', '.yml']:
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
        elif config_file.suffix.lower() == '.json':
            with open(config_file, 'r') as f:
                config_data = json.load(f)
        else:
            raise ValueError(f"Unsupported configuration file format: {config_file.suffix}")
        
        return cls(**config_data)
    
    def save_to_file(self, config_path: str):
        """Save configuration to a file"""
        config_file = Path(config_path)
        config_data = self.dict()
        
        if config_file.suffix.lower() in ['.yaml', '.yml']:
            with open(config_file, 'w') as f:
                yaml.safe_dump(config_data, f, default_flow_style=False, indent=2)
        elif config_file.suffix.lower() == '.json':
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        else:
            raise ValueError(f"Unsupported configuration file format: {config_file.suffix}")
    
    def validate_cloud_credentials(self) -> Dict[str, bool]:
        """Validate cloud provider credentials"""
        validation_results = {}
        
        # AWS validation
        aws_valid = bool(self.aws.access_key_id and self.aws.secret_access_key) or bool(self.aws.profile)
        validation_results["aws"] = aws_valid
        
        # Azure validation
        azure_valid = bool(self.azure.subscription_id and (self.azure.client_id and self.azure.client_secret))
        validation_results["azure"] = azure_valid
        
        # GCP validation
        gcp_valid = bool(self.gcp.credentials_file or self.gcp.service_account_key) and bool(self.gcp.project_id)
        validation_results["gcp"] = gcp_valid
        
        return validation_results
    
    def get_enabled_cloud_providers(self) -> List[str]:
        """Get list of enabled cloud providers based on credentials"""
        validation = self.validate_cloud_credentials()
        return [provider for provider, valid in validation.items() if valid]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return self.dict()

def load_config(config_path: Optional[str] = None) -> CloudSecurityMCPConfig:
    """Load configuration from file or environment variables"""
    if config_path and Path(config_path).exists():
        return CloudSecurityMCPConfig.from_file(config_path)
    else:
        return CloudSecurityMCPConfig()

def create_default_config_file(output_path: str = "config.yaml"):
    """Create a default configuration file"""
    config = CloudSecurityMCPConfig()
    config.save_to_file(output_path)
    print(f"Default configuration file created: {output_path}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Cloud Security MCP Configuration Manager")
    parser.add_argument("--create-config", "-c", metavar="FILE", help="Create default configuration file")
    parser.add_argument("--validate", "-v", metavar="FILE", help="Validate configuration file")
    parser.add_argument("--show-providers", "-p", action="store_true", help="Show enabled cloud providers")
    
    args = parser.parse_args()
    
    if args.create_config:
        create_default_config_file(args.create_config)
    elif args.validate:
        try:
            config = CloudSecurityMCPConfig.from_file(args.validate)
            print(f"✅ Configuration file '{args.validate}' is valid")
            
            if args.show_providers:
                providers = config.get_enabled_cloud_providers()
                print(f"Enabled cloud providers: {', '.join(providers) if providers else 'None'}")
                
        except Exception as e:
            print(f"❌ Configuration validation failed: {e}")
    elif args.show_providers:
        config = load_config()
        providers = config.get_enabled_cloud_providers()
        print(f"Enabled cloud providers: {', '.join(providers) if providers else 'None'}")
    else:
        parser.print_help()
