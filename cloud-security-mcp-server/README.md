# ☁️ Cloud Security MCP Server

A comprehensive **Model Context Protocol (MCP) server** for cloud security analysis, Infrastructure as Code scanning, and multi-cloud security assessments. This server provides AI agents with powerful cloud security capabilities across AWS, Azure, GCP, and Kubernetes environments.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)

## 🚀 Features

### Multi-Cloud Security Analysis
- **AWS Security Hub** integration for comprehensive security findings
- **Azure Security Center** alerts and recommendations
- **GCP Security Command Center** findings and asset inventory
- **Cross-cloud security posture** assessment and comparison

### Infrastructure as Code (IaC) Security
- **Terraform** security analysis with Checkov and TFSec
- **CloudFormation** template security scanning
- **ARM templates** security validation
- **Kubernetes manifests** security checks
- **Configuration drift detection** between IaC and actual resources

### Container & Kubernetes Security
- **Container vulnerability scanning** with Trivy
- **Docker security benchmarks** (CIS Docker Benchmark)
- **Kubernetes security assessment** with Kube-hunter
- **Pod security policy** analysis
- **Network policy** validation

### Compliance Frameworks
- **CIS Benchmarks** (AWS, Azure, GCP, Kubernetes)
- **NIST Cybersecurity Framework**
- **SOC 2 Type II** controls
- **PCI DSS** requirements
- **GDPR** compliance checks
- **HIPAA** security safeguards

### Advanced Security Features
- **Attack surface analysis** and external exposure mapping
- **IAM security posture** assessment
- **Secrets scanning** in code repositories and cloud resources
- **Security monitoring** setup and alerting
- **Cost security analysis** and optimization recommendations

## 🛠️ Installation

### Prerequisites
- Python 3.9 or higher
- Docker (for security tool integrations)
- Cloud provider credentials (AWS, Azure, GCP)

### Quick Start with Docker

```bash
# Clone the repository
git clone https://github.com/your-org/cloud-security-mcp-server.git
cd cloud-security-mcp-server

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your cloud credentials

# Start with Docker Compose
docker-compose up -d
```

### Manual Installation

```bash
# Install the package
pip install -e .

# Or install from PyPI (when published)
pip install cloud-security-mcp-server

# Initialize configuration
cloud-security-mcp config init

# Start the server
cloud-security-mcp server
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with your cloud provider credentials:

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# Azure Configuration
AZURE_SUBSCRIPTION_ID=your_subscription_id
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret

# GCP Configuration
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
GCP_PROJECT_ID=your_project_id

# Security Configuration
COMPLIANCE_FRAMEWORKS=cis,nist,soc2
ENABLE_CONTAINER_SCANNING=true
ENABLE_IAC_SCANNING=true
```

### Configuration File

Generate and customize a configuration file:

```bash
# Create default configuration
cloud-security-mcp config init --output config.yaml

# Validate configuration
cloud-security-mcp config validate config.yaml

# View current configuration
cloud-security-mcp config show
```

## 🔧 Usage

### MCP Tools Available

The server provides these tools for AI agents:

#### Cloud Security Assessment
- `aws_security_assessment` - Comprehensive AWS security analysis with Prowler
- `azure_security_assessment` - Azure security configuration analysis with Scout Suite
- `gcp_security_assessment` - Google Cloud Platform security assessment
- `multi_cloud_assessment` - Cross-cloud security analysis

#### Infrastructure as Code
- `iac_security_scan` - IaC security scanning with Checkov
- `terraform_security_analysis` - Terraform-specific security analysis with TFSec
- `iac_drift_detection` - Detect configuration drift between IaC and actual resources

#### Container & Kubernetes
- `container_vulnerability_scan` - Container image vulnerability scanning with Trivy
- `kubernetes_security_scan` - Kubernetes cluster security assessment with Kube-hunter
- `docker_security_scan` - Docker security analysis with Docker Bench

#### Advanced Features
- `cloud_attack_surface_analysis` - Analyze external attack surface and exposure
- `secrets_scanning` - Scan for secrets in code and cloud resources
- `cloud_compliance_check` - Compliance framework verification
- `cloud_security_monitoring` - Set up continuous security monitoring

### Command Line Interface

```bash
# Run security scans
cloud-security-mcp scan run --target my-aws-account --tool prowler
cloud-security-mcp scan multi-cloud --providers aws,azure,gcp

# Compliance checking
cloud-security-mcp compliance check --framework cis --provider aws

# Configuration management
cloud-security-mcp config init
cloud-security-mcp config validate config.yaml
```

### Example MCP Tool Usage

Here's how an AI agent would use the tools:

```json
{
  "name": "aws_security_assessment",
  "arguments": {
    "target": "all",
    "compliance_framework": "cis",
    "output_format": "json",
    "region": "us-east-1"
  }
}
```

```json
{
  "name": "iac_security_scan",
  "arguments": {
    "target": "/path/to/terraform/code",
    "scan_options": {
      "framework": "terraform",
      "skip_check": "CKV_AWS_20"
    }
  }
}
```

## 🏗️ Architecture

### Core Components

```
┌─────────────────────────────────────────────┐
│               MCP Server Layer              │
├─────────────────────────────────────────────┤
│            Tool Integrations               │
│  ┌─────────┐ ┌─────────┐ ┌─────────────┐   │
│  │ Prowler │ │ Checkov │ │ Kube-hunter │   │
│  └─────────┘ └─────────┘ └─────────────┘   │
├─────────────────────────────────────────────┤
│          Cloud Provider APIs              │
│  ┌─────┐ ┌───────┐ ┌─────┐ ┌─────────────┐ │
│  │ AWS │ │ Azure │ │ GCP │ │ Kubernetes  │ │
│  └─────┘ └───────┘ └─────┘ └─────────────┘ │
└─────────────────────────────────────────────┘
```

### Security Tools Integration

| Tool | Purpose | Container | Output Format |
|------|---------|-----------|---------------|
| **Prowler** | AWS security assessment | `toniblyx/prowler:latest` | JSON, HTML, CSV |
| **Scout Suite** | Multi-cloud security audit | `nccgroup/scoutsuite:latest` | JSON, HTML |
| **Checkov** | IaC security scanning | `bridgecrew/checkov:latest` | JSON, SARIF |
| **TFSec** | Terraform security analysis | `aquasec/tfsec:latest` | JSON, SARIF |
| **Trivy** | Container vulnerability scanning | `aquasec/trivy:latest` | JSON, SARIF |
| **Kube-hunter** | Kubernetes security testing | `aquasec/kube-hunter:latest` | JSON, YAML |

## 📊 Compliance Frameworks

### Supported Frameworks

| Framework | AWS | Azure | GCP | Kubernetes |
|-----------|-----|-------|-----|------------|
| **CIS Benchmarks** | ✅ | ✅ | ✅ | ✅ |
| **NIST CSF** | ✅ | ✅ | ✅ | ✅ |
| **SOC 2** | ✅ | ✅ | ✅ | ❌ |
| **PCI DSS** | ✅ | ✅ | ✅ | ❌ |
| **GDPR** | ✅ | ✅ | ✅ | ❌ |
| **HIPAA** | ✅ | ✅ | ✅ | ❌ |

### Compliance Scoring

The server provides compliance scoring based on:
- **Control implementation** percentage
- **Risk severity** weighting
- **Resource coverage** analysis
- **Trend analysis** over time

## 🔐 Security Considerations

### Credentials Management
- Use **IAM roles** and **service principals** when possible
- Store credentials securely using **environment variables** or **secret managers**
- Implement **credential rotation** policies
- Use **least privilege** access principles

### Network Security
- Run in **private networks** when possible
- Use **VPC endpoints** for cloud API access
- Implement **network segmentation**
- Enable **audit logging** for all activities

### Data Protection
- Scan results contain **sensitive security information**
- Implement **encryption at rest** for stored results
- Use **secure channels** for data transmission
- Follow **data retention** policies

## 🚀 Deployment

### Production Deployment

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  cloud-security-mcp:
    image: cloud-security-mcp:latest
    environment:
      - LOG_LEVEL=INFO
      - REDIS_URL=redis://redis:6379/0
    volumes:
      - ./scan_results:/app/scan_results
      - /var/run/docker.sock:/var/run/docker.sock
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloud-security-mcp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cloud-security-mcp
  template:
    metadata:
      labels:
        app: cloud-security-mcp
    spec:
      containers:
      - name: cloud-security-mcp
        image: cloud-security-mcp:latest
        ports:
        - containerPort: 8080
        env:
        - name: LOG_LEVEL
          value: "INFO"
        volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
      volumes:
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
```

## 📈 Monitoring & Observability

### Metrics Collection
- **Prometheus** metrics for scan performance
- **Grafana** dashboards for visualization
- **Alert manager** for critical findings

### Key Metrics
- Scan execution time and success rate
- Security findings by severity and cloud provider
- Compliance score trends over time
- Resource coverage and drift detection

### Sample Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Cloud Security Dashboard",
    "panels": [
      {
        "title": "Security Findings by Severity",
        "type": "stat",
        "targets": [
          {
            "expr": "sum by (severity) (cloud_security_findings_total)"
          }
        ]
      }
    ]
  }
}
```

## 🤝 Integration Examples

### With Claude/GPT

```python
# Example AI agent interaction
response = await agent.use_tool(
    "aws_security_assessment",
    {
        "target": "production-account",
        "compliance_framework": "cis",
        "scan_options": {
            "services": ["s3", "ec2", "iam"],
            "regions": ["us-east-1", "us-west-2"]
        }
    }
)

# Process findings
critical_findings = [
    f for f in response["findings"] 
    if f["severity"] == "critical"
]

# Generate remediation plan
remediation_plan = await agent.generate_remediation_plan(
    critical_findings
)
```

### With CI/CD Pipelines

```yaml
# .github/workflows/security-scan.yml
name: Cloud Security Scan
on:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run IaC Security Scan
      run: |
        docker run --rm \
          -v ${{ github.workspace }}:/workspace \
          cloud-security-mcp:latest \
          cloud-security-mcp scan run \
          --target /workspace \
          --tool checkov \
          --output security-results.json
    
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: security-results.json
```

## 📚 API Reference

### MCP Tool Schema

```typescript
interface SecurityScanRequest {
  target: string;                    // Scan target
  scan_type?: string;               // Type of scan
  output_format?: 'json' | 'sarif'; // Output format
  compliance_framework?: string;     // Compliance framework
  region?: string;                  // Cloud region
  scan_options?: Record<string, any>; // Additional options
}

interface SecurityScanResponse {
  scan_type: string;
  cloud_provider: string;
  findings: SecurityFinding[];
  compliance_status: ComplianceStatus;
  risk_score: number;
  recommendations: string[];
  scan_metadata: ScanMetadata;
}
```

## 🐛 Troubleshooting

### Common Issues

#### Docker Permission Issues
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

#### AWS Credentials
```bash
# Check AWS credentials
aws sts get-caller-identity

# Configure AWS CLI
aws configure
```

#### Memory Issues
```bash
# Increase Docker memory limit
# In Docker Desktop: Settings > Resources > Memory > 4GB+
```

### Debug Mode
```bash
# Enable verbose logging
export LOG_LEVEL=DEBUG
cloud-security-mcp server --verbose
```

## 🛣️ Roadmap

### Current Version (1.0.0)
- ✅ Multi-cloud security scanning
- ✅ IaC security analysis
- ✅ Container vulnerability scanning
- ✅ Compliance framework checking

### Upcoming Features (1.1.0)
- 🔄 Real-time security monitoring
- 🔄 Advanced threat detection
- 🔄 Security orchestration workflows
- 🔄 Integration with SIEM systems

### Future Enhancements (2.0.0)
- 🔮 AI-powered threat hunting
- 🔮 Automated remediation
- 🔮 Custom security policies
- 🔮 Advanced analytics and ML

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/your-org/cloud-security-mcp-server.git
cd cloud-security-mcp-server

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run code formatting
black cloud_security_mcp_server/
flake8 cloud_security_mcp_server/
```

## 🙏 Acknowledgments

- **Prowler** team for AWS security assessment
- **Bridgecrew** for Checkov IaC scanning
- **Aqua Security** for Trivy and Kube-hunter
- **Scout Suite** team for multi-cloud analysis
- **MCP Protocol** contributors

## 📞 Support

- 📧 Email: security-support@example.com
- 💬 Discord: [Cloud Security Community](https://discord.gg/cloud-security)
- 📖 Documentation: [https://cloud-security-mcp-server.readthedocs.io/](https://cloud-security-mcp-server.readthedocs.io/)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/cloud-security-mcp-server/issues)

---

**⭐ Star this repository if you find it useful!**

Built with ❤️ for the cloud security community.
