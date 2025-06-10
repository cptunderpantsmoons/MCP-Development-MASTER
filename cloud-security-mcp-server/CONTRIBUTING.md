# Contributing to Cloud Security MCP Server

Thank you for your interest in contributing to the Cloud Security MCP Server! This document provides guidelines and information for contributors.

## 🤝 Code of Conduct

This project adheres to a code of conduct to ensure a welcoming environment for everyone. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🚀 Getting Started

### Prerequisites

- Python 3.9 or higher
- Docker and Docker Compose
- Git
- Basic knowledge of cloud security concepts
- Familiarity with AWS, Azure, or GCP (depending on contribution area)

### Development Environment Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/cloud-security-mcp-server.git
   cd cloud-security-mcp-server
   ```

2. **Set up Python virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   pip install pre-commit
   ```

4. **Set up pre-commit hooks**
   ```bash
   pre-commit install
   ```

5. **Copy example configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your development credentials
   ```

6. **Run tests to verify setup**
   ```bash
   pytest tests/
   ```

## 📝 How to Contribute

### Reporting Issues

Before creating a new issue, please:

1. **Search existing issues** to avoid duplicates
2. **Use the issue templates** provided
3. **Include relevant information**:
   - Cloud Security MCP Server version
   - Operating system and version
   - Python version
   - Cloud provider (AWS, Azure, GCP)
   - Error messages and stack traces
   - Steps to reproduce

### Feature Requests

We welcome feature requests! Please:

1. **Check existing feature requests** first
2. **Use the feature request template**
3. **Provide clear use cases** and benefits
4. **Consider implementation complexity**
5. **Be open to discussion** about scope and approach

### Pull Requests

#### Before Submitting

1. **Create or update tests** for your changes
2. **Update documentation** if needed
3. **Run the full test suite**
4. **Follow code style guidelines**
5. **Write clear commit messages**

#### PR Process

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** with appropriate tests

3. **Run quality checks**:
   ```bash
   black cloud_security_mcp_server/
   flake8 cloud_security_mcp_server/
   mypy cloud_security_mcp_server/
   pytest tests/
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add new security scanner integration"
   ```

5. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Fill out the PR template** completely

## 🛠️ Development Guidelines

### Code Style

- **Python**: Follow [PEP 8](https://pep8.org/) style guide
- **Line length**: Maximum 127 characters
- **Formatting**: Use [Black](https://black.readthedocs.io/) for code formatting
- **Imports**: Use [isort](https://pycqa.github.io/isort/) for import sorting
- **Type hints**: Use type hints for all function parameters and return values

### Code Quality

- **Linting**: Use [flake8](https://flake8.pycqa.org/) for linting
- **Type checking**: Use [mypy](http://mypy-lang.org/) for static type checking
- **Security**: Run [bandit](https://bandit.readthedocs.io/) for security issues
- **Coverage**: Maintain test coverage above 80%

### Testing

- **Unit tests**: Test individual functions and classes
- **Integration tests**: Test component interactions
- **Mock external dependencies**: Use `unittest.mock` for cloud APIs
- **Test naming**: Use descriptive test function names
- **Test organization**: Mirror the source code structure in tests

#### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=cloud_security_mcp_server --cov-report=term-missing

# Run specific test file
pytest tests/test_specific_module.py

# Run tests matching pattern
pytest tests/ -k "test_aws"

# Run integration tests only
pytest tests/integration/
```

### Documentation

- **Docstrings**: Use Google-style docstrings for all public functions
- **README**: Keep README.md up to date
- **API docs**: Document all MCP tools and their parameters
- **Examples**: Provide working examples for new features

#### Docstring Example

```python
def scan_aws_resources(region: str, service_filter: List[str] = None) -> Dict[str, Any]:
    """Scan AWS resources for security vulnerabilities.
    
    Args:
        region: AWS region to scan (e.g., 'us-east-1')
        service_filter: Optional list of AWS services to limit scan to
        
    Returns:
        Dictionary containing scan results with findings and metadata
        
    Raises:
        AWSCredentialsError: If AWS credentials are not configured
        ServiceNotSupportedError: If service_filter contains unsupported services
        
    Example:
        >>> results = scan_aws_resources('us-east-1', ['s3', 'ec2'])
        >>> print(f"Found {len(results['findings'])} security issues")
    """
```

## 🏗️ Architecture Guidelines

### Adding New Security Tools

When adding a new security tool integration:

1. **Create tool class** in `cloud_security_mcp_server/tools.py`
2. **Extend base integration** class
3. **Add Docker support** if tool runs in container
4. **Update tool registry** in main server
5. **Add comprehensive tests**
6. **Update documentation**

#### Example Tool Integration

```python
class NewSecurityToolIntegration(SecurityToolIntegration):
    """Integration for NewSecurityTool scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("new_tool", "vendor/tool:latest", config)
    
    async def run_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run NewSecurityTool scan"""
        # Implementation here
        pass
```

### Adding Cloud Provider Support

For new cloud providers:

1. **Create provider module** in `cloud_security_mcp_server/cloud_providers.py`
2. **Implement standard interface** methods
3. **Add credential management**
4. **Support multiple authentication methods**
5. **Add region/zone support**
6. **Include compliance framework mappings**

### Adding Compliance Frameworks

For new compliance frameworks:

1. **Define framework structure** in configuration
2. **Map controls to checks** in each cloud provider
3. **Add scoring methodology**
4. **Update reporting templates**
5. **Add framework-specific tests**

## 🧪 Testing Strategy

### Test Categories

1. **Unit Tests** (`tests/test_*.py`)
   - Test individual functions and methods
   - Mock external dependencies
   - Fast execution (< 1 second each)

2. **Integration Tests** (`tests/integration/`)
   - Test component interactions
   - Use real services where possible
   - May require credentials

3. **Performance Tests** (`tests/performance/`)
   - Test system under load
   - Measure response times
   - Check resource usage

4. **Security Tests** (`tests/security/`)
   - Test security controls
   - Validate input sanitization
   - Check credential handling

### Writing Good Tests

```python
import pytest
from unittest.mock import Mock, patch
from cloud_security_mcp_server.tools import ProwlerIntegration

class TestProwlerIntegration:
    """Test cases for Prowler integration"""
    
    @pytest.fixture
    def prowler_config(self):
        """Fixture providing test configuration"""
        return {
            "aws_access_key_id": "test_key",
            "aws_secret_access_key": "test_secret",
            "aws_region": "us-east-1"
        }
    
    @pytest.mark.asyncio
    async def test_prowler_scan_success(self, prowler_config):
        """Test successful Prowler scan execution"""
        # Setup
        prowler = ProwlerIntegration(prowler_config)
        
        # Mock subprocess call
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = '{"findings": []}'
            
            # Execute
            result = await prowler.run_scan("test-account")
            
            # Assert
            assert result["status"] == "completed"
            assert "findings" in result
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_prowler_scan_failure(self, prowler_config):
        """Test Prowler scan failure handling"""
        # Test error conditions
        pass
```

## 🔒 Security Considerations

### Credential Security

- **Never commit credentials** to version control
- **Use environment variables** for sensitive data
- **Implement least privilege** access
- **Support credential rotation**
- **Validate credential formats**

### Input Validation

- **Sanitize all inputs** from users and external sources
- **Validate file paths** to prevent directory traversal
- **Check parameter ranges** and formats
- **Use parameterized queries** for databases

### Output Security

- **Sanitize scan results** before displaying
- **Remove sensitive data** from logs
- **Implement access controls** for scan results
- **Use secure storage** for scan artifacts

## 📦 Release Process

### Version Management

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes to API or core functionality
- **MINOR**: New features, maintaining backward compatibility
- **PATCH**: Bug fixes and minor improvements

### Release Checklist

1. **Update version** in `setup.py` and `__init__.py`
2. **Update CHANGELOG.md** with new features and fixes
3. **Run full test suite** and ensure all pass
4. **Update documentation** for new features
5. **Create release branch** and PR
6. **Tag release** after merge to main
7. **Monitor deployment** and release metrics

## 📚 Resources

### Documentation

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [AWS Security Documentation](https://docs.aws.amazon.com/security/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [Google Cloud Security Documentation](https://cloud.google.com/security/docs)

### Security Tools

- [Prowler Documentation](https://github.com/prowler-cloud/prowler)
- [Checkov Documentation](https://www.checkov.io/1.Welcome/Quick%20Start.html)
- [Trivy Documentation](https://trivy.dev/)
- [Kube-hunter Documentation](https://github.com/aquasecurity/kube-hunter)

### Development Tools

- [Black Code Formatter](https://black.readthedocs.io/)
- [Flake8 Linter](https://flake8.pycqa.org/)
- [MyPy Type Checker](http://mypy-lang.org/)
- [Pytest Testing Framework](https://pytest.org/)

## 🤔 Questions?

- **General questions**: Open a [Discussion](https://github.com/your-org/cloud-security-mcp-server/discussions)
- **Bug reports**: Create an [Issue](https://github.com/your-org/cloud-security-mcp-server/issues)
- **Security issues**: Email security@example.com
- **Chat**: Join our [Discord](https://discord.gg/cloud-security)

## 🏆 Recognition

Contributors are recognized in:

- **CONTRIBUTORS.md** file
- **Release notes** for significant contributions
- **GitHub contributor stats**
- **Community highlights** in project updates

Thank you for contributing to cloud security! 🔐✨

---

*This contributing guide is inspired by best practices from the open source community and adapted for cloud security tooling.*
