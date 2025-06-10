#!/usr/bin/env python3
"""
Setup script for Cloud Security MCP Server
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cloud-security-mcp-server",
    version="1.0.0",
    author="Cloud Security Team",
    author_email="security@example.com",
    description="A comprehensive Model Context Protocol server for cloud security analysis and Infrastructure as Code scanning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/cloud-security-mcp-server",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Framework :: AsyncIO",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.12.0",
            "black>=23.0.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
            "coverage>=7.3.0",
            "pre-commit>=3.5.0",
        ],
        "monitoring": [
            "prometheus-client>=0.19.0",
            "grafana-api>=1.0.3",
        ],
        "database": [
            "sqlalchemy>=2.0.0",
            "psycopg2-binary>=2.9.0",
            "alembic>=1.12.0",
        ],
        "web": [
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
            "jinja2>=3.1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "cloud-security-mcp=cloud_security_mcp_server.cli:main",
            "cloud-security-scan=cloud_security_mcp_server.scanner:main",
            "cloud-security-config=cloud_security_mcp_server.config:main",
        ],
    },
    include_package_data=True,
    package_data={
        "cloud_security_mcp_server": [
            "templates/*.html",
            "static/*",
            "compliance_frameworks/*.json",
            "security_policies/*.yaml",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/your-org/cloud-security-mcp-server/issues",
        "Source": "https://github.com/your-org/cloud-security-mcp-server",
        "Documentation": "https://cloud-security-mcp-server.readthedocs.io/",
        "Changelog": "https://github.com/your-org/cloud-security-mcp-server/blob/main/CHANGELOG.md",
    },
    keywords=[
        "cloud security",
        "aws security",
        "azure security", 
        "gcp security",
        "kubernetes security",
        "infrastructure as code",
        "security scanning",
        "compliance",
        "devops security",
        "container security",
        "vulnerability scanning",
        "security automation",
        "mcp server",
        "model context protocol"
    ],
    zip_safe=False,
)
