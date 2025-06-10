from setuptools import setup, find_packages

setup(
    name="threat-intel-mcp-server",
    version="1.0.0",
    description="MCP Server for Threat Intelligence and OSINT Analysis",
    author="REDLOG_AI",
    packages=find_packages(),
    install_requires=[
        "mcp>=1.0.0",
        "aiohttp>=3.8.0",
        "aiofiles>=23.0.0",
        "pydantic>=2.0.0",
        "tldextract>=3.4.0",
        "python-whois>=0.7.3",
        "dnspython>=2.3.0",
        "ipaddress>=1.0.23",
        "python-dateutil>=2.8.2"
    ],
    entry_points={
        'console_scripts': [
            'threat-intel-mcp-server=threat_intel_mcp_server.main:main',
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)