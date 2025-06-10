from setuptools import setup, find_packages

setup(
    name="cybersec-mcp-server",
    version="1.0.0",
    description="MCP Server for Cybersecurity Tools Integration",
    author="REDLOG_AI",
    packages=find_packages(),
    install_requires=[
        "mcp>=1.0.0",
        "docker>=6.0.0", 
        "aiofiles>=23.0.0",
        "pydantic>=2.0.0",
        "lxml>=4.9.0"
    ],
    entry_points={
        'console_scripts': [
            'cybersec-mcp-server=cybersec_mcp_server.main:main',
        ],
    },
    python_requires=">=3.8",
)