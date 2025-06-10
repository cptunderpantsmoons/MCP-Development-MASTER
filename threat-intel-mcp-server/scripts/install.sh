#!/bin/bash
# Installation script for Threat Intelligence MCP Server

set -e

echo "🔍 Installing Threat Intelligence MCP Server..."

# Check prerequisites
echo "📋 Checking prerequisites..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check pip
if ! command -v pip &> /dev/null; then
    echo "❌ pip is required but not installed."
    exit 1
fi

echo "✅ All prerequisites met!"

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Copy environment configuration
if [ ! -f .env ]; then
    echo "⚙️ Creating environment configuration..."
    cp .env.example .env
    echo "📝 Please edit .env file with your API keys before starting the server."
fi

# Create intel logs directory
mkdir -p intel_logs

# Set permissions
chmod 755 intel_logs

# Create cache directory
mkdir -p intel_cache
chmod 755 intel_cache

echo "🎉 Installation complete!"
echo ""
echo "Next steps:"
echo "1. Get API keys from threat intelligence providers:"
echo "   - VirusTotal: https://www.virustotal.com/gui/join-us"
echo "   - Shodan: https://account.shodan.io/"
echo "   - Have I Been Pwned: https://haveibeenpwned.com/API/Key"
echo "   - AbuseIPDB: https://www.abuseipdb.com/api"
echo "   - And others listed in README.md"
echo ""
echo "2. Edit .env file with your API keys"
echo "3. Review config.yaml for server settings"
echo "4. Start the server with: python -m threat_intel_mcp_server.main"
echo "5. Or use Docker: docker-compose up -d"
echo ""
echo "For more information, see README.md"