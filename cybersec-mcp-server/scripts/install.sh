#!/bin/bash
# Installation script for Cybersecurity MCP Server

set -e

echo "🔧 Installing Cybersecurity MCP Server..."

# Check prerequisites
echo "📋 Checking prerequisites..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required but not installed."
    echo "Please install Docker and try again."
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is required but not installed."
    echo "Please install Docker Compose and try again."
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
    echo "📝 Please edit .env file with your configuration before starting the server."
fi

# Pull Docker images
echo "🐳 Pulling Docker images..."
docker pull kalilinux/kali-rolling

# Create audit logs directory
mkdir -p audit_logs

# Set permissions
chmod 755 audit_logs

echo "🎉 Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Review config.yaml for security settings"
echo "3. Start the server with: docker-compose up -d"
echo "4. Test with: python -m cybersec_mcp_server.main"
echo ""
echo "For more information, see README.md"
