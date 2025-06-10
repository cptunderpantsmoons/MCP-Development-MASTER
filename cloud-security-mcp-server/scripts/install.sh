#!/bin/bash
# Cloud Security MCP Server Installation Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/cloud-security-mcp"
SERVICE_USER="cloud-security"
SERVICE_NAME="cloud-security-mcp"

echo -e "${BLUE}Cloud Security MCP Server Installation${NC}"
echo "========================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo -e "${RED}Unsupported operating system: $OSTYPE${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Detected OS: $OS"

# Install system dependencies
echo -e "${BLUE}Installing system dependencies...${NC}"

if [[ "$OS" == "linux" ]]; then
    # Update package lists
    apt-get update -y
    
    # Install required packages
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        docker.io \
        docker-compose \
        curl \
        wget \
        git \
        unzip \
        jq \
        systemd
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
elif [[ "$OS" == "macos" ]]; then
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo -e "${YELLOW}Installing Homebrew...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install required packages
    brew install python3 docker docker-compose curl wget git jq
fi

echo -e "${GREEN}✓${NC} System dependencies installed"

# Install cloud CLIs
echo -e "${BLUE}Installing cloud provider CLIs...${NC}"

# AWS CLI
if ! command -v aws &> /dev/null; then
    echo -e "${YELLOW}Installing AWS CLI...${NC}"
    if [[ "$OS" == "linux" ]]; then
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
        unzip awscliv2.zip
        ./aws/install
        rm -rf aws awscliv2.zip
    elif [[ "$OS" == "macos" ]]; then
        curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
        installer -pkg AWSCLIV2.pkg -target /
        rm AWSCLIV2.pkg
    fi
fi

# Azure CLI
if ! command -v az &> /dev/null; then
    echo -e "${YELLOW}Installing Azure CLI...${NC}"
    if [[ "$OS" == "linux" ]]; then
        curl -sL https://aka.ms/InstallAzureCLIDeb | bash
    elif [[ "$OS" == "macos" ]]; then
        brew install azure-cli
    fi
fi

# Google Cloud CLI
if ! command -v gcloud &> /dev/null; then
    echo -e "${YELLOW}Installing Google Cloud CLI...${NC}"
    if [[ "$OS" == "linux" ]]; then
        echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
        curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
        apt-get update -y && apt-get install -y google-cloud-cli
    elif [[ "$OS" == "macos" ]]; then
        brew install google-cloud-sdk
    fi
fi

# kubectl
if ! command -v kubectl &> /dev/null; then
    echo -e "${YELLOW}Installing kubectl...${NC}"
    if [[ "$OS" == "linux" ]]; then
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
        rm kubectl
    elif [[ "$OS" == "macos" ]]; then
        brew install kubectl
    fi
fi

# Terraform
if ! command -v terraform &> /dev/null; then
    echo -e "${YELLOW}Installing Terraform...${NC}"
    if [[ "$OS" == "linux" ]]; then
        wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list
        apt-get update && apt-get install -y terraform
    elif [[ "$OS" == "macos" ]]; then
        brew tap hashicorp/tap
        brew install hashicorp/tap/terraform
    fi
fi

echo -e "${GREEN}✓${NC} Cloud CLIs installed"

# Create service user
echo -e "${BLUE}Creating service user...${NC}"
if [[ "$OS" == "linux" ]]; then
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
        usermod -aG docker "$SERVICE_USER"
    fi
elif [[ "$OS" == "macos" ]]; then
    if ! dscl . -read /Users/"$SERVICE_USER" &>/dev/null; then
        dscl . -create /Users/"$SERVICE_USER"
        dscl . -create /Users/"$SERVICE_USER" UserShell /bin/false
    fi
fi

echo -e "${GREEN}✓${NC} Service user created"

# Create installation directory
echo -e "${BLUE}Setting up installation directory...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"/{config,logs,scan_results,scripts}

# Download and install the application
echo -e "${BLUE}Installing Cloud Security MCP Server...${NC}"

# Create Python virtual environment
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Install the package
pip install --upgrade pip
pip install cloud-security-mcp-server

# Create configuration files
cat > "$INSTALL_DIR/config/config.yaml" << 'EOF'
# Cloud Security MCP Server Configuration
server_name: "cloud-security-mcp"
server_version: "1.0.0"

# AWS Configuration
aws:
  region: "us-east-1"
  # Add your AWS credentials here or use IAM roles

# Azure Configuration  
azure:
  # Add your Azure credentials here

# GCP Configuration
gcp:
  # Add your GCP credentials here

# Security Tools Configuration
security_tools:
  enable_container_scanning: true
  enable_iac_scanning: true
  enable_compliance_checks: true
  max_scan_time_minutes: 30

# Compliance Frameworks
compliance:
  frameworks: ["cis", "nist", "soc2"]

# Logging
logging:
  level: "INFO"
  format: "json"
  file: "/opt/cloud-security-mcp/logs/cloud_security.log"
EOF

# Create environment file
cat > "$INSTALL_DIR/config/.env" << 'EOF'
# Cloud Security MCP Server Environment Variables

# AWS Configuration
# AWS_ACCESS_KEY_ID=your_access_key
# AWS_SECRET_ACCESS_KEY=your_secret_key
# AWS_DEFAULT_REGION=us-east-1

# Azure Configuration
# AZURE_SUBSCRIPTION_ID=your_subscription_id
# AZURE_TENANT_ID=your_tenant_id
# AZURE_CLIENT_ID=your_client_id
# AZURE_CLIENT_SECRET=your_client_secret

# GCP Configuration
# GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
# GCP_PROJECT_ID=your_project_id

# Security Configuration
LOG_LEVEL=INFO
ENABLE_CONTAINER_SCANNING=true
ENABLE_IAC_SCANNING=true
ENABLE_COMPLIANCE_CHECKS=true
EOF

# Set permissions
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/config/.env"
chmod 755 "$INSTALL_DIR"/{config,logs,scan_results,scripts}

echo -e "${GREEN}✓${NC} Application installed"

# Create systemd service (Linux only)
if [[ "$OS" == "linux" ]]; then
    echo -e "${BLUE}Creating systemd service...${NC}"
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Cloud Security MCP Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=$INSTALL_DIR/config/.env
ExecStart=$INSTALL_DIR/venv/bin/python -m cloud_security_mcp_server.main
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    echo -e "${GREEN}✓${NC} Systemd service created"
fi

# Create management scripts
echo -e "${BLUE}Creating management scripts...${NC}"

# Start script
cat > "$INSTALL_DIR/scripts/start.sh" << 'EOF'
#!/bin/bash
cd /opt/cloud-security-mcp
source venv/bin/activate
export $(cat config/.env | xargs)
python -m cloud_security_mcp_server.main
EOF

# Stop script
cat > "$INSTALL_DIR/scripts/stop.sh" << 'EOF'
#!/bin/bash
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    systemctl stop cloud-security-mcp
else
    pkill -f "cloud_security_mcp_server"
fi
EOF

# Status script
cat > "$INSTALL_DIR/scripts/status.sh" << 'EOF'
#!/bin/bash
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    systemctl status cloud-security-mcp
else
    pgrep -f "cloud_security_mcp_server" > /dev/null && echo "Running" || echo "Stopped"
fi
EOF

# Update script
cat > "$INSTALL_DIR/scripts/update.sh" << 'EOF'
#!/bin/bash
echo "Updating Cloud Security MCP Server..."
cd /opt/cloud-security-mcp
source venv/bin/activate
pip install --upgrade cloud-security-mcp-server
echo "Update complete. Please restart the service."
EOF

# Backup script
cat > "$INSTALL_DIR/scripts/backup.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/cloud-security-mcp/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "Creating backup..."
tar -czf "$BACKUP_DIR/cloud_security_backup_$TIMESTAMP.tar.gz" \
    -C /opt/cloud-security-mcp \
    config/ logs/ scan_results/ \
    --exclude='logs/*.log' \
    --exclude='scan_results/tmp*'

echo "Backup created: $BACKUP_DIR/cloud_security_backup_$TIMESTAMP.tar.gz"

# Keep only last 10 backups
ls -t "$BACKUP_DIR"/cloud_security_backup_*.tar.gz | tail -n +11 | xargs -r rm
EOF

# Make scripts executable
chmod +x "$INSTALL_DIR/scripts"/*.sh

echo -e "${GREEN}✓${NC} Management scripts created"

# Pull Docker images
echo -e "${BLUE}Pulling security tool Docker images...${NC}"
docker pull toniblyx/prowler:latest
docker pull bridgecrew/checkov:latest
docker pull aquasec/trivy:latest
docker pull aquasec/kube-hunter:latest
docker pull nccgroup/scoutsuite:latest

echo -e "${GREEN}✓${NC} Docker images pulled"

# Create log rotation configuration
if [[ "$OS" == "linux" ]]; then
    echo -e "${BLUE}Setting up log rotation...${NC}"
    
    cat > "/etc/logrotate.d/$SERVICE_NAME" << EOF
$INSTALL_DIR/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload $SERVICE_NAME || true
    endscript
}
EOF

    echo -e "${GREEN}✓${NC} Log rotation configured"
fi

# Installation summary
echo
echo -e "${GREEN}========================================"
echo -e "Installation Complete! ✓"
echo -e "========================================${NC}"
echo
echo -e "${BLUE}Installation Directory:${NC} $INSTALL_DIR"
echo -e "${BLUE}Configuration File:${NC} $INSTALL_DIR/config/config.yaml"
echo -e "${BLUE}Environment File:${NC} $INSTALL_DIR/config/.env"
echo -e "${BLUE}Log Directory:${NC} $INSTALL_DIR/logs"
echo -e "${BLUE}Service User:${NC} $SERVICE_USER"
echo

echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Configure your cloud provider credentials in $INSTALL_DIR/config/.env"
echo "2. Review and customize $INSTALL_DIR/config/config.yaml"
if [[ "$OS" == "linux" ]]; then
    echo "3. Start the service: systemctl start $SERVICE_NAME"
    echo "4. Check status: systemctl status $SERVICE_NAME"
    echo "5. View logs: journalctl -u $SERVICE_NAME -f"
else
    echo "3. Start the service: $INSTALL_DIR/scripts/start.sh"
    echo "4. Check status: $INSTALL_DIR/scripts/status.sh"
fi
echo

echo -e "${YELLOW}Management Commands:${NC}"
echo "• Start:  $INSTALL_DIR/scripts/start.sh"
echo "• Stop:   $INSTALL_DIR/scripts/stop.sh"
echo "• Status: $INSTALL_DIR/scripts/status.sh"
echo "• Update: $INSTALL_DIR/scripts/update.sh"
echo "• Backup: $INSTALL_DIR/scripts/backup.sh"
echo

echo -e "${BLUE}Documentation:${NC} https://cloud-security-mcp-server.readthedocs.io/"
echo -e "${BLUE}Support:${NC} https://github.com/your-org/cloud-security-mcp-server/issues"
echo

echo -e "${GREEN}Happy Scanning! 🔐${NC}"
