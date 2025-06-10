#!/bin/bash

# DSN Development Environment Setup Script
# This script sets up the complete development environment for the DSN project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check Go
    if ! command_exists go; then
        log_error "Go is not installed. Please install Go 1.21 or later."
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Found Go version: $GO_VERSION"
    
    # Check Docker
    if ! command_exists docker; then
        log_error "Docker is not installed. Please install Docker."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command_exists docker-compose && ! docker compose version >/dev/null 2>&1; then
        log_error "Docker Compose is not installed. Please install Docker Compose."
        exit 1
    fi
    
    # Check Git
    if ! command_exists git; then
        log_error "Git is not installed. Please install Git."
        exit 1
    fi
    
    # Check Make
    if ! command_exists make; then
        log_warning "Make is not installed. Some build commands may not work."
    fi
    
    log_success "All requirements satisfied!"
}

# Install Go tools
install_go_tools() {
    log_info "Installing Go development tools..."
    
    # Protocol Buffers compiler
    if ! command_exists protoc; then
        log_warning "protoc not found. Please install Protocol Buffers compiler manually."
    fi
    
    # Go tools
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    go install honnef.co/go/tools/cmd/staticcheck@latest
    go install github.com/air-verse/air@latest
    
    log_success "Go tools installed!"
}

# Setup project dependencies
setup_dependencies() {
    log_info "Setting up project dependencies..."
    
    # Download Go modules
    go mod download
    go mod verify
    
    log_success "Dependencies installed!"
}

# Generate Protocol Buffers
generate_protos() {
    log_info "Generating Protocol Buffer files..."
    
    if command_exists protoc; then
        make proto-gen 2>/dev/null || {
            log_info "Running protoc manually..."
            
            # Create output directories
            mkdir -p pkg/proto/sentinel/v1
            mkdir -p pkg/proto/consensus/v1
            
            # Generate Go files from proto definitions
            protoc --go_out=. --go_opt=paths=source_relative \
                   --go-grpc_out=. --go-grpc_opt=paths=source_relative \
                   proto/sentinel/v1/sentinel.proto
            
            protoc --go_out=. --go_opt=paths=source_relative \
                   --go-grpc_out=. --go-grpc_opt=paths=source_relative \
                   proto/consensus/v1/consensus.proto
        }
        log_success "Protocol Buffer files generated!"
    else
        log_warning "protoc not available. Skipping Protocol Buffer generation."
    fi
}

# Setup development database
setup_database() {
    log_info "Setting up development database..."
    
    # Start PostgreSQL and Redis using Docker Compose
    if command_exists docker-compose; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    
    cd deployments/docker
    $COMPOSE_CMD up -d postgres redis
    cd ../..
    
    # Wait for database to be ready
    log_info "Waiting for database to be ready..."
    sleep 10
    
    log_success "Development database is ready!"
}

# Setup monitoring stack
setup_monitoring() {
    log_info "Setting up monitoring stack..."
    
    if command_exists docker-compose; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    
    cd deployments/docker
    $COMPOSE_CMD up -d prometheus grafana jaeger
    cd ../..
    
    log_success "Monitoring stack is ready!"
    log_info "Grafana: http://localhost:3000 (admin/admin123)"
    log_info "Prometheus: http://localhost:9091"
    log_info "Jaeger: http://localhost:16686"
}

# Create development configuration
create_dev_config() {
    log_info "Creating development configuration..."
    
    # Copy sample config if it doesn't exist
    if [ ! -f "configs/sentinel.dev.yaml" ]; then
        cp configs/sentinel.yaml configs/sentinel.dev.yaml
        log_info "Created configs/sentinel.dev.yaml from template"
    fi
    
    # Create environment file
    cat > .env.dev << EOF
# DSN Development Environment Variables
DSN_CONFIG_FILE=configs/sentinel.dev.yaml
DSN_LOG_LEVEL=debug
DSN_LOG_FORMAT=json
DSN_ENVIRONMENT=development

# Database
DSN_DB_HOST=localhost
DSN_DB_PORT=5432
DSN_DB_NAME=dsn_dev
DSN_DB_USER=dsn_user
DSN_DB_PASSWORD=dsn_dev_password

# Redis
DSN_REDIS_HOST=localhost
DSN_REDIS_PORT=6379
DSN_REDIS_PASSWORD=dsn-dev-password

# Monitoring
DSN_METRICS_ENABLED=true
DSN_PROMETHEUS_ENDPOINT=http://localhost:9091
DSN_JAEGER_ENDPOINT=http://localhost:14268/api/traces
EOF
    
    log_success "Development configuration created!"
}

# Setup Git hooks
setup_git_hooks() {
    log_info "Setting up Git hooks..."
    
    # Create pre-commit hook
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# DSN Pre-commit hook

echo "Running pre-commit checks..."

# Run go fmt
if ! go fmt ./...; then
    echo "go fmt failed"
    exit 1
fi

# Run go vet
if ! go vet ./...; then
    echo "go vet failed"
    exit 1
fi

# Run tests
if ! go test -short ./...; then
    echo "Tests failed"
    exit 1
fi

echo "Pre-commit checks passed!"
EOF
    
    chmod +x .git/hooks/pre-commit
    
    log_success "Git hooks installed!"
}

# Build the project
build_project() {
    log_info "Building the project..."
    
    make build 2>/dev/null || {
        log_info "Running go build manually..."
        go build -o bin/sentinel ./cmd/sentinel
    }
    
    log_success "Project built successfully!"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    go test -v -short ./...
    
    log_success "Tests completed!"
}

# Print setup summary
print_summary() {
    log_success "Development environment setup complete!"
    echo
    echo "Quick start commands:"
    echo "  make dev          # Start development server with hot reload"
    echo "  make test         # Run all tests"
    echo "  make build        # Build the project"
    echo "  make docker-dev   # Start full development stack"
    echo
    echo "Useful URLs:"
    echo "  Grafana:    http://localhost:3000 (admin/admin123)"
    echo "  Prometheus: http://localhost:9091"
    echo "  Jaeger:     http://localhost:16686"
    echo
    echo "Configuration files:"
    echo "  Main config:    configs/sentinel.yaml"
    echo "  Dev config:     configs/sentinel.dev.yaml"
    echo "  Environment:    .env.dev"
    echo
    echo "Next steps:"
    echo "  1. Review and customize configs/sentinel.dev.yaml"
    echo "  2. Run 'make dev' to start the development server"
    echo "  3. Check the documentation in docs/ directory"
    echo
}

# Main setup function
main() {
    echo "========================================="
    echo "DSN Development Environment Setup"
    echo "========================================="
    echo
    
    check_requirements
    install_go_tools
    setup_dependencies
    generate_protos
    create_dev_config
    setup_database
    setup_monitoring
    setup_git_hooks
    build_project
    run_tests
    
    echo
    print_summary
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "DSN Development Setup Script"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --quick, -q    Quick setup (skip optional components)"
        echo "  --clean        Clean existing setup and start fresh"
        echo
        exit 0
        ;;
    --quick|-q)
        log_info "Running quick setup..."
        check_requirements
        setup_dependencies
        create_dev_config
        build_project
        print_summary
        ;;
    --clean)
        log_info "Cleaning existing setup..."
        docker-compose -f deployments/docker/docker-compose.dev.yml down -v 2>/dev/null || true
        rm -rf bin/ pkg/proto/ .env.dev configs/sentinel.dev.yaml 2>/dev/null || true
        log_success "Cleanup complete!"
        main
        ;;
    *)
        main
        ;;
esac