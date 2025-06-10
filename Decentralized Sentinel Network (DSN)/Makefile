# Decentralized Sentinel Network (DSN) Makefile

# Variables
PROJECT_NAME := dsn
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go variables
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Docker variables
DOCKER := docker
DOCKER_REGISTRY := ghcr.io
DOCKER_REPO := $(DOCKER_REGISTRY)/dsn
DOCKER_TAG := $(VERSION)

# Kubernetes variables
KUBECTL := kubectl
HELM := helm
NAMESPACE := dsn-system

# Build flags
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)
BUILD_FLAGS := -ldflags "$(LDFLAGS)" -trimpath

# Directories
CMD_DIR := ./cmd
INTERNAL_DIR := ./internal
PKG_DIR := ./pkg
PROTO_DIR := ./proto
BUILD_DIR := ./build
DEPLOY_DIR := ./deployments

.PHONY: help
help: ## Display this help message
	@echo "DSN - Decentralized Sentinel Network"
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development commands
.PHONY: setup-dev
setup-dev: ## Set up development environment
	@echo "Setting up development environment..."
	$(GOMOD) download
	$(GOMOD) tidy
	@make install-tools
	@make generate-proto
	@echo "Development environment ready!"

.PHONY: install-tools
install-tools: ## Install development tools
	@echo "Installing development tools..."
	$(GOGET) google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GOGET) google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	$(GOGET) github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Build commands
.PHONY: build
build: ## Build all binaries
	@echo "Building DSN components..."
	@make build-sentinel
	@make build-consensus
	@make build-ai-engine
	@make build-healing
	@echo "Build complete!"

.PHONY: build-sentinel
build-sentinel: ## Build sentinel node binary
	@echo "Building sentinel node..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/sentinel $(CMD_DIR)/sentinel

.PHONY: build-consensus
build-consensus: ## Build consensus layer binary
	@echo "Building consensus layer..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/consensus $(CMD_DIR)/consensus

.PHONY: build-ai-engine
build-ai-engine: ## Build AI engine binary
	@echo "Building AI engine..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/ai-engine $(CMD_DIR)/ai-engine

.PHONY: build-healing
build-healing: ## Build self-healing binary
	@echo "Building self-healing system..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/healing $(CMD_DIR)/healing
# Monitor package commands
.PHONY: test-monitor
test-monitor: ## Run monitor package tests
	@echo "Running monitor package tests..."
	$(GOTEST) -v -race -coverprofile=coverage-monitor.out ./tests/unit/monitor_test.go ./internal/monitor/...

.PHONY: bench-monitor
bench-monitor: ## Run monitor package benchmarks
	@echo "Running monitor package benchmarks..."
	$(GOTEST) -bench=. -benchmem ./tests/unit/monitor_test.go ./internal/monitor/...

.PHONY: fuzz-monitor
fuzz-monitor: ## Run monitor package fuzz tests
	@echo "Running monitor package fuzz tests..."
	$(GOTEST) -fuzz=FuzzMetricValidator -fuzztime=30s ./tests/unit/monitor_test.go

.PHONY: monitor-coverage
monitor-coverage: test-monitor ## Generate monitor test coverage report
	@echo "Generating monitor coverage report..."
	$(GOCMD) tool cover -html=coverage-monitor.out -o coverage-monitor.html
	@echo "Coverage report generated: coverage-monitor.html"

# Protocol Buffers
.PHONY: generate-proto
generate-proto: ## Generate protobuf code
	@echo "Generating protobuf code..."
	@find $(PROTO_DIR) -name "*.proto" -exec protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=. \
		--grpc-gateway_opt=paths=source_relative \
		{} \;
	@echo "Protobuf generation complete!"

# Testing
.PHONY: test
test: ## Run all tests
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo "Tests complete!"

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	$(GOTEST) -v -short ./...

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "Running integration tests..."
	$(GOTEST) -v -run Integration ./...

.PHONY: test-coverage
test-coverage: test ## Generate test coverage report
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Code quality
.PHONY: lint
lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format code
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	$(GOCMD) vet ./...

.PHONY: security-scan
security-scan: ## Run security scan
	@echo "Running security scan..."
	@command -v gosec >/dev/null 2>&1 || { echo "Installing gosec..."; $(GOGET) github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; }
	gosec ./...

# Docker commands
.PHONY: docker-build
docker-build: ## Build all Docker images
	@echo "Building Docker images..."
	@make docker-build-sentinel
	@make docker-build-consensus
	@make docker-build-ai-engine
	@make docker-build-healing

.PHONY: docker-build-sentinel
docker-build-sentinel: ## Build sentinel Docker image
	$(DOCKER) build -f $(DEPLOY_DIR)/docker/Dockerfile.sentinel -t $(DOCKER_REPO)/sentinel:$(DOCKER_TAG) .

.PHONY: docker-build-consensus
docker-build-consensus: ## Build consensus Docker image
	$(DOCKER) build -f $(DEPLOY_DIR)/docker/Dockerfile.consensus -t $(DOCKER_REPO)/consensus:$(DOCKER_TAG) .

.PHONY: docker-build-ai-engine
docker-build-ai-engine: ## Build AI engine Docker image
	$(DOCKER) build -f $(DEPLOY_DIR)/docker/Dockerfile.ai-engine -t $(DOCKER_REPO)/ai-engine:$(DOCKER_TAG) .

.PHONY: docker-build-healing
docker-build-healing: ## Build healing Docker image
	$(DOCKER) build -f $(DEPLOY_DIR)/docker/Dockerfile.healing -t $(DOCKER_REPO)/healing:$(DOCKER_TAG) .

.PHONY: docker-push
docker-push: ## Push Docker images to registry
	@echo "Pushing Docker images..."
	$(DOCKER) push $(DOCKER_REPO)/sentinel:$(DOCKER_TAG)
	$(DOCKER) push $(DOCKER_REPO)/consensus:$(DOCKER_TAG)
	$(DOCKER) push $(DOCKER_REPO)/ai-engine:$(DOCKER_TAG)
	$(DOCKER) push $(DOCKER_REPO)/healing:$(DOCKER_TAG)

# Development environment
.PHONY: dev-setup
dev-setup: ## Setup complete development environment
	@echo "Setting up complete development environment..."
	@chmod +x scripts/dev-setup.sh
	@./scripts/dev-setup.sh

.PHONY: dev-start
dev-start: ## Start development stack with Docker Compose
	@echo "Starting development stack..."
	cd $(DEPLOY_DIR)/docker && docker-compose -f docker-compose.dev.yml up -d

.PHONY: dev-stop
dev-stop: ## Stop development stack
	@echo "Stopping development stack..."
	cd $(DEPLOY_DIR)/docker && docker-compose -f docker-compose.dev.yml down

.PHONY: dev-logs
dev-logs: ## Show development stack logs
	@echo "Showing development stack logs..."
	cd $(DEPLOY_DIR)/docker && docker-compose -f docker-compose.dev.yml logs -f

.PHONY: dev-clean
dev-clean: ## Clean development environment
	@echo "Cleaning development environment..."
	cd $(DEPLOY_DIR)/docker && docker-compose -f docker-compose.dev.yml down -v
	$(DOCKER) system prune -f

# Hot reload development
.PHONY: dev-watch
dev-watch: ## Run with hot reload using air
	@echo "Starting development server with hot reload..."
	@if [ ! -f .air.toml ]; then \
		echo "Creating .air.toml configuration..."; \
		echo 'root = "."' > .air.toml; \
		echo 'testdata_dir = "testdata"' >> .air.toml; \
		echo 'tmp_dir = "tmp"' >> .air.toml; \
		echo '' >> .air.toml; \
		echo '[build]' >> .air.toml; \
		echo '  args_bin = ["--config", "configs/sentinel.yaml"]' >> .air.toml; \
		echo '  bin = "./tmp/main"' >> .air.toml; \
		echo '  cmd = "go build -o ./tmp/main ./cmd/sentinel"' >> .air.toml; \
		echo '  delay = 1000' >> .air.toml; \
		echo '  exclude_dir = ["assets", "tmp", "vendor", "testdata", "deployments"]' >> .air.toml; \
		echo '  exclude_file = []' >> .air.toml; \
		echo '  exclude_regex = ["_test.go"]' >> .air.toml; \
		echo '  exclude_unchanged = false' >> .air.toml; \
		echo '  follow_symlink = false' >> .air.toml; \
		echo '  full_bin = ""' >> .air.toml; \
		echo '  include_dir = []' >> .air.toml; \
		echo '  include_ext = ["go", "tpl", "tmpl", "html", "yaml", "yml"]' >> .air.toml; \
		echo '  kill_delay = "0s"' >> .air.toml; \
		echo '  log = "build-errors.log"' >> .air.toml; \
		echo '  send_interrupt = false' >> .air.toml; \
		echo '  stop_on_root = false' >> .air.toml; \
	fi
	@command -v air >/dev/null 2>&1 || { echo "Installing air..."; $(GOGET) github.com/air-verse/air@latest; }
	air -c .air.toml

# Run commands
.PHONY: run-sentinel
run-sentinel: build-sentinel ## Run sentinel node
	@echo "Running sentinel node..."
	./$(BUILD_DIR)/sentinel --config configs/sentinel.yaml

.PHONY: run-all
run-all: build ## Run all components
	@echo "Running all DSN components..."
	@echo "This would start all services in production mode"
	@echo "Use 'make dev-start' for development environment"
	$(DOCKER) push $(DOCKER_REPO)/consensus:$(DOCKER_TAG)
	$(DOCKER) push $(DOCKER_REPO)/ai-engine:$(DOCKER_TAG)
	$(DOCKER) push $(DOCKER_REPO)/healing:$(DOCKER_TAG)

# Kubernetes deployment
.PHONY: deploy-dev
deploy-dev: ## Deploy to development environment
	@echo "Deploying to development..."
	$(HELM) upgrade --install dsn-dev $(DEPLOY_DIR)/helm/dsn \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--values $(DEPLOY_DIR)/helm/dsn/values-dev.yaml \
		--set image.tag=$(DOCKER_TAG)

.PHONY: deploy-staging
deploy-staging: ## Deploy to staging environment
	@echo "Deploying to staging..."
	$(HELM) upgrade --install dsn-staging $(DEPLOY_DIR)/helm/dsn \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--values $(DEPLOY_DIR)/helm/dsn/values-staging.yaml \
		--set image.tag=$(DOCKER_TAG)

.PHONY: deploy-prod
deploy-prod: ## Deploy to production environment
	@echo "Deploying to production..."
	$(HELM) upgrade --install dsn-prod $(DEPLOY_DIR)/helm/dsn \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--values $(DEPLOY_DIR)/helm/dsn/values-production.yaml \
		--set image.tag=$(DOCKER_TAG)

.PHONY: undeploy
undeploy: ## Remove deployment
	@echo "Removing deployment..."
	$(HELM) uninstall dsn-dev -n $(NAMESPACE) || true
	$(HELM) uninstall dsn-staging -n $(NAMESPACE) || true
	$(HELM) uninstall dsn-prod -n $(NAMESPACE) || true

# Development environment
.PHONY: dev-up
dev-up: ## Start development environment
	@echo "Starting development environment..."
	docker-compose -f $(DEPLOY_DIR)/docker-compose/docker-compose.dev.yml up -d

.PHONY: dev-down
dev-down: ## Stop development environment
	@echo "Stopping development environment..."
	docker-compose -f $(DEPLOY_DIR)/docker-compose/docker-compose.dev.yml down

.PHONY: dev-logs
dev-logs: ## Show development environment logs
	docker-compose -f $(DEPLOY_DIR)/docker-compose/docker-compose.dev.yml logs -f

# Monitoring
.PHONY: monitor-up
monitor-up: ## Start monitoring stack
	@echo "Starting monitoring stack..."
	$(KUBECTL) apply -f $(DEPLOY_DIR)/kubernetes/monitoring/

.PHONY: monitor-down
monitor-down: ## Stop monitoring stack
	@echo "Stopping monitoring stack..."
	$(KUBECTL) delete -f $(DEPLOY_DIR)/kubernetes/monitoring/

# Utilities
.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

.PHONY: update-deps
update-deps: ## Update dependencies
	@echo "Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

.PHONY: version
version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

# Default target
.DEFAULT_GOAL := help