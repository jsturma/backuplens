.PHONY: all build clean install deps test help
.DEFAULT_GOAL := help

# Build configuration
GO_VERSION := 1.21
BUILD_DIR := ./bin
SERVICES := pipeline-go yara-scanner clamav-updater
TOOLS := entropy-map

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)BackupLens Build System$(NC)"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build          # Build all services"
	@echo "  make build SERVICE=pipeline-go  # Build specific service"
	@echo "  make install       # Build and install to /usr/local/bin"
	@echo "  make clean         # Remove build artifacts"

all: deps build ## Build all services (default)

deps: ## Download Go dependencies for all services
	@echo "$(GREEN)Downloading dependencies...$(NC)"
	@for service in $(SERVICES); do \
		echo "  - $$service"; \
		(cd services/$$service && go mod download) || exit 1; \
	done

build: ## Build all services and tools
	@echo "$(GREEN)Building services...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@failed=0; \
	for service in $(SERVICES); do \
		echo "  Building $$service..."; \
		if (cd services/$$service && go build -o ../../$(BUILD_DIR)/$$service -ldflags="-s -w" .); then \
			echo "  ✓ $$service built successfully"; \
		else \
			echo "  ✗ $$service build failed"; \
			failed=$$((failed + 1)); \
		fi; \
	done; \
	echo "$(GREEN)Building tools...$(NC)"; \
	for tool in $(TOOLS); do \
		echo "  Building $$tool..."; \
		if (cd tools/analyze && go build -o ../../$(BUILD_DIR)/$$tool $$tool.go); then \
			echo "  ✓ $$tool built successfully"; \
		else \
			echo "  ✗ $$tool build failed"; \
			failed=$$((failed + 1)); \
		fi; \
	done; \
	if [ $$failed -eq 0 ]; then \
		echo "$(GREEN)Build complete! Binaries in $(BUILD_DIR)/$(NC)"; \
	else \
		echo "$(YELLOW)Build completed with $$failed error(s). Some services may require additional dependencies.$(NC)"; \
		echo "$(YELLOW)For yara-scanner, install YARA: brew install yara (macOS) or apt-get install libyara-dev (Linux)$(NC)"; \
		exit 1; \
	fi

build-service: ## Build a specific service (use SERVICE=name)
	@if [ -z "$(SERVICE)" ]; then \
		echo "$(YELLOW)Error: SERVICE variable not set$(NC)"; \
		echo "Usage: make build-service SERVICE=pipeline-go"; \
		exit 1; \
	fi
	@echo "$(GREEN)Building $(SERVICE)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@cd services/$(SERVICE) && \
	go build -o ../../$(BUILD_DIR)/$(SERVICE) -ldflags="-s -w" .
	@echo "$(GREEN)$(SERVICE) built in $(BUILD_DIR)/$(NC)"

install: build ## Install all services to /usr/local/bin
	@echo "$(GREEN)Installing services...$(NC)"
	@sudo cp $(BUILD_DIR)/* /usr/local/bin/
	@echo "$(GREEN)Installation complete!$(NC)"

clean: ## Remove build artifacts
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR)
	@for service in $(SERVICES); do \
		(cd services/$$service && go clean) || true; \
	done
	@echo "$(GREEN)Clean complete!$(NC)"

test: ## Run tests for all services
	@echo "$(GREEN)Running tests...$(NC)"
	@for service in $(SERVICES); do \
		echo "  Testing $$service..."; \
		(cd services/$$service && go test ./...) || exit 1; \
	done

fmt: ## Format all Go code
	@echo "$(GREEN)Formatting code...$(NC)"
	@for service in $(SERVICES); do \
		(cd services/$$service && go fmt ./...) || exit 1; \
	done

vet: ## Run go vet on all services
	@echo "$(GREEN)Running go vet...$(NC)"
	@for service in $(SERVICES); do \
		echo "  Checking $$service..."; \
		(cd services/$$service && go vet ./...) || exit 1; \
	done

lint: fmt vet ## Run formatting and vetting

# Service-specific targets
pipeline-go: ## Build pipeline-go service
	@$(MAKE) build-service SERVICE=pipeline-go

yara-scanner: ## Build yara-scanner service
	@$(MAKE) build-service SERVICE=yara-scanner

clamav-updater: ## Build clamav-updater service
	@$(MAKE) build-service SERVICE=clamav-updater

entropy-map: ## Build entropy-map tool
	@echo "$(GREEN)Building entropy-map...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@cd tools/analyze && go build -o ../../$(BUILD_DIR)/entropy-map entropy-map.go
	@echo "$(GREEN)entropy-map built in $(BUILD_DIR)/$(NC)"

# Container management targets
podman-up: ## Start services with Podman Compose
	@if command -v podman-compose >/dev/null 2>&1; then \
		podman-compose -f podman-compose.yml up -d; \
	elif command -v podman >/dev/null 2>&1 && command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_PROJECT_NAME=backuplens docker-compose -f podman-compose.yml up -d; \
	else \
		echo "$(YELLOW)Error: podman-compose or podman+docker-compose not found$(NC)"; \
		exit 1; \
	fi

podman-down: ## Stop services with Podman Compose
	@if command -v podman-compose >/dev/null 2>&1; then \
		podman-compose -f podman-compose.yml down; \
	elif command -v podman >/dev/null 2>&1 && command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_PROJECT_NAME=backuplens docker-compose -f podman-compose.yml down; \
	else \
		echo "$(YELLOW)Error: podman-compose or podman+docker-compose not found$(NC)"; \
		exit 1; \
	fi

podman-logs: ## View logs with Podman Compose
	@if command -v podman-compose >/dev/null 2>&1; then \
		podman-compose -f podman-compose.yml logs -f; \
	elif command -v podman >/dev/null 2>&1 && command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_PROJECT_NAME=backuplens docker-compose -f podman-compose.yml logs -f; \
	else \
		echo "$(YELLOW)Error: podman-compose or podman+docker-compose not found$(NC)"; \
		exit 1; \
	fi

docker-up: ## Start services with Docker Compose
	@docker-compose up -d

docker-down: ## Stop services with Docker Compose
	@docker-compose down

docker-logs: ## View logs with Docker Compose
	@docker-compose logs -f

