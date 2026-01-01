# Build scripts and utilities for Argus

.PHONY: all build build-native build-server build-agent clean test

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build directories
BUILD_DIR=bin
NATIVE_BUILD_DIR=native/build

# Output binaries
SERVER_BINARY=$(BUILD_DIR)/argus-server
AGENT_BINARY=$(BUILD_DIR)/argus-agent

ifeq ($(OS),Windows_NT)
    SERVER_BINARY=$(BUILD_DIR)/argus-server.exe
    AGENT_BINARY=$(BUILD_DIR)/argus-agent.exe
    CMAKE_GENERATOR=-G "Visual Studio 17 2022"
    RM=rmdir /s /q
    MKDIR=mkdir
else
    CMAKE_GENERATOR=
    RM=rm -rf
    MKDIR=mkdir -p
endif

all: build

# Build everything
build: build-native build-server build-agent

# Build native C++ components
build-native:
	@echo "Building native modules..."
	@$(MKDIR) $(NATIVE_BUILD_DIR) 2>nul || true
	cd $(NATIVE_BUILD_DIR) && cmake $(CMAKE_GENERATOR) .. && cmake --build . --config Release

# Build Go server
build-server:
	@echo "Building server..."
	@$(MKDIR) $(BUILD_DIR) 2>nul || true
	$(GOBUILD) -o $(SERVER_BINARY) -v ./cmd/server

# Build Go agent
build-agent:
	@echo "Building agent..."
	@$(MKDIR) $(BUILD_DIR) 2>nul || true
	$(GOBUILD) -o $(AGENT_BINARY) -v ./cmd/agent

# Build with CGO (native module support)
build-cgo: build-native
	@echo "Building with CGO support..."
	CGO_ENABLED=1 $(GOBUILD) -tags cgo -o $(SERVER_BINARY) -v ./cmd/server
	CGO_ENABLED=1 $(GOBUILD) -tags cgo -o $(AGENT_BINARY) -v ./cmd/agent

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run tests
test:
	$(GOTEST) -v ./...

# Clean build artifacts
clean:
	$(GOCLEAN)
	$(RM) $(BUILD_DIR) 2>nul || true
	$(RM) $(NATIVE_BUILD_DIR) 2>nul || true

# Generate TLS certificates (for development)
certs:
	@echo "Generating development certificates..."
	@$(MKDIR) certs 2>nul || true
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout certs/server.key -out certs/server.crt \
		-subj "/CN=localhost/O=Argus"
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout certs/agent.key -out certs/agent.crt \
		-subj "/CN=agent/O=Argus"

# Run server in development mode
run-server: build-server
	$(SERVER_BINARY) --listen :8443 --api :8080

# Run agent in development mode
run-agent: build-agent
	$(AGENT_BINARY) --server localhost:8443

# Docker build
docker-build:
	docker build -t argus-server:latest -f Dockerfile.server .
	docker build -t argus-agent:latest -f Dockerfile.agent .

# Help
help:
	@echo "Argus Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build everything (default)"
	@echo "  build        - Build native modules, server, and agent"
	@echo "  build-native - Build C++ native modules only"
	@echo "  build-server - Build Go server only"
	@echo "  build-agent  - Build Go agent only"
	@echo "  build-cgo    - Build with CGO support for native modules"
	@echo "  deps         - Download Go dependencies"
	@echo "  test         - Run tests"
	@echo "  clean        - Remove build artifacts"
	@echo "  certs        - Generate development TLS certificates"
	@echo "  run-server   - Build and run server"
	@echo "  run-agent    - Build and run agent"
	@echo "  docker-build - Build Docker images"
