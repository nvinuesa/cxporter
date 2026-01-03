# cxporter Makefile

# Build variables
BINARY_NAME := cxporter
BUILD_DIR := ./bin
CMD_DIR := ./cmd/cxporter
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildDate=$(BUILD_DATE)"

# Go commands
export GOEXPERIMENT := runtimesecret
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOVET := $(GOCMD) vet

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)

# Run all tests with coverage
.PHONY: test
test:
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@$(GOCMD) tool cover -func=coverage.out | tail -1

# Run unit tests only
.PHONY: test-unit
test-unit:
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@$(GOCMD) tool cover -func=coverage.out | tail -1

# Run bash integration tests
.PHONY: test-integration
test-integration: build
	@echo "Running integration tests..."
	@./test/run_all.sh

# Run all tests (unit + integration)
.PHONY: test-all
test-all: test-unit test-integration

# Run tests with HTML coverage report
.PHONY: test-coverage
test-coverage: test
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Run linter (requires golangci-lint)
.PHONY: lint
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

# Format code
.PHONY: fmt
fmt:
	$(GOFMT) -s -w .

# Vet code
.PHONY: vet
vet:
	$(GOVET) ./...

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Download dependencies
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Verify dependencies
.PHONY: verify
verify:
	$(GOMOD) verify

# Install binary to GOPATH/bin
.PHONY: install
install:
	$(GOCMD) install $(LDFLAGS) $(CMD_DIR)

# Run the application
.PHONY: run
run: build
	$(BUILD_DIR)/$(BINARY_NAME)

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build            - Build the binary to ./bin/"
	@echo "  test             - Run tests with coverage"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run bash integration tests"
	@echo "  test-all         - Run all tests (unit + integration)"
	@echo "  test-coverage    - Run tests and generate HTML coverage report"
	@echo "  lint             - Run golangci-lint"
	@echo "  fmt              - Format code"
	@echo "  vet              - Run go vet"
	@echo "  clean            - Remove build artifacts"
	@echo "  deps             - Download and tidy dependencies"
	@echo "  verify           - Verify dependencies"
	@echo "  install          - Install binary to GOPATH/bin"
	@echo "  run              - Build and run the application"
	@echo "  help             - Show this help"
