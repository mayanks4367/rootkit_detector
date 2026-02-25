.PHONY: all build test clean ebpf build-ebpf run help install-deps

# Build configuration
BINARY_NAME=loader
BIN_DIR=bin
DETECTORS_DIR=detectors
LOADER_DIR=loader

# Colors
GREEN=\033[0;32m
YELLOW=\033[1;33m
NC=\033[0m

all: help

help:
	@echo "eBPF Rootkit Detector - Build Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build the Go loader (requires sudo for eBPF)"
	@echo "  build-nosudo   Build without requiring sudo"
	@echo "  ebpf          Compile eBPF programs"
	@echo "  test          Run Go tests"
	@echo "  lint          Run golangci-lint"
	@echo "  fmt           Format Go code"
	@echo "  vet           Run go vet"
	@echo "  clean         Remove build artifacts"
	@echo "  run           Build and run the detector"
	@echo "  install-deps  Install required dependencies"
	@echo ""

build: build-ebpf
	@echo "$(GREEN)Building Go loader...$(NC)"
	cd $(LOADER_DIR) && go build -o ../$(BIN_DIR)/$(BINARY_NAME) main.go

build-nosudo:
	@echo "$(GREEN)Building Go loader (no eBPF compile)...$(NC)"
	cd $(LOADER_DIR) && go build -o ../$(BIN_DIR)/$(BINARY_NAME) main.go

ebpf:
	@echo "$(YELLOW)Compiling eBPF programs...$(NC)"
	clang -O2 -target bpf -g -I/usr/include -c $(DETECTORS_DIR)/syscall.c -o $(DETECTORS_DIR)/syscall.o
	@echo "$(GREEN)eBPF compilation complete$(NC)"

test:
	@echo "$(GREEN)Running tests...$(NC)"
	go test -v ./...

lint:
	@echo "$(GREEN)Running linter...$(NC)"
	golangci-lint run ./...

fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	go fmt ./...

vet:
	@echo "$(GREEN)Running go vet...$(NC)"
	go vet ./...

clean:
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	rm -rf $(BIN_DIR)
	rm -f $(DETECTORS_DIR)/*.o
	rm -f $(DETECTORS_DIR)/*.d
	rm -f $(LOADER_DIR)/syscall*
	go clean

run: build
	@echo "$(GREEN)Running detector...$(NC)"
	sudo ./$(BIN_DIR)/$(BINARY_NAME)

install-deps:
	@echo "$(GREEN)Installing dependencies...$(NC)"
	go mod download
	@echo "$(GREEN)Dependencies installed$(NC)"
	@echo ""
	@echo "You may need to install:"
	@echo "  - clang (for eBPF compilation)"
	@echo "  - golangci-lint (for linting)"
