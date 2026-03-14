.PHONY: all help kernel daemon tui build clean install fmt lint test \
        ebpf build-nosudo run

# ── Configuration ──────────────────────────────────────────────────────────
KVER     := $(shell uname -r)
KDIR     ?= /lib/modules/$(KVER)/build
RUST_BIN := $(HOME)/.cargo/bin

# Colours
GREEN  := \033[0;32m
YELLOW := \033[1;33m
CYAN   := \033[0;36m
NC     := \033[0m

# ══════════════════════════════════════════════════════════════════════════════
all: help

help:
	@echo ""
	@echo "  rootkit-radar — Build System"
	@echo ""
	@echo "  Targets:"
	@echo "    make kernel        Build the LKM (requires kernel headers)"
	@echo "    make daemon        Build the Rust aggregation daemon"
	@echo "    make tui           Build the Rust Ratatui TUI"
	@echo "    make build         Build everything (kernel + daemon + tui)"
	@echo "    make install       Full install via deploy/install.sh (run as root)"
	@echo "    make clean         Remove all build artefacts"
	@echo ""
	@echo "  Legacy eBPF targets (kept for compatibility):"
	@echo "    make ebpf          Compile eBPF C program"
	@echo "    make build-nosudo  Build Go eBPF loader only"
	@echo "    make fmt           Format Go code"
	@echo "    make lint          Run golangci-lint on Go code"
	@echo "    make test          Run Go tests"
	@echo ""

# ── Phase 1: Kernel Module ─────────────────────────────────────────────────
kernel:
	@echo "$(CYAN)Building kernel module...$(NC)"
	$(MAKE) -C kernel_module KDIR=$(KDIR)
	@echo "$(GREEN)Kernel module built: kernel_module/rootkit_radar.ko$(NC)"

# ── Phase 2: Rust Daemon ───────────────────────────────────────────────────
daemon:
	@echo "$(CYAN)Building Rust daemon...$(NC)"
	cd daemon && cargo build --release
	@echo "$(GREEN)Daemon built: daemon/target/release/rr-daemon$(NC)"

# ── Phase 3: Rust TUI ─────────────────────────────────────────────────────
tui:
	@echo "$(CYAN)Building Rust TUI...$(NC)"
	cd tui && cargo build --release
	@echo "$(GREEN)TUI built: tui/target/release/rr-tui$(NC)"

# ── Build everything ───────────────────────────────────────────────────────
build: kernel daemon tui

# ── Install ────────────────────────────────────────────────────────────────
install:
	@echo "$(YELLOW)Running install script (requires root)...$(NC)"
	sudo bash deploy/install.sh

# ── Clean ──────────────────────────────────────────────────────────────────
clean:
	@echo "$(GREEN)Cleaning all build artefacts...$(NC)"
	-$(MAKE) -C kernel_module KDIR=$(KDIR) clean 2>/dev/null || true
	-cd daemon && cargo clean 2>/dev/null || true
	-cd tui    && cargo clean 2>/dev/null || true
	-rm -rf bin/
	-rm -f detectors/*.o detectors/*.d loader/syscall*
	go clean 2>/dev/null || true

# ── Legacy eBPF / Go targets ───────────────────────────────────────────────
ebpf:
	@echo "$(YELLOW)Compiling eBPF program...$(NC)"
	clang -O2 -target bpf -g -I/usr/include \
	      -c detectors/syscall.c -o detectors/syscall.o
	@echo "$(GREEN)eBPF compilation complete$(NC)"

build-nosudo:
	@echo "$(GREEN)Building Go eBPF loader...$(NC)"
	cd loader && go build -o ../bin/loader main.go

fmt:
	go fmt ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

test:
	go test -v ./...
