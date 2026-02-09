# eBPF Rootkit Detector

A lightweight kernel-level monitor that detects rootkit-like behavior in real-time using eBPF with minimal CPU overhead and no custom kernel module required.

## 🎯 Objectives

This detector monitors for suspicious kernel-level activities that normal programs never perform:

- **Syscall hooking detection** - Identifies tampered syscall tables
- **Process hiding detection** - Finds hidden processes not visible in /proc
- **File hiding detection** - Detects directory enumeration filtering 
- **Module tampering detection** - Monitors unauthorized kernel module loading

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   eBPF Programs │───▶│  Ring Buffer     │───▶│   Go Userspace  │
│   (Kernel)      │    │  (Communication) │    │   Loader/API    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
    ┌────▼────┐             ┌─────▼─────┐             ┌───▼───┐
    │Kprobes │             │   Events  │             │ CLI   │
    │Trace   │             │  Processing│             │ Web UI│
    └─────────┘             └───────────┘             └───────┘
```

## 🚀 Quick Start

### Prerequisites

- Linux kernel with eBPF support (kernel 4.4+)
- Go 1.25.7+
- clang (for eBPF compilation)
- Root privileges (required for eBPF)

### Build & Run

```bash
# Clone the repository
git clone <repo-url>
cd rootkit-detector

# Build eBPF programs
clang -O2 -target bpf -c detectors/syscall.c -o detectors/syscall.o

# Build Go loader
go build -o bin/loader ./loader/main.go

# Run with elevated privileges
sudo ./bin/loader
```

### Test Installation

```bash
# Run comprehensive tests
sudo ./test.sh

# Check web interface
curl http://localhost:8080/alerts
```

## 📊 Features

### Real-time Detection

1. **Syscall Hooking Detection**
   - Monitors syscall table integrity
   - Detects unusual syscall numbers
   - Alerts on high syscall frequency

2. **Process Hiding Detection**
   - Tracks process creation via do_fork
   - Monitors rapid process spawning
   - Detects kernel filesystem access

3. **File Hiding Detection**
   - Times directory enumeration operations
   - Detects filldir64 delays (filtering indicator)
   - Monitors suspicious file access patterns

4. **Module Tampering Detection**
   - Monitors load_module calls
   - Validates module loading processes
   - Detects unauthorized kernel modifications

### User Interface

- **CLI Monitoring** - Real-time alerts in terminal
- **Web Dashboard** - Interactive web interface at http://localhost:8080
- **JSON API** - RESTful endpoints for integration

## 🔧 Configuration

### Build Commands

```bash
# Build main application
go build -o bin/loader ./loader/main.go

# Compile eBPF program
clang -O2 -target bpf -c detectors/syscall.c -o detectors/syscall.o

# Run tests
go test ./...
```

### API Endpoints

- `GET /` - Web dashboard
- `GET /alerts` - JSON list of recent security alerts
- `GET /health` - Health check endpoint

## 📈 Performance

Designed for minimal overhead:
- **Memory**: ~2MB ring buffer
- **CPU**: <1% on idle systems
- **Latency**: Sub-millisecond detection
- **Impact**: Negligible on normal operations

## 🛡️ Security Considerations

- eBPF programs are kernel-verified and sandboxed
- No persistent kernel modifications
- Read-only monitoring (non-invasive)
- Safe resource limits enforced
- Graceful error handling

## 🧪 Testing Scenarios

The detector responds to:

```bash
# Process hiding tests
bash -c 'for i in {1..100}; do /bin/true; done'

# File hiding tests  
find /proc -name comm > /dev/null

# Module loading tests
sudo insmod test_module.ko  # (if available)

# Suspicious execve tests
/bin/cat /proc/version
```

## 📋 Event Types

| Type | ID | Description |
|------|----|-------------|
| SYSCALL_HOOK | 1 | Syscall table tampering detected |
| PROCESS_HIDE | 2 | Process hiding activity detected |
| FILE_HIDE | 3 | File hiding behavior detected |
| MODULE_TAMPER | 4 | Kernel module tampering detected |

## 🔄 Production Deployment

### Systemd Service

```ini
[Unit]
Description=eBPF Rootkit Detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rootkit-detector
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

### Monitoring

```bash
# Service logs
journalctl -u rootkit-detector -f

# API monitoring
curl -s http://localhost:8080/alerts | jq '.total'

# Process monitoring
ps aux | grep loader
```

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Solution: Run with sudo
   sudo ./bin/loader
   ```

2. **eBPF Verifier Errors**
   ```bash
   # Check kernel logs
   sudo dmesg | grep -i ebpf
   
   # Update eBPF program compilation
   clang -O2 -target bpf -c detectors/syscall.c -o detectors/syscall.o
   ```

3. **Missing bpffs**
   ```bash
   sudo mount -t bpf bpf /sys/fs/bpf/
   ```

4. **API Not Accessible**
   ```bash
   # Check port availability
   netstat -tlnp | grep 8080
   
   # Verify service is running
   ps aux | grep loader
   ```

## 📚 Development

### Project Structure

```
rootkit-detector/
├── detectors/
│   ├── syscall.c      # eBPF C programs
│   └── syscall.o      # Compiled eBPF bytecode
├── loader/
│   └── main.go        # Go userspace loader
├── bin/
│   └── loader         # Compiled binary
├── test.sh            # Test script
├── AGENTS.md          # Development guidelines
└── README.md          # This file
```

### Adding New Detectors

1. Create eBPF program in `detectors/`
2. Add kprobe attachment in `loader/main.go`
3. Update event types and handling
4. Test with `./test.sh`

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

## 🔗 Related Projects

- [Cilium eBPF](https://github.com/cilium/ebpf) - eBPF Go library
- [Tracee](https://github.com/aquasecurity/tracee) - Runtime security
- [Falco](https://github.com/falcosecurity/falco) - Cloud native runtime security

---

**⚠️ Disclaimer**: This tool is for educational and defensive security purposes only. Ensure proper authorization before monitoring production systems.