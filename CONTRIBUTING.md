# Contributing to eBPF Rootkit Detector

Thank you for your interest in contributing to the eBPF Rootkit Detector!

## Development Process

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
4. **Make** your changes
5. **Test** your changes
6. **Commit** with clear commit messages
7. **Push** to your fork
8. **Submit** a Pull Request

## Code Style Guidelines

### Go
- Follow standard Go conventions
- Use `gofmt` for formatting: `go fmt ./...`
- Run `go vet` before committing: `go vet ./...`
- Add tests for new functionality

### eBPF C Programs
- Use proper SEC() macros for program sections
- Include Linux kernel headers first
- Document complex logic with comments
- Test on multiple kernel versions when possible

## Development Setup

```bash
# Install dependencies
go mod download

# Build eBPF programs
clang -O2 -target bpf -g -c detectors/syscall.c -o detectors/syscall.o

# Build Go loader
go build -o bin/loader ./loader/main.go

# Run tests
go test ./...
```

## Testing

```bash
# Run all tests
go test -v ./...

# Test with coverage
go test -cover ./...

# Test eBPF compilation
clang -O2 -target bpf -g -c detectors/syscall.c -o detectors/syscall.o
```

## Reporting Issues

When reporting issues, please include:
- Operating system and kernel version
- Go version
- Steps to reproduce
- Expected vs actual behavior

## Security Considerations

- Never commit secrets or credentials
- Validate all user inputs
- Follow least privilege principle
- Test in isolated environments first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
