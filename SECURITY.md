# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within this project, please send an email to [INSERT EMAIL]. All security vulnerabilities will be promptly addressed.

Please include the following information:
- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code
- Any special configuration required to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue

## Security Considerations

### Elevated Privileges Required

This tool requires root privileges to:
- Load eBPF programs into the kernel
- Attach kprobes to kernel functions
- Access kernel data structures

**Use only on systems you control or have explicit authorization to monitor.**

### Intended Use

This detector is designed for:
- Defensive security monitoring
- System administrators monitoring their own infrastructure
- Security research and analysis

**Do not use this tool for:**
- Unauthorized monitoring of systems you don't own
- Bypassing security controls
- Attacking or exploiting systems

### Kernel Impact

- eBPF programs are verified by the kernel before execution
- Programs that don't pass verification are rejected
- eBPF has built-in resource limits to prevent abuse
- All operations are read-only (monitoring only)

### Best Practices

1. **Run in containers** when possible for isolation
2. **Limit network exposure** of the web API
3. **Use authentication** for production deployments
4. **Review alerts** before taking action
5. **Keep updated** with latest security patches
