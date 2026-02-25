# Changelog

All notable changes to the eBPF Rootkit Detector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release with core detection capabilities
- Syscall hooking detection via kprobes
- Process hiding detection via do_fork monitoring
- File hiding detection via filldir64 timing analysis
- Kernel module tampering detection via load_module monitoring
- Real-time CLI alert display
- Web dashboard with Material Design 3 UI
- JSON API for programmatic access
- Health check endpoint

### Features
- eBPF ring buffer for efficient event communication
- Multiple kprobe attachments for comprehensive monitoring
- Auto-refreshing web interface
- Color-coded alert categorization

### Technical
- Go 1.25.7+ support
- Cilium eBPF library integration
- Linux kernel 4.4+ compatibility (with BTF support)

## Known Limitations

- Requires root privileges for eBPF operations
- Needs BTF-enabled kernel for optimal operation
- Some detection heuristics are simplified for demonstration

## Future Plans

- [ ] Process hiding detection via /proc vs kernel task list comparison
- [ ] Syscall table integrity checking with known-good addresses
- [ ] File integrity monitoring
- [ ] Network connection monitoring
- [ ] Container runtime detection
- [ ] Integration with SIEM systems
- [ ] Alert notifications (Slack, PagerDuty, etc.)
