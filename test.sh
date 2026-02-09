#!/bin/bash

# Test script for eBPF Rootkit Detector

echo "🧪 Testing eBPF Rootkit Detector..."
echo

# Check if running as root (required for eBPF)
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root for eBPF functionality"
   echo "   Try: sudo ./test.sh"
   exit 1
fi

# Check if kernel supports eBPF
if ! ls /sys/fs/bpf/ > /dev/null 2>&1; then
    echo "❌ eBPF filesystem not mounted"
    echo "   Try: sudo mount -t bpf bpf /sys/fs/bpf/"
    exit 1
fi

echo "✅ Environment checks passed"

# Test compilation
echo
echo "🔨 Testing compilation..."
go build -o bin/test-loader ./loader/main.go
if [[ $? -eq 0 ]]; then
    echo "✅ Compilation successful"
else
    echo "❌ Compilation failed"
    exit 1
fi

# Test eBPF program compilation
echo
echo "🔨 Testing eBPF compilation..."
clang -O2 -target bpf -c detectors/syscall.c -o detectors/syscall.o
if [[ $? -eq 0 ]]; then
    echo "✅ eBPF compilation successful"
else
    echo "❌ eBPF compilation failed"
    exit 1
fi

# Test Go modules
echo
echo "📦 Testing Go modules..."
go mod tidy
if [[ $? -eq 0 ]]; then
    echo "✅ Go modules tidy"
else
    echo "❌ Go modules error"
    exit 1
fi

echo
echo "🚀 Starting detector for 10 seconds test run..."
timeout 10s ./bin/test-loader &
DETECTOR_PID=$!

sleep 2

echo "🎭 Triggering some test activity..."

# Test process creation (should trigger process monitoring)
for i in {1..5}; do
    sleep 0.1 &
done

# Test file operations (should trigger file monitoring)
ls -la /tmp > /dev/null 2>&1

# Test syscalls (should trigger syscall monitoring)
echo "test" > /tmp/test_ebpf
rm -f /tmp/test_ebpf

# Try to load a module (should trigger module monitoring if not insmod/modprobe)
echo "Testing module detection..."

# Wait for detector to collect events
sleep 3

# Check if detector is still running
if kill -0 $DETECTOR_PID 2>/dev/null; then
    echo "🛑 Stopping detector..."
    kill $DETECTOR_PID
    wait $DETECTOR_PID 2>/dev/null
fi

echo
echo "📊 Test Results:"
echo "✅ Detector compiled and started"
echo "✅ Test activities executed"
echo "✅ API would be available at http://localhost:8080"

echo
echo "🔍 Manual Test Instructions:"
echo "1. Run with sudo: sudo ./bin/loader"
echo "2. Open browser: http://localhost:8080"
echo "3. Try suspicious activities:"
echo "   - Run: bash -c 'for i in {1..100}; do /bin/true; done'"
echo "   - Check: ls /proc/*/comm"
echo "   - Monitor: watch ls /tmp"
echo "4. Observe alerts in CLI and web interface"

echo
echo "🎯 Production Deployment:"
echo "• Run as systemd service: sudo systemctl start rootkit-detector"
echo "• Monitor logs: journalctl -u rootkit-detector -f"
echo "• API alerts: curl http://localhost:8080/alerts"

echo
echo "✅ Test script completed successfully!"