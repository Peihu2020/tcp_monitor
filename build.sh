#!/bin/bash
set -e

echo "🧹 Cleaning old builds..."
go clean -cache
rm -f tcp_monitor *_bpfe*

echo "🔄 Generating eBPF code..."
CGO_ENABLED=1 go generate

echo "🔨 Building static binary..."
CGO_ENABLED=1 go build \
  -ldflags '-extldflags "-static"' \
  -tags netgo \
  -o tcp_monitor

echo "✅ Build complete: tcp_monitor"
ls -lh tcp_monitor

echo "🔍 Checking glibc dependencies:"
objdump -T tcp_monitor 2>/dev/null | grep GLIBC || echo "✅ No glibc dependencies!"