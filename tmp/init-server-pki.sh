#!/bin/bash
# Initialize server PKI with isolated certs
set -e

SERVER_PKI_DIR="$(pwd)/tmp/server/data/pki"
mkdir -p "$SERVER_PKI_DIR"

echo "Generating server PKI certs in $SERVER_PKI_DIR..."

# Use the config package's pki generation by running the server briefly
# to force PKI initialization, then copy certs to server-specific dir
export WEZTERM_CONFIG_DIR="$(pwd)/tmp/server"
export XDG_DATA_HOME="$(pwd)/tmp/server/data/share"
export XDG_RUNTIME_DIR="$(pwd)/tmp/server/data/runtime"

mkdir -p "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"

# Start server, wait for PKI to be generated, then kill it
timeout 3 cargo run --features quic --release -p wezterm-mux-server -- --config-file "$(pwd)/tmp/server/wezterm.lua" 2>&1 | grep -E "PKI|listening" || true
sleep 1

# Copy generated PKI to server's isolated directory
if [ -d "$XDG_RUNTIME_DIR/wezterm/pki" ]; then
  cp -v "$XDG_RUNTIME_DIR/wezterm/pki"/* "$SERVER_PKI_DIR/" 2>/dev/null || true
  echo "Copied PKI certs to $SERVER_PKI_DIR"
else
  echo "WARNING: PKI not generated in expected location"
fi

ls -la "$SERVER_PKI_DIR/" || echo "No certs generated"
