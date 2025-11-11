#!/bin/bash
set -e

cd /home/jeremy/git/wezterm

export CONFIG_DIR="$(pwd)/tmp"
export DATA_DIR="$(pwd)/tmp/data"
export WEZTERM_CONFIG_DIR="$CONFIG_DIR"
export XDG_DATA_HOME="$DATA_DIR/share"

mkdir -p "$DATA_DIR/share/wezterm"
mkdir -p "$DATA_DIR/.local/share"

echo "Generating PKI certificates..."
echo "This will start the server briefly to create certs, then stop it."

# Start server, let it generate PKI, then kill it
cargo run --features quic --release -p wezterm-mux-server -- --config-file "$CONFIG_DIR/wezterm.lua" &
SERVER_PID=$!

sleep 3

kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo "Checking for generated certs..."
ls -la "$DATA_DIR/share/wezterm/pki/quic_test/quic/" 2>/dev/null || echo "Server PKI not found yet"
