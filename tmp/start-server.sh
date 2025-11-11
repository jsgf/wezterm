#!/bin/bash
set -e

cd /home/jeremy/git/wezterm

export CONFIG_DIR="$(pwd)/tmp/server"
export DATA_DIR="$(pwd)/tmp/server/data"
export WEZTERM_CONFIG_DIR="$CONFIG_DIR"
export XDG_DATA_HOME="$DATA_DIR/share"

mkdir -p "$DATA_DIR/share/wezterm"

echo "Killing any existing servers..."
killall wezterm-mux-server 2>/dev/null || true
sleep 1

echo "Starting QUIC mux server..."
echo "Config: $CONFIG_DIR/wezterm.lua"
echo "Data: $DATA_DIR"

RELEASE=""

WEZTERM_LOG=wezterm_mux_server::quic_server=debug,wezterm_mux_server_impl=debug cargo run --features quic $RELEASE -p wezterm-mux-server -- --config-file "$CONFIG_DIR/wezterm.lua"
