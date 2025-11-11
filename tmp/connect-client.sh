#!/bin/bash
set -e

cd /home/jeremy/git/wezterm

export CONFIG_DIR="$(pwd)/tmp/client"
export DATA_DIR="$(pwd)/tmp/client/data"
export WEZTERM_CONFIG_DIR="$CONFIG_DIR"
export XDG_DATA_HOME="$DATA_DIR/share"

mkdir -p "$DATA_DIR/share/wezterm"

echo "Connecting to QUIC domain 'quic_test'..."
echo "Config: $CONFIG_DIR/wezterm.lua"
echo "Data: $DATA_DIR"

RELEASE=""

cargo build --features quic $RELEASE -p wezterm-gui
WEZTERM_LOG=wezterm_client=debug cargo run --features quic $RELEASE -p wezterm -- --config-file "$CONFIG_DIR/wezterm.lua" connect quic_test
