#!/bin/bash
cd /home/jeremy/git/wezterm

echo "Killing mux server and GUI..."
killall wezterm-mux-server wezterm-gui 2>/dev/null || true
sleep 1

echo "Cleaning server and client data directories..."
rm -rf tmp/server/data
rm -rf tmp/client/data

echo "Done."
