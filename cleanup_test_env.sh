#!/bin/bash
# Cleanup script for DTLS VPN test environment

echo "Cleaning up network namespaces..."

# Delete network namespaces (this also removes interfaces inside them)
sudo ip netns del client 2>/dev/null || true
sudo ip netns del server 2>/dev/null || true

# Delete veth pair if it still exists
sudo ip link del veth0 2>/dev/null || true

echo "Cleanup complete!"

# Made with Bob
