#!/bin/bash
# Setup script for testing DTLS VPN with network namespaces

set -e

echo "Setting up network namespaces for DTLS VPN testing..."

CLIENT_IP=192.168.100.1
SERVER_IP=192.168.100.2

# Cleanup any existing setup
sudo ip netns del client 2>/dev/null || true
sudo ip netns del server 2>/dev/null || true
sudo ip link del veth0 2>/dev/null || true

# Create network namespaces
echo "Creating network namespaces..."
sudo ip netns add client
sudo ip netns add server

# Create veth pair to connect the namespaces
echo "Creating veth pair..."
sudo ip link add veth0 type veth peer name veth1

# Move veth interfaces to namespaces
sudo ip link set veth0 netns client
sudo ip link set veth1 netns server

# Configure client namespace
echo "Configuring client namespace..."
sudo ip netns exec client ip addr add ${CLIENT_IP}/24 dev veth0
sudo ip netns exec client ip link set veth0 up
sudo ip netns exec client ip link set lo up

# Configure server namespace
echo "Configuring server namespace..."
sudo ip netns exec server ip addr add ${SERVER_IP}/24 dev veth1
sudo ip netns exec server ip link set veth1 up
sudo ip netns exec server ip link set lo up

# Enable IP forwarding in both namespaces
#sudo ip netns exec client sysctl -w net.ipv4.ip_forward=1 > /dev/null
#sudo ip netns exec server sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Disable reverse path filtering
#sudo ip netns exec client sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null
#sudo ip netns exec server sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null

echo ""
echo "Network namespaces setup complete!"
echo ""
echo "Network topology:"
echo "  client namespace: ${CLIENT_IP} (veth0)"
echo "  server namespace: ${SERVER_IP} (veth1)"
echo ""
echo "To run the server:"
echo "  sudo ip netns exec server ./build/server 4433 certs/server_cert.pem certs/server_key.pem 10.9.0.254"
echo ""
echo "To run the client (in another terminal):"
echo "  sudo ip netns exec client ./build/client ${SERVER_IP} 4433 10.8.0.1"
echo ""
echo "Create route for client (-> to make rp_filter happy, i.e. server TUN addr can be accessed via tun0):"
echo "  sudo ip netns exec client ip route add 10.9.0.0/24 dev tun0"
echo "Create route for server (-> to make reply IP from http server to find tun1)):"
echo "  sudo ip netns exec server ip route add 10.8.0.0/24 dev tun1"
echo""
echo "To test with ping (after VPN is connected):"
echo "  sudo ip netns exec client ping  10.9.0.254"
echo ""
echo "To run HTTP server in server namespace:"
echo "  sudo ip netns exec server python3 -m http.server --bind 10.9.0.254 2222"
echo ""
echo "To test HTTP (from client namespace):"
echo "  sudo ip netns exec client curl -v --interface tun0 http://10.9.0.254:2222"
echo ""
echo "To cleanup:"
echo "  ./cleanup_test_env.sh"
echo ""

# Made with Bob
