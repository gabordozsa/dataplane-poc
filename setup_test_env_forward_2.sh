#!/bin/bash
# Setup script for testing DTLS VPN with network namespaces, with 2 forwarders:
# client -> forwarder_1 -> forwarder_2 -> server

set -e

CLIENT_IP=192.168.100.1

SERVER_IP=192.168.100.2
SERVER_PORT=4433

FORWARD_IP_1_1=192.168.100.3
FORWARD_IP_1_2=192.168.100.4
FORWARD_IP_2_1=192.168.100.5
FORWARD_IP_2_2=192.168.100.6
FORWARD_IN_PORT=5000
FORWARD_OUT_PORT=5010

# Cleanup any existing setup
sudo ip netns del client 2>/dev/null || true
sudo ip netns del server 2>/dev/null || true
sudo ip netns del forward_1 2>/dev/null || true
sudo ip netns del forward_2 2>/dev/null || true
sudo ip link del veth0 2>/dev/null || true
sudo ip link del veth2 2>/dev/null || true
sudo ip link del veth4 2>/dev/null || true

# Exit if cleaning only
[[ "x$1" == "xclean" ]] && { echo "Cleaned up previous setup"; exit 0; }

echo "Setting up network namespaces for TUN/DTLS  testing..."

# Create network namespaces
echo "Creating network namespaces..."
sudo ip netns add client
sudo ip netns add server
sudo ip netns add forward_1
sudo ip netns add forward_2

# Create veth pair to connect the namespaces
echo "Creating veth pair..."
sudo ip link add veth0 type veth peer name veth1
sudo ip link add veth2 type veth peer name veth3
sudo ip link add veth4 type veth peer name veth5

# Move veth interfaces to namespaces
sudo ip link set veth0 netns client
sudo ip link set veth1 netns forward_1
sudo ip link set veth2 netns forward_1
sudo ip link set veth3 netns forward_2
sudo ip link set veth4 netns forward_2
sudo ip link set veth5 netns server

# Configure client namespace
echo "Configuring client namespace..."
sudo ip netns exec client ip addr add ${CLIENT_IP}/24 dev veth0
sudo ip netns exec client ip link set veth0 up
sudo ip netns exec client ip link set lo up

# Configure server namespace
echo "Configuring server namespace..."
sudo ip netns exec server ip addr add ${SERVER_IP}/24 dev veth5
sudo ip netns exec server ip link set veth5 up
sudo ip netns exec server ip link set lo up

# Configure forward_1 namespace
echo "Configuring forward_1 namespace..."
sudo ip netns exec forward_1 ip addr add ${FORWARD_IP_1_1}/24 dev veth1
sudo ip netns exec forward_1 ip link set veth1 up
sudo ip netns exec forward_1 ip addr add ${FORWARD_IP_1_2}/24 dev veth2
sudo ip netns exec forward_1 ip link set veth2 up
sudo ip netns exec forward_1 ip link set lo up
sudo ip netns exec forward_1 route add -host ${CLIENT_IP} dev veth1
sudo ip netns exec forward_1 route add -host ${FORWARD_IP_2_1} dev veth2

# Configure forward_2 namespace
echo "Configuring forward_2 namespace..."
sudo ip netns exec forward_2 ip addr add ${FORWARD_IP_2_1}/24 dev veth3
sudo ip netns exec forward_2 ip link set veth3 up
sudo ip netns exec forward_2 ip addr add ${FORWARD_IP_2_2}/24 dev veth4
sudo ip netns exec forward_2 ip link set veth4 up
sudo ip netns exec forward_2 ip link set lo up
sudo ip netns exec forward_2 route add -host ${FORWARD_IP_1_2} dev veth3
sudo ip netns exec forward_2 route add -host ${SERVER_IP} dev veth4


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
echo "  client    namespace: ${CLIENT_IP} (veth0)"
echo "  server    namespace: ${SERVER_IP} (veth5)"
echo "  forward_1 namespace: ${FORWARD_IP_1_1} (veth1) ${FORWARD_IP_1_2} (veth2)"
echo "  forward_2 namespace: ${FORWARD_IP_2_1} (veth3) ${FORWARD_IP_2_2} (veth4)"
echo ""
echo "To run the server:"
echo "  sudo ip netns exec server ./build/vpn_server 4433 certs/server_cert.pem certs/server_key.pem 10.9.0.254"
echo ""
echo "To run the 1st forwarder:"
echo "  sudo ip netns exec forward_1 ./build/dtls_forwarder ${FORWARD_IN_PORT} ${FORWARD_OUT_PORT}  certs/forwarder_cert.pem certs/forwarder_key.pem  ${FORWARD_IP_2_1} ${FORWARD_IN_PORT}"
echo ""
echo "To run the 2nd forwarder:"
echo "  sudo ip netns exec forward_2 ./build/dtls_forwarder ${FORWARD_IN_PORT} ${FORWARD_OUT_PORT}  certs/forwarder_cert.pem certs/forwarder_key.pem  ${SERVER_IP} ${SERVER_PORT}"
echo ""
echo "To run the client:"
echo "  sudo ip netns exec client ./build/vpn_client ${FORWARD_IP_1_1} ${FORWARD_IN_PORT}  10.8.0.1"
echo ""
echo "Create route for client (-> to make rp_filter happy, i.e. server TUN addr can be accessed via tun0):"
echo "  sudo ip netns exec client ip route add 10.9.0.0/24 dev tun0"
echo "Create route for server (-> to make reply IP from http server to find tun1)):"
echo "  sudo ip netns exec server ip route add 10.8.0.0/24 dev tun1"
echo ""
echo "To test with ping:"
echo "  sudo ip netns exec client ping  10.9.0.254"
echo ""
echo "To run HTTP server in server namespace:"
echo "  sudo ip netns exec server python3 -m http.server --bind 10.9.0.254 2222"
echo ""
echo "To test HTTP (from client namespace):"
echo "  sudo ip netns exec client curl -v http://10.9.0.254:2222"
echo ""
echo "iperf3 server:"
echo "   sudo ip netns exec server iperf3 -s -B 10.9.0.254"
echo ""
echo "iperf3 client:"
echo "   sudo ip netns exec client iperf3 -t 4 -c 10.9.0.254"
echo ""
echo "To cleanup:"
echo "  $0 clean"


# Made with Bob
