#!/bin/bash

# Script to generate self-signed certificates for testing

echo "Generating self-signed certificates for DTLS VPN testing..."

# Generate CA certificate and key (for signing other certificates)
echo "Generating CA certificate..."
openssl req -x509 -newkey rsa:2048 -keyout ca_key.pem -out ca_cert.pem \
    -days 365 -nodes -subj "/CN=DTLS-VPN-CA/O=DTLS VPN/C=US"

if [ $? -eq 0 ]; then
    echo "✓ Generated ca_cert.pem and ca_key.pem"
else
    echo "✗ Failed to generate CA certificates"
    exit 1
fi

# Generate server certificate and key
echo "Generating server certificate..."
openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem \
    -days 365 -nodes -subj "/CN=vpn-server/O=DTLS VPN/C=US"

if [ $? -eq 0 ]; then
    echo "✓ Generated server_cert.pem and server_key.pem"
else
    echo "✗ Failed to generate server certificates"
    exit 1
fi

# Generate client certificate and key (optional, for mutual TLS)
echo "Generating client certificate..."
openssl req -x509 -newkey rsa:2048 -keyout client_key.pem -out client_cert.pem \
    -days 365 -nodes -subj "/CN=vpn-client/O=DTLS VPN/C=US"

if [ $? -eq 0 ]; then
    echo "✓ Generated client_cert.pem and client_key.pem"
else
    echo "✗ Failed to generate client certificates"
    exit 1
fi

# Generate forwarder certificate and key (acts as both server and client)
echo "Generating forwarder certificate..."
openssl req -x509 -newkey rsa:2048 -keyout forwarder_key.pem -out forwarder_cert.pem \
    -days 365 -nodes -subj "/CN=dtls-forwarder/O=DTLS VPN/C=US"

if [ $? -eq 0 ]; then
    echo "✓ Generated forwarder_cert.pem and forwarder_key.pem"
else
    echo "✗ Failed to generate forwarder certificates"
    exit 1
fi

# Set appropriate permissions
chmod 600 *.pem

echo ""
echo "Certificates generated successfully!"
echo ""
echo "CA certificate:        ca_cert.pem"
echo "CA key:                ca_key.pem"
echo "Server certificate:    server_cert.pem"
echo "Server key:            server_key.pem"
echo "Client certificate:    client_cert.pem"
echo "Client key:            client_key.pem"
echo "Forwarder certificate: forwarder_cert.pem"
echo "Forwarder key:         forwarder_key.pem"
echo ""
echo "To use:"
echo "  Server:    ./vpn_server 4433 certs/server_cert.pem certs/server_key.pem"
echo "  Client:    ./vpn_client <server_ip> 4433 [tun_ip] [certs/ca_cert.pem]"
echo "  Forwarder: ./dtls_forwarder <inbound_port> <outbound_port> <target_host> <target_port> \\"
echo "                              certs/forwarder_cert.pem certs/forwarder_key.pem certs/ca_cert.pem"

# Made with Bob
