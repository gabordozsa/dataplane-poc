#!/bin/bash

# Script to generate self-signed certificates for testing

echo "Generating self-signed certificates for DTLS VPN testing..."

# Generate server certificate and key
openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem \
    -days 365 -nodes -subj "/CN=vpn-server/O=DTLS VPN/C=US"

if [ $? -eq 0 ]; then
    echo "✓ Generated server_cert.pem and server_key.pem"
else
    echo "✗ Failed to generate server certificates"
    exit 1
fi

# Generate client certificate and key (optional, for mutual TLS)
openssl req -x509 -newkey rsa:2048 -keyout client_key.pem -out client_cert.pem \
    -days 365 -nodes -subj "/CN=vpn-client/O=DTLS VPN/C=US"

if [ $? -eq 0 ]; then
    echo "✓ Generated client_cert.pem and client_key.pem"
else
    echo "✗ Failed to generate client certificates"
    exit 1
fi

# Set appropriate permissions
chmod 600 *.pem

echo ""
echo "Certificates generated successfully!"
echo ""
echo "Server certificate: server_cert.pem"
echo "Server key:         server_key.pem"
echo "Client certificate: client_cert.pem"
echo "Client key:         client_key.pem"
echo ""
echo "To use:"
echo "  Server: ./vpn_server 4433 certs/server_cert.pem certs/server_key.pem"
echo "  Client: ./vpn_client <server_ip> 4433"

# Made with Bob
