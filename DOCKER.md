# Docker Deployment Guide for DTLS VPN

This guide explains how to build and run the DTLS VPN server and client using Docker.

## Prerequisites

- Docker Engine 20.10 or later
- Docker Compose 1.29 or later
- Linux host with TUN/TAP support (`/dev/net/tun`)
- Root/sudo access for network capabilities

## Quick Start with Docker Compose

### 1. Generate Certificates

First, generate the required SSL certificates:

```bash
cd certs
./generate_certs.sh
cd ..
```

### 2. Build and Run

```bash
# Build and start both server and client
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build
```

### 3. View Logs

```bash
# View server logs
docker-compose logs -f vpn-server

# View client logs
docker-compose logs -f vpn-client
```

### 4. Test the VPN

```bash
# Enter client container
docker exec -it dtls-vpn-client bash

# Ping server's VPN IP
ping -I tun0 10.9.0.254

# Test HTTP (if server is running a service)
curl --interface tun0 http://10.9.0.254:8080
```

### 5. Stop and Clean Up

```bash
# Stop containers
docker-compose down

# Remove images
docker-compose down --rmi all
```

## Manual Docker Build and Run

### Build Images

```bash
# Build server image
docker build -f Dockerfile.server -t dtls-vpn-server:latest .

# Build client image
docker build -f Dockerfile.client -t dtls-vpn-client:latest .
```

### Run Server

```bash
docker run -d \
  --name dtls-vpn-server \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 4433:4433/udp \
  dtls-vpn-server:latest
```

### Run Client

```bash
docker run -d \
  --name dtls-vpn-client \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  dtls-vpn-client:latest \
  ./client <server-ip> 4433 10.8.0.1
```

Replace `<server-ip>` with the actual server IP address.

## Docker Image Details

### Server Image (Dockerfile.server)

**Base Image:** Ubuntu 22.04

**Build Dependencies:**
- build-essential
- cmake
- libssl-dev
- liburing-dev
- pkg-config

**Runtime Dependencies:**
- libssl3
- liburing2
- iproute2
- iptables

**Exposed Ports:**
- 4433/udp (DTLS)

**Default Command:**
```bash
./server 4433 certs/server_cert.pem certs/server_key.pem 10.9.0.254
```

### Client Image (Dockerfile.client)

**Base Image:** Ubuntu 22.04

**Build Dependencies:**
- build-essential
- cmake
- libssl-dev
- liburing-dev
- pkg-config

**Runtime Dependencies:**
- libssl3
- liburing2
- iproute2
- iputils-ping
- curl

**Default Command:**
```bash
./client server 4433 10.8.0.1
```

## Required Capabilities and Devices

Both containers require:

1. **NET_ADMIN capability**: For creating and configuring TUN devices
   ```bash
   --cap-add=NET_ADMIN
   ```

2. **TUN device access**: For VPN tunnel creation
   ```bash
   --device=/dev/net/tun
   ```

## Network Configuration

### Docker Compose Network

The `docker-compose.yml` creates a bridge network:
- Network: `172.20.0.0/24`
- Server: `172.20.0.10`
- Client: `172.20.0.20`

### VPN Tunnel IPs

- Server TUN IP: `10.9.0.254/24`
- Client TUN IP: `10.8.0.1/24`

## Customization

### Change Server Port

Edit `docker-compose.yml`:
```yaml
services:
  vpn-server:
    ports:
      - "5000:5000/udp"  # Change port
    command: ["./server", "5000", "certs/server_cert.pem", "certs/server_key.pem", "10.9.0.254"]
```

### Change VPN Subnet

Edit the command arguments:
```yaml
services:
  vpn-server:
    command: ["./server", "4433", "certs/server_cert.pem", "certs/server_key.pem", "10.10.0.254"]
  vpn-client:
    command: ["./client", "172.20.0.10", "4433", "10.10.0.1"]
```

### Use Custom Certificates

Mount your certificates as volumes:
```yaml
services:
  vpn-server:
    volumes:
      - ./my-certs:/app/certs:ro
    command: ["./server", "4433", "certs/my-server.pem", "certs/my-key.pem", "10.9.0.254"]
```

## Troubleshooting

### TUN Device Not Available

**Error:** `Failed to open /dev/net/tun`

**Solution:**
1. Ensure `/dev/net/tun` exists on host:
   ```bash
   ls -l /dev/net/tun
   ```

2. Load TUN module if missing:
   ```bash
   sudo modprobe tun
   ```

3. Verify container has device access:
   ```bash
   docker exec dtls-vpn-server ls -l /dev/net/tun
   ```

### Permission Denied

**Error:** `Permission denied` when creating TUN device

**Solution:**
Ensure container has NET_ADMIN capability:
```bash
docker run --cap-add=NET_ADMIN --device=/dev/net/tun ...
```

### Connection Refused

**Error:** Client cannot connect to server

**Solution:**
1. Check server is listening:
   ```bash
   docker exec dtls-vpn-server netstat -ulnp | grep 4433
   ```

2. Verify network connectivity:
   ```bash
   docker exec dtls-vpn-client ping 172.20.0.10
   ```

3. Check firewall rules on host

### Certificate Errors

**Error:** `Failed to load certificate` or `Failed to load private key`

**Solution:**
1. Verify certificates exist:
   ```bash
   docker exec dtls-vpn-server ls -l certs/
   ```

2. Regenerate certificates:
   ```bash
   cd certs && ./generate_certs.sh
   ```

3. Rebuild images:
   ```bash
   docker-compose build --no-cache
   ```

## Production Considerations

### Security

1. **Use proper certificates**: Don't use self-signed certs in production
2. **Enable certificate verification**: Remove `DTLS_VERIFY_NONE` flag
3. **Restrict network access**: Use firewall rules
4. **Run as non-root**: Create dedicated user in Dockerfile
5. **Scan images**: Use `docker scan` to check for vulnerabilities

### Performance

1. **Resource limits**: Set CPU and memory limits
   ```yaml
   services:
     vpn-server:
       deploy:
         resources:
           limits:
             cpus: '2'
             memory: 512M
   ```

2. **Logging**: Configure log rotation
   ```yaml
   services:
     vpn-server:
       logging:
         driver: "json-file"
         options:
           max-size: "10m"
           max-file: "3"
   ```

### Monitoring

1. **Health checks**: Add health check endpoints
   ```yaml
   services:
     vpn-server:
       healthcheck:
         test: ["CMD", "pgrep", "server"]
         interval: 30s
         timeout: 10s
         retries: 3
   ```

2. **Metrics**: Export metrics for Prometheus/Grafana
3. **Alerts**: Set up alerting for connection failures

## Multi-Architecture Builds

Build for multiple architectures:

```bash
# Enable buildx
docker buildx create --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile.server \
  -t dtls-vpn-server:latest \
  --push .
```

## References

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [TUN/TAP in Docker](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)