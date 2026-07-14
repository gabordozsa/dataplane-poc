# Multi-stage build for DTLS VPN Server
FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    liburing-dev \
    pkg-config

# Set working directory
WORKDIR /build

# Copy source files
COPY CMakeLists.txt .
COPY include/ include/
COPY src/ src/
COPY certs/ certs/

# Build the project
RUN mkdir build && cd build && \
    cmake  -DCMAKE_BUILD_TYPE=Debug .. && \
    make

# Runtime stage
FROM ubuntu:24.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    liburing2 \
    iproute2 \
    iputils-ping \
    iperf3

# Create directory for certificates
RUN mkdir -p /app/certs

# Copy binary from builder
COPY --from=builder /build/build/edge_server /build/build/edge_client /app/
COPY --from=builder /build/build/dtls_forwarder /app/


# Copy certificates
COPY --from=builder /build/certs/ /app/certs/

# Set working directory
WORKDIR /app



# Add capabilities for TUN device creation
# Note: Container must be run with --cap-add=NET_ADMIN --device=/dev/net/tun

# Default command
CMD ["./edge_server", "4433", "certs/server_cert.pem", "certs/server_key.pem", "10.9.0.254"]

# Made with Bob
