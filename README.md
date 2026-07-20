# DTLS Tunnel with io-uring

An IP tunnel implementation using TUN devices for packet capture/injection, io-uring for asynchronous I/O, and OpenSSL DTLS for encryption. Creates a secure encrypted tunnel between client and server, routing IP packets through the secure channel.

## Features

- **TUN Device Integration**: Virtual network interface for packet capture and injection
- **Asynchronous I/O**: Uses io-uring for efficient, non-blocking operations
- **DTLS Encryption**: Secure UDP communication using OpenSSL DTLS 1.2
- **High Performance**: Handles thousands of concurrent connections with low latency
- **Connection Management**: Automatic connection tracking and lifecycle management
- **IP Packet Routing**: Full Layer 3 VPN functionality

## How It Works

The VPN tunnel operates as follows:

**Client → Server (Outbound)**:
1. Application sends packet to remote IP (e.g., 10.8.0.2)
2. Kernel routes packet to TUN device (tun0)
3. io-uring reads IP packet from TUN device
4. DTLS encrypts the packet
5. io-uring sends encrypted UDP packet to server
6. Server receives, decrypts, and injects into its TUN device

**Server → Client (Inbound)**:
1. Packet arrives at server for client IP
2. Kernel routes to server's TUN device (tun1)
3. io-uring reads packet, encrypts with DTLS
4. Sends to client, which decrypts and injects into tun0
5. Kernel delivers to application

See [TUN_ARCHITECTURE.md](TUN_ARCHITECTURE.md) for detailed system design.

## Requirements

### System Requirements
- Linux kernel 5.1 or later (for io-uring support)
- x86_64 or ARM64 architecture

### Build Dependencies
- GCC 7+ or Clang 6+ (C11 support required)
- CMake 3.10 or later
- liburing 2.0 or later
- OpenSSL 1.1.1 or later (DTLS 1.2 support)

### Installing Dependencies

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install build-essential cmake liburing-dev libssl-dev
```

**Fedora/RHEL**:
```bash
sudo dnf install gcc cmake liburing-devel openssl-devel
```

**Arch Linux**:
```bash
sudo pacman -S base-devel cmake liburing openssl
```

## Quick Start

### 1. Build
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential cmake liburing-dev libssl-dev

# Build
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

See [BUILD.md](BUILD.md) for detailed build instructions.

### 2. Generate Certificates
```bash
cd certs
./generate_certs.sh
cd ..
```

### 3. Run Server
```bash
# Terminal 1
sudo ./build/vpn_server 4433 certs/server_cert.pem certs/server_key.pem
```

### 4. Run Client
```bash
# Terminal 2
sudo ./build/vpn_client 127.0.0.1 4433
```

### 5. Test
```bash
# Terminal 3
ping 10.8.0.254  # Ping server through tunnel
```

## Usage

### Generating Test Certificates

For testing purposes, generate self-signed certificates:

```bash
# Generate private key and certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj "/CN=localhost"

# Move to certs directory
mkdir -p certs
mv key.pem cert.pem certs/
```

### Running the Example Server

```bash
# Run with default settings (port 4433)
./build/server_example

# Specify port and certificates
./build/server_example --port 5000 --cert certs/cert.pem --key certs/key.pem

# Enable debug logging
./build/server_example --log-level debug
```

### Testing with OpenSSL Client

```bash
# Connect to the server
openssl s_client -dtls1_2 -connect localhost:4433

# Send data (will be echoed back)
Hello, DTLS server!
```

### Command Line Options

```
Usage: server_example [OPTIONS]

Options:
  -p, --port PORT          UDP port to listen on (default: 4433)
  -c, --cert FILE          Path to certificate file (default: certs/cert.pem)
  -k, --key FILE           Path to private key file (default: certs/key.pem)
  -q, --queue-depth N      io-uring queue depth (default: 256)
  -m, --max-connections N  Maximum concurrent connections (default: 10000)
  -t, --timeout SECONDS    Connection timeout (default: 60)
  -l, --log-level LEVEL    Log level: debug, info, warn, error (default: info)
  -h, --help               Show this help message
```

## API Overview

### Core Components

#### io-uring Manager
```c
// Initialize io-uring context
iouring_ctx_t* iouring_init(unsigned queue_depth);

// Submit receive operation
int iouring_submit_recv(iouring_ctx_t *ctx, io_op_t *op);

// Submit send operation
int iouring_submit_send(iouring_ctx_t *ctx, io_op_t *op, 
                        struct sockaddr *addr, const void *data, size_t len);

// Wait for and process completion events
int iouring_wait_cqe(iouring_ctx_t *ctx, struct io_uring_cqe **cqe);
```

#### DTLS Context
```c
// Initialize DTLS context with certificates
dtls_ctx_t* dtls_context_init(const char *cert_file, const char *key_file);

// Create SSL object for new connection
SSL* dtls_create_ssl(dtls_ctx_t *ctx);

// Cleanup
void dtls_context_cleanup(dtls_ctx_t *ctx);
```

#### Connection Management
```c
// Initialize connection table
connection_table_t* connection_table_init(size_t bucket_count, size_t max_conn);

// Find or create connection
connection_t* connection_find_or_create(connection_table_t *table, 
                                        struct sockaddr *addr, 
                                        dtls_ctx_t *dtls_ctx);

// Remove idle connections
void connection_cleanup_idle(connection_table_t *table, time_t timeout);
```

## Performance Tuning

### Queue Depth
- **Small (64-128)**: Lower latency, less memory
- **Medium (256-512)**: Balanced for most workloads
- **Large (1024+)**: Higher throughput, more memory

### Connection Limits
- Set based on available memory (~10KB per connection)
- Consider file descriptor limits (`ulimit -n`)

### Buffer Sizes
- Default: 2048 bytes (safe for most MTUs)
- Adjust based on network MTU and packet sizes

### Hash Table Size
- Use prime number close to expected connection count
- Larger table = faster lookups, more memory

## Troubleshooting

### "Cannot allocate memory" errors
- Increase `ulimit -n` for file descriptors
- Reduce max connections or queue depth
- Check available system memory

### "Permission denied" on port binding
- Use port > 1024 or run with sudo
- Check firewall rules

### High CPU usage
- Reduce queue depth
- Enable kernel polling (`IORING_SETUP_SQPOLL`)
- Check for busy-wait loops

### Connection timeouts
- Verify network connectivity
- Check MTU settings
- Increase timeout value
- Verify certificates are valid

### DTLS handshake failures
- Verify certificate and key match
- Check certificate validity dates
- Ensure client supports DTLS 1.2
- Check cipher suite compatibility

## Development

### Project Structure
```
dataplane/
├── src/              # Source files
│   ├── main.c
│   ├── iouring.c
│   ├── udp_socket.c
│   ├── dtls_context.c
│   ├── connection.c
│   ├── event_handler.c
│   └── utils.c
├── include/          # Header files
│   ├── iouring.h
│   ├── udp_socket.h
│   ├── dtls_context.h
│   ├── connection.h
│   ├── event_handler.h
│   └── utils.h
├── examples/         # Example programs
│   └── server_example.c
├── certs/           # Certificates (gitignored)
├── build/           # Build output (gitignored)
├── CMakeLists.txt   # Build configuration
├── README.md        # This file
├── ARCHITECTURE.md  # System architecture
└── IMPLEMENTATION_PLAN.md  # Implementation details
```

### Running Tests
```bash
# Build with tests
cmake -DBUILD_TESTS=ON ..
make

# Run tests
make test
```

### Code Style
- Follow Linux kernel coding style
- Use 4 spaces for indentation
- Maximum line length: 100 characters
- Document all public functions

## Security Considerations

### Certificate Management
- Use proper CA-signed certificates in production
- Rotate certificates regularly
- Protect private keys (chmod 600)

### DoS Protection
- DTLS cookie mechanism enabled by default
- Connection limits enforced
- Rate limiting recommended for production

### Input Validation
- All received data is validated
- Buffer overflow protection
- Bounds checking on all operations

## Limitations

- Single-threaded design (one CPU core)
- No connection migration support
- Basic error recovery
- Limited metrics/monitoring

## Future Enhancements

- Multi-threaded support with io-uring sharing
- Advanced metrics and monitoring
- Configuration file support
- Connection migration
- DTLS 1.3 support
- Zero-copy optimizations
- eBPF integration for packet filtering

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Specify your license here]

## References

- [io-uring documentation](https://kernel.dk/io_uring.pdf)
- [OpenSSL DTLS guide](https://www.openssl.org/docs/man1.1.1/man3/DTLS_method.html)
- [RFC 6347 - DTLS 1.2](https://tools.ietf.org/html/rfc6347)

## Support

For issues, questions, or contributions:
- GitHub Issues: [repository-url]/issues
- Documentation: See ARCHITECTURE.md and IMPLEMENTATION_PLAN.md

## Acknowledgments

- liburing project for excellent io-uring library
- OpenSSL project for DTLS implementation
- Linux kernel team for io-uring subsystem