# Implementation Plan: io-uring + DTLS UDP Transport

## Phase 1: Project Setup and Foundation

### 1.1 Directory Structure
```
dataplane/
├── src/           # Source files
├── include/       # Header files
├── examples/      # Example programs
├── certs/         # Test certificates (gitignored)
└── build/         # Build output (gitignored)
```

### 1.2 Build System (CMakeLists.txt)
- Set C11 standard
- Find and link liburing
- Find and link OpenSSL
- Configure compiler warnings (-Wall -Wextra)
- Set up debug and release configurations
- Create targets for library and examples

## Phase 2: Core Infrastructure

### 2.1 Utility Module (utils.h/c)
**Purpose**: Common utilities and helpers

**Functions**:
- `log_error()`, `log_info()`, `log_debug()` - Logging functions
- `get_timestamp()` - Current time for timeouts
- `addr_to_string()` - Convert sockaddr to string for logging
- `addr_hash()` - Hash function for connection table
- `addr_compare()` - Compare two socket addresses

**Data Structures**:
```c
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;
```

### 2.2 UDP Socket Module (udp_socket.h/c)
**Purpose**: UDP socket creation and configuration

**Functions**:
- `udp_socket_create(port)` - Create and bind UDP socket
- `udp_socket_set_nonblocking(fd)` - Set non-blocking mode
- `udp_socket_close(fd)` - Close socket

**Key Implementation Details**:
- Use `socket(AF_INET, SOCK_DGRAM, 0)`
- Set `SO_REUSEADDR` and `SO_REUSEPORT`
- Bind to `INADDR_ANY` or specific address
- Set non-blocking with `fcntl()`

## Phase 3: io-uring Integration

### 3.1 io-uring Manager (iouring.h/c)
**Purpose**: Manage io-uring instance and operations

**Data Structures**:
```c
typedef struct {
    struct io_uring ring;
    unsigned queue_depth;
    int udp_fd;
} iouring_ctx_t;

typedef struct {
    int op_type;  // RECV or SEND
    void *user_data;
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    char buffer[2048];  // MTU-sized buffer
} io_op_t;
```

**Functions**:
- `iouring_init(queue_depth)` - Initialize io-uring
- `iouring_cleanup()` - Clean up io-uring
- `iouring_submit_recv(ctx, op)` - Submit receive operation
- `iouring_submit_send(ctx, op, addr, data, len)` - Submit send operation
- `iouring_wait_cqe(ctx, cqe)` - Wait for completion
- `iouring_process_cqe(ctx, cqe)` - Process completion event

**Key Implementation Details**:
- Use `io_uring_queue_init()` with appropriate depth (256-1024)
- Prepare `recvmsg` SQEs with `io_uring_prep_recvmsg()`
- Prepare `sendmsg` SQEs with `io_uring_prep_sendmsg()`
- Use `IORING_SETUP_SQPOLL` for kernel polling (optional)
- Handle `EAGAIN` and retry logic

## Phase 4: DTLS Integration

### 4.1 DTLS Context Module (dtls_context.h/c)
**Purpose**: OpenSSL DTLS initialization and configuration

**Data Structures**:
```c
typedef struct {
    SSL_CTX *ctx;
    char *cert_file;
    char *key_file;
} dtls_ctx_t;
```

**Functions**:
- `dtls_context_init(cert_file, key_file)` - Initialize DTLS context
- `dtls_context_cleanup()` - Clean up DTLS context
- `dtls_create_ssl(dtls_ctx)` - Create new SSL object for connection

**Key Implementation Details**:
- Use `DTLS_server_method()`
- Load certificate with `SSL_CTX_use_certificate_file()`
- Load private key with `SSL_CTX_use_PrivateKey_file()`
- Set cipher suites with `SSL_CTX_set_cipher_list()`
- Configure cookie generation for DoS protection
- Set MTU with `SSL_set_mtu()`

### 4.2 Connection State Module (connection.h/c)
**Purpose**: Track individual DTLS connections

**Data Structures**:
```c
typedef enum {
    CONN_STATE_HANDSHAKING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_CLOSING
} conn_state_t;

typedef struct connection {
    SSL *ssl;
    BIO *rbio;  // Read BIO (network -> SSL)
    BIO *wbio;  // Write BIO (SSL -> network)
    struct sockaddr_storage addr;
    socklen_t addr_len;
    conn_state_t state;
    time_t last_activity;
    struct connection *next;  // For hash table chaining
} connection_t;

typedef struct {
    connection_t **buckets;
    size_t bucket_count;
    size_t conn_count;
    size_t max_connections;
} connection_table_t;
```

**Functions**:
- `connection_table_init(bucket_count, max_conn)` - Initialize hash table
- `connection_table_cleanup()` - Clean up all connections
- `connection_find(table, addr)` - Find connection by address
- `connection_create(table, dtls_ctx, addr)` - Create new connection
- `connection_destroy(table, conn)` - Destroy connection
- `connection_cleanup_idle(table, timeout)` - Remove idle connections

**Key Implementation Details**:
- Use hash table with chaining for O(1) lookup
- Hash based on IP address and port
- Create BIO pair with `BIO_new_bio_pair()`
- Associate BIO with SSL using `SSL_set_bio()`
- Set SSL to server mode with `SSL_set_accept_state()`

## Phase 5: Event Processing

### 5.1 Event Handler Module (event_handler.h/c)
**Purpose**: Process io-uring completion events and coordinate DTLS

**Functions**:
- `handle_recv_event(ctx, cqe, conn_table, dtls_ctx)` - Process received data
- `handle_send_event(ctx, cqe)` - Process send completion
- `process_dtls_handshake(conn)` - Handle DTLS handshake
- `process_dtls_data(conn, app_data, len)` - Process decrypted application data
- `send_dtls_data(ctx, conn, data, len)` - Encrypt and send data

**Key Implementation Details**:

**Receive Path**:
1. Get completion event from io-uring
2. Extract source address from `msghdr`
3. Look up or create connection
4. Write data to SSL read BIO: `BIO_write(conn->rbio, data, len)`
5. If handshaking: call `SSL_do_handshake()`
6. If established: call `SSL_read()` to get decrypted data
7. Read from write BIO: `BIO_read(conn->wbio, out_buf, size)`
8. If data in write BIO, submit send operation
9. Submit new receive operation

**Send Path**:
1. Application calls send function with plaintext
2. Call `SSL_write(conn->ssl, data, len)`
3. Read encrypted data from write BIO
4. Submit sendmsg via io-uring
5. On completion, free buffers

**Handshake Handling**:
- Call `SSL_do_handshake()` repeatedly
- Check return value and `SSL_get_error()`
- Handle `SSL_ERROR_WANT_READ` and `SSL_ERROR_WANT_WRITE`
- Transition to established state when complete

## Phase 6: Main Loop

### 6.1 Main Server (main.c)
**Purpose**: Tie everything together

**Main Loop Structure**:
```c
int main(int argc, char **argv) {
    // 1. Initialize logging
    // 2. Create UDP socket
    // 3. Initialize io-uring
    // 4. Initialize DTLS context
    // 5. Initialize connection table
    
    // 6. Submit initial receive operations (multiple for parallelism)
    for (int i = 0; i < RECV_QUEUE_SIZE; i++) {
        submit_recv_operation();
    }
    
    // 7. Main event loop
    while (running) {
        // Wait for completion events
        io_uring_wait_cqe(&ring, &cqe);
        
        // Process event
        if (cqe->user_data == RECV_OP) {
            handle_recv_event();
        } else if (cqe->user_data == SEND_OP) {
            handle_send_event();
        }
        
        // Mark CQE as seen
        io_uring_cqe_seen(&ring, cqe);
        
        // Periodic cleanup
        if (should_cleanup()) {
            connection_cleanup_idle();
        }
    }
    
    // 8. Cleanup
    // - Close all connections
    // - Cleanup DTLS context
    // - Cleanup io-uring
    // - Close socket
    
    return 0;
}
```

**Signal Handling**:
- Catch SIGINT and SIGTERM for graceful shutdown
- Set `running = 0` to exit main loop

## Phase 7: Example and Testing

### 7.1 Example Server (examples/server_example.c)
**Purpose**: Demonstrate usage

**Features**:
- Parse command line arguments (port, cert, key)
- Initialize server
- Echo received data back to clients
- Handle shutdown gracefully

### 7.2 Test Certificates
**Generate self-signed certificates**:
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 7.3 Testing Strategy
- Use `openssl s_client` with `-dtls` flag for testing
- Create simple client program for automated testing
- Test scenarios:
  - Single connection handshake
  - Multiple concurrent connections
  - Connection timeout
  - Large data transfer
  - Malformed packets

## Phase 8: Documentation

### 8.1 README.md
**Contents**:
- Project overview
- Features
- Dependencies
- Build instructions
- Usage examples
- Configuration options
- Troubleshooting

### 8.2 API Documentation
- Document all public functions
- Include usage examples
- Describe data structures

## Implementation Order

1. ✅ Project structure and build system
2. ✅ Utility module (logging, helpers)
3. ✅ UDP socket module
4. ✅ io-uring manager (basic operations)
5. ✅ DTLS context initialization
6. ✅ Connection state management
7. ✅ Event handler (receive path)
8. ✅ Event handler (send path)
9. ✅ Main loop integration
10. ✅ Connection lifecycle (timeouts, cleanup)
11. ✅ Example server
12. ✅ Testing and debugging
13. ✅ Documentation

## Key Challenges and Solutions

### Challenge 1: BIO Integration
**Problem**: OpenSSL expects blocking I/O, io-uring is async
**Solution**: Use memory BIO pairs to decouple SSL from network I/O

### Challenge 2: Connection Demultiplexing
**Problem**: UDP is connectionless, need to track DTLS sessions
**Solution**: Hash table keyed by client address

### Challenge 3: Handshake Retransmissions
**Problem**: DTLS handshake packets may be lost
**Solution**: OpenSSL handles retransmissions internally with timers

### Challenge 4: Buffer Management
**Problem**: Need efficient buffer allocation for high throughput
**Solution**: Pre-allocate buffer pool, reuse buffers

### Challenge 5: Error Handling
**Problem**: Many failure points (network, SSL, memory)
**Solution**: Consistent error checking, cleanup paths, logging

## Performance Considerations

1. **Queue Depth**: Balance between latency and throughput (256-1024)
2. **Buffer Size**: Match MTU (typically 1500 bytes for Ethernet)
3. **Connection Limit**: Set based on available memory
4. **Hash Table Size**: Prime number, ~10-20% of max connections
5. **Batch Operations**: Submit multiple SQEs before calling `io_uring_submit()`

## Security Considerations

1. **Certificate Validation**: Implement proper certificate verification
2. **DoS Protection**: Use DTLS cookie mechanism
3. **Rate Limiting**: Limit connections per IP
4. **Resource Limits**: Enforce max connections, timeouts
5. **Input Validation**: Validate all received data

## Next Steps After Basic Implementation

1. Add configuration file support
2. Implement metrics and monitoring
3. Add multi-threading support
4. Optimize memory allocation
5. Add comprehensive test suite
6. Performance benchmarking
7. Security audit