# Quick Reference Guide

## io-uring Key Concepts

### Basic Flow
```c
// 1. Initialize
struct io_uring ring;
io_uring_queue_init(256, &ring, 0);

// 2. Get SQE (Submission Queue Entry)
struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);

// 3. Prepare operation
io_uring_prep_recvmsg(sqe, fd, &msg, 0);
io_uring_sqe_set_data(sqe, user_data);

// 4. Submit
io_uring_submit(&ring);

// 5. Wait for completion
struct io_uring_cqe *cqe;
io_uring_wait_cqe(&ring, &cqe);

// 6. Process result
int result = cqe->res;
void *data = io_uring_cqe_get_data(cqe);

// 7. Mark as seen
io_uring_cqe_seen(&ring, cqe);
```

### Important Functions
- `io_uring_queue_init()` - Initialize io-uring instance
- `io_uring_get_sqe()` - Get submission queue entry
- `io_uring_prep_recvmsg()` - Prepare receive operation
- `io_uring_prep_sendmsg()` - Prepare send operation
- `io_uring_submit()` - Submit operations to kernel
- `io_uring_wait_cqe()` - Wait for completion
- `io_uring_peek_cqe()` - Non-blocking check for completion
- `io_uring_cqe_seen()` - Mark completion as processed

## DTLS with OpenSSL

### Server Setup
```c
// 1. Initialize OpenSSL
SSL_library_init();
OpenSSL_add_all_algorithms();

// 2. Create DTLS context
SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());

// 3. Load certificates
SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);

// 4. Set options
SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");
SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
```

### Per-Connection Setup
```c
// 1. Create SSL object
SSL *ssl = SSL_new(ctx);

// 2. Create BIO pair
BIO *rbio, *wbio;
BIO_new_bio_pair(&rbio, 8192, &wbio, 8192);

// 3. Associate BIOs with SSL
SSL_set_bio(ssl, rbio, wbio);

// 4. Set server mode
SSL_set_accept_state(ssl);

// 5. Set MTU
SSL_set_mtu(ssl, 1500);
```

### Data Flow
```c
// Receive path:
// 1. Network data arrives
// 2. Write to read BIO
BIO_write(rbio, network_data, len);

// 3. Process handshake or read data
if (handshaking) {
    int ret = SSL_do_handshake(ssl);
    // Check ret and SSL_get_error()
} else {
    int ret = SSL_read(ssl, app_buffer, sizeof(app_buffer));
}

// 4. Check if SSL wants to send
int pending = BIO_ctrl_pending(wbio);
if (pending > 0) {
    BIO_read(wbio, network_buffer, pending);
    // Send network_buffer via io-uring
}

// Send path:
// 1. Write application data
SSL_write(ssl, app_data, len);

// 2. Read encrypted data from write BIO
int pending = BIO_ctrl_pending(wbio);
BIO_read(wbio, network_buffer, pending);

// 3. Send via io-uring
```

### Error Handling
```c
int ret = SSL_read(ssl, buffer, size);
if (ret <= 0) {
    int err = SSL_get_error(ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            // Need more network data
            break;
        case SSL_ERROR_WANT_WRITE:
            // Need to send data
            break;
        case SSL_ERROR_ZERO_RETURN:
            // Connection closed
            break;
        default:
            // Real error
            break;
    }
}
```

## UDP Socket Setup

```c
// Create socket
int fd = socket(AF_INET, SOCK_DGRAM, 0);

// Set reuse options
int opt = 1;
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

// Bind
struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr.s_addr = INADDR_ANY
};
bind(fd, (struct sockaddr*)&addr, sizeof(addr));

// Set non-blocking
int flags = fcntl(fd, F_GETFL, 0);
fcntl(fd, F_SETFL, flags | O_NONBLOCK);
```

## msghdr Structure for recvmsg/sendmsg

```c
struct msghdr msg = {0};
struct iovec iov;
struct sockaddr_storage addr;
char buffer[2048];

// Setup for receive
iov.iov_base = buffer;
iov.iov_len = sizeof(buffer);
msg.msg_iov = &iov;
msg.msg_iovlen = 1;
msg.msg_name = &addr;
msg.msg_namelen = sizeof(addr);

// After recvmsg, addr contains source address
// buffer contains received data
// msg.msg_namelen contains actual address length
```

## Hash Table for Connections

```c
// Hash function
uint32_t hash_addr(struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        return (sin->sin_addr.s_addr ^ sin->sin_port) % bucket_count;
    }
    // Handle IPv6...
}

// Lookup
connection_t* find_connection(struct sockaddr *addr) {
    uint32_t hash = hash_addr(addr);
    connection_t *conn = table->buckets[hash];
    
    while (conn) {
        if (addr_compare(&conn->addr, addr) == 0) {
            return conn;
        }
        conn = conn->next;
    }
    return NULL;
}
```

## Memory Management Tips

### Buffer Pool Pattern
```c
typedef struct buffer {
    char data[2048];
    int refcount;
    struct buffer *next;
} buffer_t;

buffer_t *buffer_pool = NULL;

buffer_t* buffer_alloc() {
    if (buffer_pool) {
        buffer_t *buf = buffer_pool;
        buffer_pool = buf->next;
        buf->refcount = 1;
        return buf;
    }
    return calloc(1, sizeof(buffer_t));
}

void buffer_free(buffer_t *buf) {
    if (--buf->refcount == 0) {
        buf->next = buffer_pool;
        buffer_pool = buf;
    }
}
```

## Common Pitfalls

### 1. BIO Direction Confusion
- **rbio**: Network → SSL (read from network, write to this BIO)
- **wbio**: SSL → Network (read from this BIO, write to network)

### 2. SSL_ERROR_WANT_READ/WRITE
- Not errors! Just need more data or need to send
- Continue processing, don't close connection

### 3. DTLS MTU
- Must set MTU with `SSL_set_mtu()`
- Typically 1500 for Ethernet, adjust for your network

### 4. Cookie Callbacks
- Required for DoS protection
- Generate stateless cookie based on client address
- Verify cookie before allocating resources

### 5. io-uring CQE Processing
- Always call `io_uring_cqe_seen()` after processing
- Check `cqe->res` for errors (negative = errno)
- User data can be NULL, always check

### 6. Address Comparison
- Use `memcmp()` carefully with sockaddr structures
- Different address families have different sizes
- Compare family, address, and port

## Debugging Tips

### Enable OpenSSL Debugging
```c
SSL_CTX_set_info_callback(ctx, ssl_info_callback);

void ssl_info_callback(const SSL *ssl, int where, int ret) {
    if (where & SSL_CB_HANDSHAKE_START) {
        printf("Handshake started\n");
    }
    if (where & SSL_CB_HANDSHAKE_DONE) {
        printf("Handshake completed\n");
    }
}
```

### Check io-uring Errors
```c
if (cqe->res < 0) {
    fprintf(stderr, "io-uring error: %s\n", strerror(-cqe->res));
}
```

### Verify DTLS State
```c
printf("SSL state: %s\n", SSL_state_string_long(ssl));
printf("Cipher: %s\n", SSL_get_cipher(ssl));
```

## Performance Monitoring

### Key Metrics
- Connections per second
- Handshake completion time
- Data throughput (bytes/sec)
- Queue depth utilization
- Connection table load factor

### Simple Timing
```c
struct timespec start, end;
clock_gettime(CLOCK_MONOTONIC, &start);
// ... operation ...
clock_gettime(CLOCK_MONOTONIC, &end);
long ns = (end.tv_sec - start.tv_sec) * 1000000000L + 
          (end.tv_nsec - start.tv_nsec);
printf("Operation took %ld ns\n", ns);
```

## Testing Commands

### Generate Test Traffic
```bash
# OpenSSL client
openssl s_client -dtls1_2 -connect localhost:4433

# Send UDP packet (no DTLS)
echo "test" | nc -u localhost 4433

# Multiple connections
for i in {1..10}; do
    openssl s_client -dtls1_2 -connect localhost:4433 &
done
```

### Monitor System
```bash
# Watch connections
watch -n1 'ss -u | grep 4433'

# Monitor CPU/memory
top -p $(pgrep server_example)

# Check io-uring stats
cat /proc/$(pgrep server_example)/io_uring_stats
```

## Useful Resources

- liburing examples: `/usr/share/doc/liburing/examples/`
- OpenSSL demos: `openssl/demos/ssl/`
- Man pages: `man io_uring_setup`, `man SSL_read`