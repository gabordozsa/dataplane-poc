# Understanding BIO Pairs in OpenSSL

## What is a BIO?

**BIO** stands for **Basic Input/Output** abstraction in OpenSSL. It's an I/O abstraction layer that provides a uniform interface for different types of I/O operations (files, sockets, memory buffers, etc.).

Think of a BIO as a "pipe" or "stream" that OpenSSL uses to read and write data.

## The Problem We're Solving

OpenSSL's SSL/TLS implementation was originally designed for **blocking I/O** with traditional sockets:

```
Traditional Approach (Blocking):
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Network │ ◄─────► │   SSL   │ ◄─────► │   App   │
│ Socket  │         │ Engine  │         │  Logic  │
└─────────┘         └─────────┘         └─────────┘
     ▲                                        ▲
     │                                        │
     └────── SSL reads/writes directly ──────┘
```

**But we have a problem**: We're using **io-uring** for asynchronous I/O, which doesn't fit this model. We need to:
1. Receive UDP packets asynchronously via io-uring
2. Feed them to OpenSSL for decryption
3. Get encrypted data from OpenSSL to send via io-uring

## The Solution: BIO Pairs

A **BIO pair** creates two connected memory buffers that act like a bidirectional pipe:

```
BIO Pair Concept:
┌──────────┐         ┌──────────┐
│  BIO A   │ ◄─────► │  BIO B   │
│ (rbio)   │         │ (wbio)   │
└──────────┘         └──────────┘
     ▲                    ▲
     │                    │
Write to A ──────────► Read from B
Write to B ──────────► Read from A
```

**Key insight**: What you write to one BIO, you can read from the other!

## How We Use BIO Pairs with DTLS

We create a BIO pair and give one BIO to SSL, keeping the other for ourselves:

```
Our Architecture:
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  io-uring   │         │  BIO Pair   │         │     SSL     │
│  (Network)  │         │             │         │   Engine    │
└─────────────┘         └─────────────┘         └─────────────┘
      │                       │                        │
      │                  ┌────┴────┐                   │
      │                  │         │                   │
      │              ┌───▼───┐ ┌───▼───┐              │
      │              │ rbio  │ │ wbio  │              │
      │              │(net→) │ │(→net) │              │
      │              └───┬───┘ └───┬───┘              │
      │                  │         │                   │
      │                  └────┬────┘                   │
      │                       │                        │
      └───────────────────────┴────────────────────────┘
```

### The Two BIOs Explained

1. **rbio (Read BIO)**: Network → SSL
   - We write encrypted network data here
   - SSL reads from it to decrypt

2. **wbio (Write BIO)**: SSL → Network
   - SSL writes encrypted data here
   - We read from it to send over network

## Step-by-Step Data Flow

### Receiving Data (Decryption)

```
1. io-uring receives encrypted UDP packet
   ┌─────────────────────────┐
   │ Encrypted UDP Packet    │
   │ [0x16, 0x03, 0x01, ...] │
   └─────────────────────────┘
              ↓
2. We write it to rbio
   BIO_write(rbio, encrypted_data, len)
   ┌─────────────────────────┐
   │        rbio             │
   │ [encrypted data buffer] │
   └─────────────────────────┘
              ↓
3. SSL reads from rbio and decrypts
   SSL_read(ssl, plaintext_buffer, size)
   ┌─────────────────────────┐
   │    SSL Engine           │
   │  (decrypts data)        │
   └─────────────────────────┘
              ↓
4. We get plaintext application data
   ┌─────────────────────────┐
   │ Plaintext Data          │
   │ "Hello, World!"         │
   └─────────────────────────┘
```

### Sending Data (Encryption)

```
1. Application wants to send plaintext
   ┌─────────────────────────┐
   │ Plaintext Data          │
   │ "Hello, World!"         │
   └─────────────────────────┘
              ↓
2. We write to SSL
   SSL_write(ssl, plaintext_data, len)
   ┌─────────────────────────┐
   │    SSL Engine           │
   │  (encrypts data)        │
   └─────────────────────────┘
              ↓
3. SSL writes encrypted data to wbio
   ┌─────────────────────────┐
   │        wbio             │
   │ [encrypted data buffer] │
   └─────────────────────────┘
              ↓
4. We read from wbio
   BIO_read(wbio, network_buffer, size)
   ┌─────────────────────────┐
   │ Encrypted UDP Packet    │
   │ [0x16, 0x03, 0x01, ...] │
   └─────────────────────────┘
              ↓
5. Send via io-uring
```

## Code Example

### ⚠️ IMPORTANT: BIO Pair vs Separate BIOs

**UPDATE (2026-05-06)**: We discovered that using `BIO_new_bio_pair()` creates a **feedback loop** that causes handshake failures. The correct approach is to use **separate memory BIOs**.

### ❌ WRONG: Using BIO Pair (Creates Feedback Loop)

```c
// ❌ DON'T DO THIS - Creates feedback loop!
BIO *rbio = NULL;
BIO *wbio = NULL;

// This creates two CONNECTED BIOs where:
// - Data written to rbio can be read from wbio
// - Data written to wbio can be read from rbio
int ret = BIO_new_bio_pair(&rbio, 8192, &wbio, 8192);

SSL_set_bio(ssl, rbio, wbio);

// PROBLEM: SSL writes to wbio → feeds back into rbio → SSL reads its own output!
// Result: SSL_ERROR_SSL with "unexpected message" error
```

**Why this fails**:
1. SSL writes encrypted data to `wbio`
2. Because they're a pair, this data appears in `rbio`
3. SSL tries to read from `rbio` and gets its own output
4. SSL state machine gets confused: "unexpected message"
5. Handshake generates Alert (0x15) instead of ClientHello (0x16)

### ✅ CORRECT: Using Separate Memory BIOs

```c
// ✅ DO THIS - Use separate memory BIOs
BIO *rbio = BIO_new(BIO_s_mem());  // Read BIO (network → SSL)
BIO *wbio = BIO_new(BIO_s_mem());  // Write BIO (SSL → network)

if (!rbio || !wbio) {
    // Error handling
    if (rbio) BIO_free(rbio);
    if (wbio) BIO_free(wbio);
    return -1;
}

// Make BIOs non-blocking (return -1 on EOF instead of 0)
BIO_set_mem_eof_return(rbio, -1);
BIO_set_mem_eof_return(wbio, -1);

// Create SSL object
SSL *ssl = SSL_new(ssl_ctx);

// Give both BIOs to SSL
// SSL takes ownership - don't free them manually!
SSL_set_bio(ssl, rbio, wbio);

// IMPORTANT: Set SSL state AFTER attaching BIOs!
SSL_set_accept_state(ssl);  // For server
// or
SSL_set_connect_state(ssl); // For client
```

**Why this works**:
1. `rbio` and `wbio` are **independent** memory buffers
2. SSL writes to `wbio` → we read from `wbio` → send to network
3. Network → we write to `rbio` → SSL reads from `rbio`
4. No feedback loop, clean unidirectional data flow

### Receiving and Decrypting

```c
// 1. io-uring completed a recvmsg operation
char encrypted_packet[2048];
int packet_len = cqe->res;  // bytes received

// 2. Write encrypted data to rbio
int written = BIO_write(conn->rbio, encrypted_packet, packet_len);
if (written <= 0) {
    // Handle error
}

// 3. Try to read decrypted data from SSL
char plaintext[2048];
int decrypted = SSL_read(conn->ssl, plaintext, sizeof(plaintext));

if (decrypted > 0) {
    // Success! We have plaintext data
    process_application_data(plaintext, decrypted);
} else {
    int err = SSL_get_error(conn->ssl, decrypted);
    if (err == SSL_ERROR_WANT_READ) {
        // Need more network data - normal, just wait
    } else if (err == SSL_ERROR_WANT_WRITE) {
        // SSL wants to send something (handshake message)
        // Check wbio below
    } else {
        // Real error
    }
}

// 4. Check if SSL wants to send anything (handshake messages, etc.)
int pending = BIO_ctrl_pending(conn->wbio);
if (pending > 0) {
    char outgoing[2048];
    int read = BIO_read(conn->wbio, outgoing, sizeof(outgoing));
    if (read > 0) {
        // Send this data via io-uring
        submit_send_operation(outgoing, read, &conn->addr);
    }
}
```

### Encrypting and Sending

```c
// 1. Application wants to send plaintext
char *message = "Hello, Client!";
int len = strlen(message);

// 2. Write plaintext to SSL
int written = SSL_write(conn->ssl, message, len);
if (written <= 0) {
    int err = SSL_get_error(conn->ssl, written);
    // Handle error
}

// 3. Read encrypted data from wbio
int pending = BIO_ctrl_pending(conn->wbio);
if (pending > 0) {
    char encrypted[2048];
    int read = BIO_read(conn->wbio, encrypted, sizeof(encrypted));
    
    if (read > 0) {
        // 4. Send encrypted data via io-uring
        submit_send_operation(encrypted, read, &conn->addr);
    }
}
```

## Why BIO Pairs Are Perfect for io-uring

1. **Decoupling**: Separates network I/O from SSL processing
2. **Asynchronous**: No blocking - we control when data flows
3. **Memory-based**: Fast, no system calls within SSL

## Critical Issues and Fixes (Updated 2026-05-06)

### Issue 1: BIO Pair Feedback Loop (CRITICAL)

**Problem**: Using `BIO_new_bio_pair()` creates connected BIOs that cause SSL's output to feed back into its input.

**Symptoms**:
- `SSL_do_handshake()` returns -1 with `SSL_ERROR_SSL`
- Error message: "ossl_statem_client_read_transition:unexpected message"
- Generates 15-byte Alert (0x15) instead of ClientHello (0x16)
- Handshake never completes

**Root Cause**: 
```
BIO Pair Creates Feedback Loop:
SSL writes to wbio → Data appears in rbio → SSL reads its own output!
```

**Solution**: Use separate `BIO_new(BIO_s_mem())` instances instead of `BIO_new_bio_pair()`. See the corrected code example above.

### Issue 2: SSL State Set Before BIO Attachment

**Problem**: Calling `SSL_set_connect_state()` or `SSL_set_accept_state()` before attaching BIOs puts SSL in an inconsistent state.

**Symptoms**:
- SSL expects to perform I/O but has no I/O mechanism configured
- Handshake fails with protocol errors

**Solution**: Always call `SSL_set_bio()` FIRST, then set the SSL state:
```c
// ✅ CORRECT ORDER
SSL_set_bio(ssl, rbio, wbio);           // 1. Attach BIOs first
SSL_set_connect_state(ssl);             // 2. Then set state

// ❌ WRONG ORDER
SSL_set_connect_state(ssl);             // 1. State set too early
SSL_set_bio(ssl, rbio, wbio);           // 2. BIOs attached after
```

### Issue 3: Server Not Sending Final Handshake Messages

**Problem**: When `SSL_do_handshake()` returns 1 (success), the server marks the connection as established but doesn't check if SSL generated final messages (ChangeCipherSpec + Finished) that need to be sent.

**Symptoms**:
- Server logs "handshake completed"
- Client stuck waiting with `SSL_ERROR_WANT_READ`
- Client never receives server's final messages

**Solution**: After handshake completion, always check wbio for pending data:
```c
if (SSL_do_handshake(ssl) == 1) {
    // Handshake complete!
    conn->state = CONN_STATE_ESTABLISHED;
    
    // ✅ Check if SSL has final messages to send
    int pending = BIO_ctrl_pending(wbio);
    if (pending > 0) {
        char buffer[2048];
        int read = BIO_read(wbio, buffer, sizeof(buffer));
        if (read > 0) {
            // Send these final messages!
            send_to_network(buffer, read);
        }
    }
}
```

**See DTLS-HANDSHAKE-FIXES.md for complete details on these fixes.**

4. **Flexible**: Works with any async I/O system (io-uring, epoll, etc.)

## Common Pitfalls

### Pitfall 1: Confusing rbio and wbio

```c
// ❌ WRONG - backwards!
BIO_write(wbio, network_data, len);  // NO!

// ✅ CORRECT
BIO_write(rbio, network_data, len);  // YES!
```

**Remember**: 
- **rbio** = **R**eceive from network (you write network data here)
- **wbio** = **W**rite to network (you read network data from here)

### Pitfall 2: Forgetting to Check wbio

After any SSL operation (read, write, handshake), always check if SSL wants to send:

```c
SSL_read(ssl, buffer, size);  // or SSL_write, SSL_do_handshake

// ✅ Always check wbio after SSL operations!
int pending = BIO_ctrl_pending(wbio);
if (pending > 0) {
    // Read and send the data
}
```

### Pitfall 3: Not Handling SSL_ERROR_WANT_READ/WRITE

These are **not errors**! They mean:
- `SSL_ERROR_WANT_READ`: Need more network data
- `SSL_ERROR_WANT_WRITE`: Need to send data (check wbio)

```c
int ret = SSL_read(ssl, buffer, size);
if (ret <= 0) {
    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
        // ✅ Normal - just wait for more data
        return;
    }
    // Handle other errors...
}
```

## Visual Summary

```
Complete Flow with BIO Pairs:

Network (io-uring)                    SSL Engine
       │                                   │
       │  Encrypted UDP Packet             │
       ├──────────────────────────────────►│
       │  BIO_write(rbio, data, len)       │
       │                                   │
       │                                   │
       │         SSL_read(ssl, buf, size)  │
       │                                   │
       │                                   │
       │  Plaintext to Application         │
       │◄──────────────────────────────────┤
       │                                   │
       │                                   │
       │  Plaintext from Application       │
       ├──────────────────────────────────►│
       │  SSL_write(ssl, data, len)        │
       │                                   │
       │                                   │
       │  BIO_read(wbio, buf, size)        │
       │◄──────────────────────────────────┤
       │  Encrypted UDP Packet             │
       │                                   │
```

## Key Takeaways

1. **BIO pairs** = Two connected memory buffers
2. **rbio** = Network → SSL (you write encrypted, SSL reads)
3. **wbio** = SSL → Network (SSL writes encrypted, you read)
4. **Always check wbio** after SSL operations
5. **SSL_ERROR_WANT_READ/WRITE** are normal, not errors
6. **Perfect for async I/O** like io-uring

## Further Reading

- OpenSSL BIO documentation: `man BIO_new_bio_pair`
- SSL_set_bio: `man SSL_set_bio`
- OpenSSL examples: `/usr/share/doc/openssl/examples/`

This pattern is used in many high-performance servers (nginx, haproxy, etc.) to integrate OpenSSL with event-driven I/O.