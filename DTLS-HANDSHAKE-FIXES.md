# DTLS Handshake Fixes

## Problem Summary

The DTLS handshake in the client never completed, causing the client to block indefinitely waiting for completion events. The handshake would initiate but never progress beyond the initial exchange.

## Root Causes Identified

### 1. Incorrect BIO Pair Configuration (CRITICAL)

**Problem**: Used `BIO_new_bio_pair()` which creates two **connected** memory BIOs where data written to one can be read from the other. This created a feedback loop where SSL's output fed back into its input.

**Symptom**: 
- `SSL_do_handshake()` returned `-1` with `SSL_ERROR_SSL`
- Generated a 15-byte Alert message (`0x15 fe ff 00 00...`) instead of ClientHello
- Error: `ossl_statem_client_read_transition:unexpected message`

**Fix** (src/dtls_context.c):
```c
// BEFORE: BIO pair (creates feedback loop)
BIO_new_bio_pair(&rbio, 8192, &wbio, 8192);
SSL_set_bio(ssl, rbio, wbio);

// AFTER: Separate memory BIOs (correct)
BIO *rbio = BIO_new(BIO_s_mem());
BIO *wbio = BIO_new(BIO_s_mem());
BIO_set_mem_eof_return(rbio, -1);
BIO_set_mem_eof_return(wbio, -1);
SSL_set_bio(ssl, rbio, wbio);
```

**Result**: Client now generates proper 318-byte DTLS ClientHello (`0x16 fe ff...`)

### 2. SSL State Set Before BIO Attachment

**Problem**: `SSL_set_connect_state()` was called in `dtls_create_ssl()` BEFORE the BIOs were attached via `dtls_setup_bio_pair()`. This put SSL in an inconsistent state.

**Fix** (src/dtls_context.c):
- Removed `SSL_set_connect_state()` / `SSL_set_accept_state()` from `dtls_create_ssl()`
- Moved state setting to `dtls_setup_bio_pair()` AFTER `SSL_set_bio()` is called
- Added automatic detection of server vs client mode using `SSL_is_server()`

**Result**: SSL state machine properly initialized with I/O configured

### 3. Server Not Sending Final Handshake Messages (CRITICAL)

**Problem**: When the server's `SSL_do_handshake()` returned 1 (success), it immediately marked the connection as established but never checked if SSL had generated final messages (ChangeCipherSpec + Finished) that needed to be sent to the client.

**Symptom**:
- Server log: "DTLS handshake completed"
- Client stuck waiting with `SSL_ERROR_WANT_READ`
- Client never received server's final 266-byte message

**Fix** (src/packet_handler.c):
```c
if (ret == 1) {
    // Handshake complete
    conn->state = CONN_STATE_ESTABLISHED;
    log_info("DTLS handshake completed");
    
    // NEW: Check if SSL has any final messages to send
    int pending = BIO_ctrl_pending(conn->wbio);
    if (pending > 0) {
        uint8_t buffer[PACKET_BUFFER_SIZE];
        int read = BIO_read(conn->wbio, buffer, sizeof(buffer));
        if (read > 0) {
            io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
            if (op) {
                iouring_submit_udp_send(uring_ctx, op,
                                      (struct sockaddr *)&conn->addr,
                                      conn->addr_len, buffer, read);
            }
        }
    }
    return 0;
}
```

**Result**: Server now sends its final handshake messages, allowing client to complete

### 4. Handshake Retry After Sending (Enhancement)

**Problem**: After sending handshake messages in response to `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE`, the code didn't retry `SSL_do_handshake()` to check if the handshake completed.

**Fix** (src/packet_handler.c):
Added retry logic after sending handshake messages to immediately detect completion:
```c
// After sending in WANT_READ case
ret = SSL_do_handshake(conn->ssl);
if (ret == 1) {
    conn->state = CONN_STATE_ESTABLISHED;
    log_info("DTLS handshake completed (after WANT_READ send)");
    return 0;
}
```

## Handshake Flow (Fixed)

### Successful Handshake Sequence:

1. **Client → Server**: ClientHello (318 bytes)
   - `SSL_do_handshake()` returns `-1`, `SSL_ERROR_WANT_READ`
   - Reads from wbio, sends to server

2. **Server → Client**: ServerHello + Certificate + ServerHelloDone (1435 bytes)
   - Server receives ClientHello
   - `SSL_do_handshake()` returns `-1`, `SSL_ERROR_WANT_READ`
   - Reads from wbio, sends to client

3. **Client → Server**: ClientKeyExchange + ChangeCipherSpec + Finished (133 bytes)
   - Client receives server messages
   - Writes to rbio, calls `SSL_do_handshake()`
   - Returns `-1`, `SSL_ERROR_WANT_READ`
   - Reads from wbio, sends to server

4. **Server → Client**: ChangeCipherSpec + Finished (266 bytes)
   - Server receives client's Finished
   - `SSL_do_handshake()` returns `1` (SUCCESS)
   - **NEW**: Checks wbio for pending data
   - Sends final 266-byte message to client

5. **Client**: Handshake Complete
   - Receives server's final message
   - Writes to rbio, calls `SSL_do_handshake()`
   - Returns `1` (SUCCESS)
   - Connection established!

## Files Modified

1. **src/dtls_context.c**
   - Changed BIO creation from pair to separate memory BIOs
   - Moved SSL state setting to after BIO attachment

2. **src/packet_handler.c**
   - Added final message sending after handshake completion
   - Added handshake retry after sending messages
   - Enhanced logging for debugging

3. **src/client.c**
   - Added comprehensive logging for handshake debugging
   - Added hex dump of handshake messages

## Verification

### Client Log (Success):
```
[INFO] DTLS handshake completed
[INFO] Handshake completed successfully
[INFO] DTLS connection established, starting TUN read
[DEBUG] Sending encrypted packet: 85 bytes
```

### Server Log (Success):
```
[INFO] DTLS handshake completed
[DEBUG] Sent final handshake message after completion: 266 bytes
[INFO] Handshake completed successfully
[DEBUG] Decrypted 48 bytes
```

## Key Learnings

1. **BIO Pairs vs Separate BIOs**: For DTLS with memory BIOs, use separate `BIO_new(BIO_s_mem())` instances, not `BIO_new_bio_pair()`. The pair creates a bidirectional connection that causes feedback loops.

2. **Initialization Order**: Always attach BIOs to SSL before setting the connection state (`SSL_set_connect_state()` / `SSL_set_accept_state()`).

3. **Check wbio After Success**: When `SSL_do_handshake()` returns 1, always check `BIO_ctrl_pending(wbio)` for final messages that need to be sent.

4. **DTLS is Asynchronous**: DTLS handshakes require multiple round-trips. Each call to `SSL_do_handshake()` processes one step and may generate messages to send.

## Testing

The fix was verified with:
- Client successfully connects to server
- Handshake completes on both sides
- Encrypted data flows bidirectionally
- IPv6 packets (48 bytes) encrypted to 85 bytes
- Decryption works correctly on both ends

## Date

Fixed: 2026-05-06