# DTLS Forwarder

## Overview

The DTLS Forwarder is a bidirectional packet relay that bridges two DTLS/UDP sessions. It acts as both a DTLS client (initiating an outbound connection) and a DTLS server (accepting an inbound connection), then forwards IP packets between the two established sessions.

## Architecture

```
┌─────────────┐         DTLS/UDP          ┌──────────────┐         DTLS/UDP          ┌─────────────┐
│   Client    │◄──────────────────────────►│  Forwarder   │◄──────────────────────────►│   Server    │
│  (Inbound)  │    Encrypted Session 1     │              │    Encrypted Session 2     │ (Outbound)  │
└─────────────┘                            └──────────────┘                            └─────────────┘
                                                   │
                                                   │ Decrypts from one
                                                   │ Encrypts to other
                                                   │ Forwards IP packets
                                                   ▼
```

### Key Features

- **Dual Role**: Acts as both DTLS client and server simultaneously
- **Bidirectional Forwarding**: Forwards IP packets in both directions
- **Asynchronous I/O**: Uses io-uring for high-performance packet processing
- **Connection Management**: Handles DTLS handshakes for both connections
- **Statistics Tracking**: Monitors packets and bytes forwarded in each direction

## Use Cases

1. **VPN Gateway**: Bridge between two VPN segments
2. **Network Relay**: Forward traffic through an intermediate node
3. **Protocol Translation**: Connect different VPN implementations
4. **Testing**: Create complex network topologies for testing

## Building

The forwarder is built automatically with the project:

```bash
mkdir build
cd build
cmake ..
make dtls_forwarder
```

The executable will be created as `build/dtls_forwarder`.

## Usage

### Command Line

```bash
./dtls_forwarder <local_port> <cert_file> <key_file> <ca_file> <remote_host> <remote_port>
```

### Parameters

- `local_port`: UDP port to listen on for inbound connections
- `cert_file`: Certificate file for server role (PEM format)
- `key_file`: Private key file for server role (PEM format)
- `ca_file`: CA certificate file for client role (PEM format)
- `remote_host`: Hostname or IP address of remote endpoint
- `remote_port`: UDP port of remote endpoint

### Example

```bash
# Forwarder listening on port 5000, connecting to server at 192.168.1.100:4433
./dtls_forwarder 5000 certs/cert.pem certs/key.pem certs/ca.pem 192.168.1.100 4433
```

## Operation Flow

### 1. Initialization

1. Creates UDP socket on specified local port
2. Initializes io-uring context for asynchronous I/O
3. Creates DTLS server context (for inbound connections)
4. Creates DTLS client context (for outbound connection)

### 2. Outbound Connection

1. Resolves remote hostname to IP address
2. Creates SSL object with client context
3. Initiates DTLS handshake with remote endpoint
4. Waits for handshake completion

### 3. Inbound Connection

1. Waits for incoming DTLS packets
2. Creates new connection on first packet from unknown source
3. Processes DTLS handshake as server
4. Establishes secure session

### 4. Packet Forwarding

Once both connections are established:

1. Receives encrypted packet from either connection
2. Decrypts packet using appropriate DTLS session
3. Validates packet as IP packet
4. Encrypts packet for destination connection
5. Sends encrypted packet to other endpoint
6. Updates statistics

### 5. Statistics

Periodically logs:
- Connection status (established/not established)
- Packets forwarded in each direction
- Bytes forwarded in each direction
- Total packets and bytes

## Network Topology Examples

### Example 1: Simple Relay

```
Client ──► Forwarder ──► Server
10.0.1.2   10.0.1.5      10.0.1.10
           (port 5000)   (port 4433)
```

**Setup:**

```bash
# On forwarder (10.0.1.5)
./dtls_forwarder 5000 cert.pem key.pem ca.pem 10.0.1.10 4433

# On client (10.0.1.2)
./vpn_client 10.0.1.5 4433 ca.pem 10.9.0.1

# On server (10.0.1.10)
./vpn_server 4433 cert.pem key.pem 10.9.0.254
```

### Example 2: Chain of Forwarders

```
Client ──► Forwarder1 ──► Forwarder2 ──► Server
```

**Setup:**

```bash
# Forwarder1
./dtls_forwarder 5000 cert1.pem key1.pem ca.pem forwarder2.example.com 5001

# Forwarder2
./dtls_forwarder 5001 cert2.pem key2.pem ca.pem server.example.com 4433

# Client connects to Forwarder1
./vpn_client forwarder1.example.com 5000 ca.pem 10.9.0.1

# Server listens
./vpn_server 4433 cert.pem key.pem 10.9.0.254
```

### Example 3: Hub-and-Spoke

```
        ┌─► Forwarder1 ──► Server1
Client ─┼─► Forwarder2 ──► Server2
        └─► Forwarder3 ──► Server3
```

Multiple forwarders can connect to the same client (if client acts as server).

## Implementation Details

### Data Structures

#### `forwarder_ctx_t`
Main context containing:
- UDP socket file descriptor
- io-uring context
- Two DTLS contexts (client and server)
- Two connection structures (inbound and outbound)
- Statistics counters

#### `forwarder_connection_t`
Per-connection state:
- DTLS connection object
- Role (client or server)
- Remote address
- Established flag

### Packet Processing

1. **UDP Receive**: Asynchronous receive using io-uring
2. **Connection Identification**: Match packet to inbound or outbound connection
3. **Handshake Processing**: Handle DTLS handshake messages
4. **Decryption**: Decrypt application data using SSL_read
5. **Validation**: Verify packet is valid IP packet
6. **Forwarding**: Encrypt and send to other connection
7. **Resubmit**: Queue next UDP receive operation

### Error Handling

- **Connection Failures**: Logs error and exits
- **Handshake Failures**: Logs error and continues
- **Decryption Errors**: Logs warning and drops packet
- **Invalid Packets**: Logs warning and drops packet

## Security Considerations

### Certificate Management

- **Server Role**: Requires valid certificate and private key
- **Client Role**: Requires CA certificate to verify server
- **Mutual TLS**: Can be configured for bidirectional authentication

### Recommendations

1. Use separate certificates for each forwarder instance
2. Implement certificate rotation
3. Use strong cipher suites (configured in DTLS context)
4. Monitor for connection anomalies
5. Implement rate limiting if needed

## Performance

### Optimization

- **io-uring**: Asynchronous I/O reduces context switches
- **Zero-copy**: Minimizes memory copies where possible
- **Batch Processing**: Processes multiple packets per syscall

### Benchmarks

Performance depends on:
- CPU speed
- Network latency
- Packet size
- Encryption overhead

Typical throughput: 100-500 Mbps per forwarder instance on modern hardware.

## Monitoring

### Log Levels

- **DEBUG**: Detailed packet information, handshake steps
- **INFO**: Connection events, statistics
- **WARN**: Dropped packets, minor errors
- **ERROR**: Critical failures

### Statistics Output

Every 30 seconds (or on timeout), logs:
```
=== Forwarder Statistics ===
Outbound connection: ESTABLISHED
Inbound connection: ESTABLISHED
Packets forwarded to outbound: 1234
Bytes forwarded to outbound: 1234567
Packets forwarded to inbound: 5678
Bytes forwarded to inbound: 5678901
Total packets: 6912
Total bytes: 6913468
```

## Troubleshooting

### Common Issues

#### 1. Outbound Connection Fails

**Symptoms**: "Failed to initiate outbound connection"

**Solutions**:
- Verify remote host is reachable
- Check firewall rules
- Verify remote port is correct
- Check CA certificate is valid

#### 2. Inbound Connection Not Established

**Symptoms**: No inbound connection after client connects

**Solutions**:
- Verify client is connecting to correct port
- Check certificate/key files are valid
- Verify firewall allows inbound UDP
- Check client is using correct CA certificate

#### 3. Packets Not Forwarded

**Symptoms**: Connections established but no packets forwarded

**Solutions**:
- Verify packets are valid IP packets
- Check both connections are established
- Enable DEBUG logging to see packet details
- Verify routing on client/server

#### 4. High Packet Loss

**Symptoms**: Many packets dropped

**Solutions**:
- Check network quality (latency, jitter)
- Verify MTU settings
- Monitor CPU usage
- Check for DTLS retransmissions

## Advanced Configuration

### Custom Cipher Suites

Modify `dtls_context.c` to configure specific cipher suites:

```c
SSL_CTX_set_cipher_list(ctx->ssl_ctx, "ECDHE-RSA-AES256-GCM-SHA384");
```

### Connection Timeouts

Modify idle timeout in main loop:

```c
// Check for idle connections every 60 seconds
if (now - last_check > 60) {
    // Implement timeout logic
}
```

### Buffer Sizes

Adjust `PACKET_BUFFER_SIZE` in `iouring.h` for larger packets:

```c
#define PACKET_BUFFER_SIZE 2048  // Increase for jumbo frames
```

## Integration with Existing VPN

### Scenario: Add Forwarder to Existing Setup

**Before:**
```
Client ──► Server
```

**After:**
```
Client ──► Forwarder ──► Server
```

**Steps:**

1. Deploy forwarder on intermediate host
2. Configure forwarder to connect to existing server
3. Update client to connect to forwarder instead of server
4. No changes needed to server

**Benefits:**
- Add relay capability without modifying endpoints
- Enable traffic inspection/monitoring at forwarder
- Create redundant paths with multiple forwarders

## Future Enhancements

Potential improvements:

1. **Multiple Connections**: Support N-way forwarding
2. **Load Balancing**: Distribute packets across multiple outbound connections
3. **Packet Filtering**: Filter/modify packets based on rules
4. **Connection Pooling**: Reuse connections for multiple clients
5. **Metrics Export**: Export statistics to monitoring systems
6. **Dynamic Routing**: Route packets based on destination IP
7. **QoS**: Implement quality of service policies

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - Overall system architecture
- [BUILD.md](BUILD.md) - Build instructions
- [DOCKER.md](DOCKER.md) - Docker deployment
- [TUN_ARCHITECTURE.md](TUN_ARCHITECTURE.md) - TUN device details

## Made with Bob