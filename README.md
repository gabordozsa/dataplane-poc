# DTLS Tunnel with io-uring

A high-performance VPN tunnel implementation using TUN devices for packet capture/injection, io-uring for asynchronous I/O, and OpenSSL DTLS for encryption. Creates a secure encrypted tunnel between client and server, routing IP packets through the secure channel.

## Features

- **TUN Device Integration**: Virtual network interface for packet capture and injection
- **Asynchronous I/O**: Uses io-uring for efficient, non-blocking operations
- **DTLS Encryption**: Secure UDP communication using OpenSSL DTLS 1.2
- **High Performance**: Handles thousands of concurrent connections with low latency
- **Connection Management**: Automatic connection tracking and lifecycle management
- **IP Packet Routing**: Full Layer 3 VPN functionality

## How It Works

The IP tunnel operates as follows:

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




## Usage

### Building

```
mkdir build
cd build
cmake -DCMAKEBUILD_TYPE=Release .. && make
```

Three exacutables are created:
- **edge**: forwards packets between a TUN and a UDP socket. UDP connection uses DTLS.
- **dtls_forwardwe**: forwards packets between two UDP sockets. UDP connections use DTLS.
- **edge_zero**: the same as **edge** but without DTLS - only for development/debugging.

### Running edge_zero (no DTLS) test

On the server site:
```
./edge_zero server <server_tun_ip> <server_udp_port>"
```
On the client site:
```
./edge_zero client <client_tun_ip> <server_udp_port> <server_ip>"
```

A new route must also be created at both sites to make sure that packets with
<remote_tun_ip> dest address are traveling via the local TUN iface.


Example iperf3 test, server site:
```
 ./edge_zero server 10.9.0.254 4433
ip route add 10.8.0.0/24 dev tun1
ipwrf3 -s
```
client site:
```
./edge_zero client 10.8.0.1 4433 10.16.142.61
ip route add 10.9.0.0/24 dev tun0
iperf3 -t 30  -c 10.9.0.254
```

