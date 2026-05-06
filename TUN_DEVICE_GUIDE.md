# TUN Device Programming Guide

## What is a TUN Device?

A **TUN** (network TUNnel) device is a virtual network interface that operates at the **IP layer (Layer 3)**. It allows userspace programs to:
- Read IP packets from the kernel
- Write IP packets to the kernel
- Act as a virtual network interface

### TUN vs TAP

| Feature | TUN | TAP |
|---------|-----|-----|
| Layer | Layer 3 (IP) | Layer 2 (Ethernet) |
| Packets | IP packets | Ethernet frames |
| Headers | IP header only | Ethernet + IP headers |
| Use Case | VPN, tunnels | Bridge, virtual switch |
| Our Choice | ✅ TUN | ❌ TAP |

## How TUN Works

```
Application Layer
       ↕
  TUN Device (userspace program)
       ↕
  Kernel Network Stack
       ↕
  Physical Network Interface
```

### Example Flow

```
1. Application sends packet to 10.8.0.2
   ↓
2. Kernel routing: "10.8.0.0/24 is on tun0"
   ↓
3. Kernel writes packet to TUN device
   ↓
4. Our program reads packet from TUN fd
   ↓
5. Our program encrypts and sends over UDP
   ↓
6. Remote side receives, decrypts
   ↓
7. Remote side writes to its TUN device
   ↓
8. Remote kernel delivers to 10.8.0.2
```

## Creating a TUN Device

### Basic Creation

```c
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;
    
    // Open the TUN/TAP device
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    
    // Flags:
    // IFF_TUN   - TUN device (no Ethernet headers)
    // IFF_TAP   - TAP device (with Ethernet headers)
    // IFF_NO_PI - Do not provide packet information
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    // If a device name was specified, use it
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    
    // Create the device
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return err;
    }
    
    // Copy the actual device name back
    strcpy(dev, ifr.ifr_name);
    
    return fd;
}
```

### Usage Example

```c
char tun_name[IFNAMSIZ];
strcpy(tun_name, "tun0");

int tun_fd = tun_alloc(tun_name);
if (tun_fd < 0) {
    fprintf(stderr, "Failed to create TUN device\n");
    exit(1);
}

printf("TUN device %s created, fd=%d\n", tun_name, tun_fd);
```

## Configuring TUN Device

### Setting IP Address

```c
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int tun_set_ip(const char *dev, const char *ip, const char *netmask) {
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int sockfd;
    
    // Create socket for ioctl
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    
    // Set IP address
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFADDR");
        close(sockfd);
        return -1;
    }
    
    // Set netmask
    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, netmask, &addr->sin_addr);
    
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    return 0;
}
```

### Bringing Interface Up

```c
int tun_set_up(const char *dev) {
    struct ifreq ifr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    
    // Get current flags
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sockfd);
        return -1;
    }
    
    // Set UP flag
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    return 0;
}
```

### Setting MTU

```c
int tun_set_mtu(const char *dev, int mtu) {
    struct ifreq ifr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_mtu = mtu;
    
    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        perror("ioctl SIOCSIFMTU");
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    return 0;
}
```

## Reading from TUN Device

### Simple Read

```c
uint8_t buffer[2048];
ssize_t nread;

nread = read(tun_fd, buffer, sizeof(buffer));
if (nread < 0) {
    perror("read from TUN");
    return -1;
}

printf("Read %zd bytes from TUN\n", nread);
// buffer now contains an IP packet
```

### With io-uring

```c
void submit_tun_read(struct io_uring *ring, int tun_fd, uint8_t *buffer) {
    struct io_uring_sqe *sqe;
    
    sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "Could not get SQE\n");
        return;
    }
    
    io_uring_prep_read(sqe, tun_fd, buffer, 2048, 0);
    io_uring_sqe_set_data(sqe, (void *)TUN_READ_OP);
    
    io_uring_submit(ring);
}
```

## Writing to TUN Device

### Simple Write

```c
uint8_t ip_packet[100] = { /* IP packet data */ };
ssize_t nwritten;

nwritten = write(tun_fd, ip_packet, sizeof(ip_packet));
if (nwritten < 0) {
    perror("write to TUN");
    return -1;
}

printf("Wrote %zd bytes to TUN\n", nwritten);
// Kernel will now route this packet
```

### With io-uring

```c
void submit_tun_write(struct io_uring *ring, int tun_fd, 
                      const uint8_t *packet, size_t len) {
    struct io_uring_sqe *sqe;
    
    sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "Could not get SQE\n");
        return;
    }
    
    io_uring_prep_write(sqe, tun_fd, packet, len, 0);
    io_uring_sqe_set_data(sqe, (void *)TUN_WRITE_OP);
    
    io_uring_submit(ring);
}
```

## IP Packet Structure

### IPv4 Header

```c
struct iphdr {
    uint8_t  version_ihl;    // Version (4 bits) + IHL (4 bits)
    uint8_t  tos;            // Type of Service
    uint16_t tot_len;        // Total Length
    uint16_t id;             // Identification
    uint16_t frag_off;       // Flags + Fragment Offset
    uint8_t  ttl;            // Time to Live
    uint8_t  protocol;       // Protocol (TCP=6, UDP=17, ICMP=1)
    uint16_t check;          // Header Checksum
    uint32_t saddr;          // Source Address
    uint32_t daddr;          // Destination Address
};
```

### Parsing IP Packet

```c
#include <netinet/ip.h>

void parse_ip_packet(const uint8_t *packet, size_t len) {
    if (len < sizeof(struct iphdr)) {
        fprintf(stderr, "Packet too short\n");
        return;
    }
    
    struct iphdr *iph = (struct iphdr *)packet;
    
    uint8_t version = iph->version_ihl >> 4;
    uint8_t ihl = iph->version_ihl & 0x0F;
    uint8_t header_len = ihl * 4;
    
    printf("IP Version: %d\n", version);
    printf("Header Length: %d bytes\n", header_len);
    printf("Total Length: %d bytes\n", ntohs(iph->tot_len));
    printf("Protocol: %d\n", iph->protocol);
    
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
    
    printf("Source: %s\n", src);
    printf("Destination: %s\n", dst);
}
```

### Validating IP Packet

```c
bool validate_ip_packet(const uint8_t *packet, size_t len) {
    if (len < 20) {
        return false;  // Minimum IPv4 header size
    }
    
    uint8_t version = (packet[0] >> 4);
    if (version != 4 && version != 6) {
        return false;  // Only IPv4 and IPv6
    }
    
    if (version == 4) {
        struct iphdr *iph = (struct iphdr *)packet;
        uint16_t total_len = ntohs(iph->tot_len);
        
        if (total_len > len) {
            return false;  // Truncated packet
        }
        
        if (total_len < 20) {
            return false;  // Too short
        }
    }
    
    return true;
}
```

## Complete TUN Module Example

```c
// tun_device.h
#ifndef TUN_DEVICE_H
#define TUN_DEVICE_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int fd;
    char name[16];
    char ip[16];
    char netmask[16];
    int mtu;
} tun_device_t;

tun_device_t* tun_device_create(const char *name);
int tun_device_configure(tun_device_t *tun, const char *ip, 
                         const char *netmask, int mtu);
int tun_device_up(tun_device_t *tun);
void tun_device_destroy(tun_device_t *tun);

#endif

// tun_device.c
#include "tun_device.h"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

tun_device_t* tun_device_create(const char *name) {
    tun_device_t *tun = calloc(1, sizeof(tun_device_t));
    if (!tun) {
        return NULL;
    }
    
    struct ifreq ifr;
    int fd;
    
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        free(tun);
        return NULL;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    if (name) {
        strncpy(ifr.ifr_name, name, IFNAMSIZ);
    }
    
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        free(tun);
        return NULL;
    }
    
    tun->fd = fd;
    strncpy(tun->name, ifr.ifr_name, sizeof(tun->name) - 1);
    
    return tun;
}

int tun_device_configure(tun_device_t *tun, const char *ip,
                         const char *netmask, int mtu) {
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
    
    // Set IP address
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFADDR");
        close(sockfd);
        return -1;
    }
    
    // Set netmask
    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, netmask, &addr->sin_addr);
    
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        close(sockfd);
        return -1;
    }
    
    // Set MTU
    ifr.ifr_mtu = mtu;
    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        perror("ioctl SIOCSIFMTU");
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    
    strncpy(tun->ip, ip, sizeof(tun->ip) - 1);
    strncpy(tun->netmask, netmask, sizeof(tun->netmask) - 1);
    tun->mtu = mtu;
    
    return 0;
}

int tun_device_up(tun_device_t *tun) {
    struct ifreq ifr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
    
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sockfd);
        return -1;
    }
    
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    return 0;
}

void tun_device_destroy(tun_device_t *tun) {
    if (tun) {
        if (tun->fd >= 0) {
            close(tun->fd);
        }
        free(tun);
    }
}
```

## Shell Commands for TUN Management

### Create and Configure (Alternative to C code)

```bash
# Create TUN device
ip tuntap add mode tun name tun0

# Set IP address
ip addr add 10.8.0.1/24 dev tun0

# Set MTU
ip link set tun0 mtu 1400

# Bring up
ip link set tun0 up

# Add route
ip route add 10.8.0.0/24 dev tun0

# Delete TUN device
ip tuntap del mode tun name tun0
```

### Monitoring

```bash
# Show TUN interface
ip addr show tun0

# Show routes
ip route show

# Monitor traffic
tcpdump -i tun0 -n

# Show statistics
ip -s link show tun0
```

## Common Issues and Solutions

### Issue 1: Permission Denied

```bash
# Solution: Run with sudo or set capabilities
sudo ./vpn_client

# Or set capabilities (preferred)
sudo setcap cap_net_admin+ep ./vpn_client
```

### Issue 2: Device Already Exists

```c
// Check if device exists and delete it
system("ip link delete tun0 2>/dev/null");
// Then create new one
```

### Issue 3: Routing Not Working

```bash
# Enable IP forwarding (server side)
sudo sysctl -w net.ipv4.ip_forward=1

# Check routing table
ip route show

# Add missing route
ip route add 10.8.0.0/24 dev tun0
```

### Issue 4: MTU Problems

```bash
# Check current MTU
ip link show tun0

# Set appropriate MTU (account for DTLS overhead)
ip link set tun0 mtu 1400

# Test with ping
ping -M do -s 1372 10.8.0.2  # 1372 + 28 (IP+ICMP) = 1400
```

## Best Practices

1. **Always validate packets** before processing
2. **Set appropriate MTU** to avoid fragmentation
3. **Handle errors gracefully** (device creation, configuration)
4. **Clean up resources** on exit
5. **Use non-blocking I/O** with io-uring
6. **Log important events** for debugging
7. **Check permissions** before creating TUN device

## Security Considerations

1. **Validate packet headers** to prevent injection attacks
2. **Limit packet sizes** to prevent buffer overflows
3. **Check source/destination** addresses
4. **Implement rate limiting** to prevent DoS
5. **Use proper firewall rules** on TUN interface

## References

- Linux TUN/TAP documentation: `/usr/src/linux/Documentation/networking/tuntap.txt`
- Man pages: `man tun`, `man ip-link`, `man ip-route`
- Example code: `/usr/share/doc/iproute2/examples/`