#include "udp_socket.h"
#include "utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

int udp_socket_create(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }
    
    log_debug("Created UDP socket: fd=%d", fd);
    return fd;
}

int udp_socket_bind(int fd, uint16_t port, const char *addr) {
    struct sockaddr_in server_addr;
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (addr) {
        if (inet_pton(AF_INET, addr, &server_addr.sin_addr) != 1) {
            log_error("Invalid bind address: %s", addr);
            return -1;
        }
    } else {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    }
    
    if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Failed to bind UDP socket to port %d: %s", port, strerror(errno));
        return -1;
    }
    
    log_info("Bound UDP socket to %s:%d", 
             addr ? addr : "0.0.0.0", port);
    
    return 0;
}

int udp_socket_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        log_error("Failed to get socket flags: %s", strerror(errno));
        return -1;
    }
    
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_error("Failed to set non-blocking mode: %s", strerror(errno));
        return -1;
    }
    
    log_debug("Set socket fd=%d to non-blocking mode", fd);
    return 0;
}

int udp_socket_set_options(int fd) {
    int opt = 1;
    
    // Set SO_REUSEADDR to allow quick restart
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_warn("Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    // Set SO_REUSEPORT for load balancing (if available)
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        log_warn("Failed to set SO_REUSEPORT: %s", strerror(errno));
    }
#endif
    
    // Increase receive buffer size
    int rcvbuf = 1024 * 1024;  // 1MB
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        log_warn("Failed to set SO_RCVBUF: %s", strerror(errno));
    }
    
    // Increase send buffer size
    int sndbuf = 1024 * 1024;  // 1MB
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        log_warn("Failed to set SO_SNDBUF: %s", strerror(errno));
    }
    
    log_debug("Set socket options for fd=%d", fd);
    return 0;
}

void udp_socket_close(int fd) {
    if (fd >= 0) {
        log_debug("Closing UDP socket: fd=%d", fd);
        close(fd);
    }
}

int resolve_hostname(const char *host, uint16_t port, struct sockaddr *addr, socklen_t *addr_len) {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        log_error("Failed to resolve %s: %s", host, gai_strerror(ret));
        return -1;
    }
    // Copy address
    memcpy(addr, result->ai_addr, result->ai_addrlen);
    *addr_len = result->ai_addrlen;
    freeaddrinfo(result);
    return 0;
}
// Made with Bob
