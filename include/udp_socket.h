#ifndef UDP_SOCKET_H
#define UDP_SOCKET_H

#include <stdint.h>
#include <sys/socket.h>

/**
 * Create a UDP socket
 * @return Socket file descriptor on success, -1 on failure
 */
int udp_socket_create(void);

/**
 * Bind UDP socket to a specific port
 * @param fd Socket file descriptor
 * @param port Port number (host byte order)
 * @param addr Address to bind to (NULL for INADDR_ANY)
 * @return 0 on success, -1 on failure
 */
int udp_socket_bind(int fd, uint16_t port, const char *addr);

/**
 * Set socket to non-blocking mode
 * @param fd Socket file descriptor
 * @return 0 on success, -1 on failure
 */
int udp_socket_set_nonblocking(int fd);

/**
 * Set socket options for better performance
 * @param fd Socket file descriptor
 * @return 0 on success, -1 on failure
 */
int udp_socket_set_options(int fd);

/**
 * Close UDP socket
 * @param fd Socket file descriptor
 */
void udp_socket_close(int fd);

/**
 * Resolve hostname
 */
int resolve_hostname(const char *host, uint16_t port, struct sockaddr *addr, socklen_t *addr_len);

#endif // UDP_SOCKET_H

// Made with Bob
