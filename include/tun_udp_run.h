#include "connection.h"
#include "iouring.h"

/**
 * Common event loop for edge client and server
 */
int tun_udp_run(iouring_ctx_t *uring_ctx, connection_t *conn, int tun_fd, volatile int *running);

/**
 * Common event loop for edge client and server without DTLS
 */
int tun_udp_run_zero(iouring_ctx_t *uring_ctx, connection_t *conn, int tun_fd, volatile int *running);