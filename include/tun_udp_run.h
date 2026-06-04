#include "connection.h"
#include "iouring.h"

/**
 * Common event loop for client and server
 */
int tun_udp_run(iouring_ctx_t *uring_ctx, dtls_connection_t *conn, int tun_fd, volatile int *running);