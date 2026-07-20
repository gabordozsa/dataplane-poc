#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include "iouring.h"
#include "connection.h"
#include "dtls_context.h"
#include <liburing.h>

/**
 * Encrypt and send packet via DTLS
 * @param conn Connection
 * @param data Plaintext data
 * @param len Data length
 * @param uring_ctx io-uring context
 * @return 0 on success, -1 on failure
 */
int dtls_encrypt_and_send_udp(connection_t *conn, const uint8_t *data,
                              size_t len, iouring_ctx_t *uring_ctx);


/**
 * Decrypt and write packet to TUN
 */
int dtls_decrypt_and_write_tun(connection_t *conn,
                               int tun_fd,
                               const uint8_t *encrypted, int encrypted_len,
                               iouring_ctx_t *uring_ctx);

/**
 * Wait for the next receive completion
 */
io_op_t *wait_for_recv(iouring_ctx_t *uring_ctx);

/**
 * Send UDP datagram by io_uring
 */
int send_udp(iouring_ctx_t *uring_ctx, connection_t *conn,
             const uint8_t *encrypted, int encrypted_len);

#endif // PACKET_HANDLER_H

/**
 * Forward IP packet from TUN to UDP socket
 */
int tun_to_udp(connection_t *conn,
               io_op_t *op,
               iouring_ctx_t *uring_ctx);

/**
 * Forward IP packet from UDP socket to TUN
 */
int udp_to_tun(int tun_fd,
               io_op_t *op,
               iouring_ctx_t *uring_ctx);
