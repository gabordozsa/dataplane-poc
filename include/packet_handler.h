#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include "iouring.h"
#include "connection.h"
#include "dtls_context.h"
#include <liburing.h>

/**
 * Handle TUN read completion (packet from TUN device)
 * For client: encrypt and send to server
 * For server: encrypt and send to appropriate client
 * @param cqe Completion queue entry
 * @param conn Connection (NULL for client single connection)
 * @param uring_ctx io-uring context
 * @return 0 on success, -1 on failure
 */
int handle_tun_read(struct io_uring_cqe *cqe, connection_t *conn,
                    iouring_ctx_t *uring_ctx);

/**
 * Handle UDP receive completion (encrypted packet from network)
 * Decrypt and write to TUN device
 * @param cqe Completion queue entry
 * @param conn_table Connection table (NULL for client)
 * @param conn Single connection (for client, NULL for server)
 * @param dtls_ctx DTLS context (for creating new connections on server)
 * @param uring_ctx io-uring context
 * @return 0 on success, -1 on failure
 */
int handle_udp_recv(struct io_uring_cqe *cqe, connection_table_t *conn_table,
                    connection_t *conn, dtls_ctx_t *dtls_ctx,
                    iouring_ctx_t *uring_ctx);

/**
 * Handle TUN write completion
 * @param cqe Completion queue entry
 * @return 0 on success, -1 on failure
 */
int handle_tun_write(struct io_uring_cqe *cqe);

/**
 * Handle UDP send completion
 * @param cqe Completion queue entry
 * @return 0 on success, -1 on failure
 */
int handle_udp_send(struct io_uring_cqe *cqe);

/**
 * Process DTLS handshake
 * @param conn Connection
 * @param uring_ctx io-uring context
 * @return 0 if handshake complete, 1 if in progress, -1 on error
 */
int process_dtls_handshake(connection_t *conn, iouring_ctx_t *uring_ctx);

/**
 * Encrypt and send packet via DTLS
 * @param conn Connection
 * @param data Plaintext data
 * @param len Data length
 * @param uring_ctx io-uring context
 * @return 0 on success, -1 on failure
 */
int dtls_encrypt_and_send(connection_t *conn, const uint8_t *data, size_t len,
                          iouring_ctx_t *uring_ctx);

/**
 * Receive and decrypt packet via DTLS
 * @param conn Connection
 * @param encrypted Encrypted data
 * @param encrypted_len Encrypted data length
 * @param decrypted Buffer for decrypted data
 * @param decrypted_size Size of decrypted buffer
 * @param uring_ctx io-uring context
 * @return Number of decrypted bytes on success, -1 on error
 */
int dtls_recv_and_decrypt(connection_t *conn, const uint8_t *encrypted,
                          size_t encrypted_len, uint8_t *decrypted,
                          size_t decrypted_size, iouring_ctx_t *uring_ctx);

#endif // PACKET_HANDLER_H

// Made with Bob
