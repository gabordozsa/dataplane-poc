#ifndef FORWARDER_H
#define FORWARDER_H

#include "dtls_context.h"
#include "connection.h"
#include "iouring.h"
#include <netinet/in.h>

/**
 * Forwarder connection role
 */
typedef enum {
    FORWARDER_ROLE_CLIENT,  // Initiates connection (outbound)
    FORWARDER_ROLE_SERVER   // Accepts connection (inbound)
} forwarder_role_t;

static char *FORWARDER_ROLE_STR[] = {"CLIENT", "SERVER"};

/**
 * Forwarder connection state
 */
typedef struct forwarder_connection {
    int udp_fd;
    dtls_ctx_t *dtls_ctx;
    connection_t dtls_conn;       // DTLS connection
    forwarder_role_t role;        // Client or server role
    //struct sockaddr_storage addr; // Remote address
    //socklen_t addr_len;           // Address length
    int established;              // Connection established flag
    // statistics
    uint64_t packets_forwarded;
    uint64_t bytes_forwarded;
} forwarder_connection_t;

/**
 * Forwarder context - manages two DTLS sessions
 */
typedef struct forwarder_ctx {
    // Network components
    iouring_ctx_t *uring_ctx;        // io-uring context

    // Two connections
    forwarder_connection_t *outbound;  // Connection we initiate
    forwarder_connection_t *inbound;   // Connection we accept
} forwarder_ctx_t;

/**
 * Create forwarder context
 * @param remote_host Outbound UDP connection target host
 * @param remote_port Outbound UDP connection target port
 * @param inbound_port Local UDP port for inbound connections
 * @param outbound_port Local UDP port for outbound connections
 * @param cert_file Certificate file for server role
 * @param key_file Private key file for server role
 * @param ca_file CA certificate file for client role
 * @return Forwarder context or NULL on failure
 */
forwarder_ctx_t *forwarder_create(const char *remote_host, uint16_t remote_port,
                                  uint16_t inbound_port, uint16_t outbound_port,
                                  const char *cert_file, const char *key_file,
                                  const char *ca_file);

/**
 * Destroy forwarder context
 * @param ctx Forwarder context
 */
void forwarder_destroy(forwarder_ctx_t *ctx);

/**
 * Initiate outbound DTLS connection
 * @param ctx Forwarder context
 * @param host Remote host
 * @param port Remote port
 * @return 0 on success, -1 on failure
 */
int forwarder_connect_outbound(forwarder_ctx_t *ctx, const char *host, uint16_t port);

/**
 * Run forwarder main loop
 * @param ctx Forwarder context
 * @return 0 on success, -1 on failure
 */
int forwarder_run(forwarder_ctx_t *ctx);

/**
 * Forward packet from one connection to another
 * @param ctx Forwarder context
 * @param from_conn Source connection
 * @param to_conn Destination connection
 * @param data Packet data
 * @param len Packet length
 * @return 0 on success, -1 on failure
 */
int forwarder_forward_packet(forwarder_ctx_t *ctx,
                              forwarder_connection_t *from_conn,
                              forwarder_connection_t *to_conn,
                              const uint8_t *data, size_t len);

/**
 * Print forwarder statistics
 * @param ctx Forwarder context
 */
void forwarder_print_stats(forwarder_ctx_t *ctx);

/**
 * Decrypt udp packet payload
 */
int dtls_decrypt_packet(connection_t *dtls,
                        const uint8_t *encrypted, int encrypted_len,
                        uint8_t *decrypted, int decrypted_len);

/**
 * Encrypt udp packet payload
 */
int dtls_encrypt_packet(connection_t *dtls,
                        const uint8_t *data, int data_len,
                        uint8_t *result, int result_size);

/**
 * Receive a udp packet by uring
 */
io_op_t *recv_udp(iouring_ctx_t *uring_ctx);

/**
 * Send a udp packet by uring
 */
int send_udp(iouring_ctx_t *uring_ctx, forwarder_connection_t *conn,
             const uint8_t *encrypted, int encrypted_len);


#endif // FORWARDER_H

// Made with Bob