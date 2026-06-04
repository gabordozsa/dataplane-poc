#ifndef FORWARDER_H
#define FORWARDER_H

#include "dtls_context.h"
#include "connection.h"
#include "iouring.h"
#include <netinet/in.h>

/**
 * Forwarder context - manages two DTLS sessions
 */
typedef struct forwarder_ctx {
    // Network components
    iouring_ctx_t *uring_ctx;        // io-uring context

    // Two connections
    dtls_connection_t *outbound;  // Connection we initiate
    dtls_connection_t *inbound;   // Connection we accept
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
                             dtls_connection_t *from_conn,
                             dtls_connection_t *to_conn,
                             const uint8_t *data, size_t len);



#endif // FORWARDER_H

// Made with Bob