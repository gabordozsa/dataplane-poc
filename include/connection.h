#ifndef CONNECTION_H
#define CONNECTION_H

#include "dtls_context.h"
#include "iouring.h"
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <time.h>

/**
 *  UDP connection role
 */
typedef enum {
    CONN_ROLE_CLIENT,  // Initiates connection (outbound)
    CONN_ROLE_SERVER   // Accepts connection (inbound)
} conn_role_t;


// Connection states
typedef enum {
    CONN_STATE_HANDSHAKING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_CLOSING
} conn_state_t;

// Connection structure
typedef struct dtls_connection {
    int udp_fd;

    dtls_ctx_t *dtls_ctx;
    SSL *ssl;
    BIO *rbio;  // Read BIO (network → SSL)
    BIO *wbio;  // Write BIO (SSL → network)

    struct sockaddr_storage addr;  // UDP address (IP:port)
    socklen_t addr_len;

    conn_state_t state;
    time_t last_activity;

    struct connection *next;  // For hash table chaining
} dtls_connection_t;

/**
 * Return the role name as string
 */
char *conn_role_str(conn_role_t role);

/**
 * Create new dtls connection
 */
dtls_connection_t* create_dtls_connection(conn_role_t role,
                                          const char *remote_host,
                                          uint16_t remote_port,
                                          uint16_t local_port,
                                          const char *cert_file,
                                          const char *key_file,
                                          const char *ca_file);

/**
 * Decrypt udp packet payload
 */
int dtls_decrypt_packet(dtls_connection_t *dtls,
                        const uint8_t *encrypted, int encrypted_len,
                        uint8_t *decrypted, int decrypted_len);

/**
 * Encrypt udp packet payload
 */
int dtls_encrypt_packet(dtls_connection_t *dtls,
                        const uint8_t *data, int data_len,
                        uint8_t *result, int result_size);


/**
 * Start and complete DTLS handshake
 */
int do_dtls_handshake(iouring_ctx_t *uring_ctx, dtls_connection_t *conn);

#endif // CONNECTION_H

// Made with Bob
