#ifndef CONNECTION_H
#define CONNECTION_H

#include <openssl/ssl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <time.h>

// Connection states
typedef enum {
    CONN_STATE_HANDSHAKING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_CLOSING
} conn_state_t;

// Connection structure
typedef struct connection {
    SSL *ssl;
    BIO *rbio;  // Read BIO (network → SSL)
    BIO *wbio;  // Write BIO (SSL → network)
    
    struct sockaddr_storage addr;  // UDP address (IP:port)
    socklen_t addr_len;
    
    uint32_t tunnel_ip;  // Client's VPN tunnel IP (network byte order)
    
    conn_state_t state;
    time_t last_activity;
    
    struct connection *next;  // For hash table chaining
} connection_t;

// Connection table (hash table)
typedef struct {
    connection_t **buckets;
    size_t bucket_count;
    size_t conn_count;
    size_t max_connections;
} connection_table_t;

/**
 * Initialize connection table
 * @param bucket_count Number of hash buckets
 * @param max_connections Maximum number of connections
 * @return Pointer to connection_table_t on success, NULL on failure
 */
connection_table_t* connection_table_init(size_t bucket_count, size_t max_connections);

/**
 * Find connection by UDP address
 * @param table Connection table
 * @param addr Client UDP address
 * @return Pointer to connection_t if found, NULL otherwise
 */
connection_t* connection_find(connection_table_t *table, const struct sockaddr *addr);

/**
 * Find connection by tunnel IP address
 * @param table Connection table
 * @param tunnel_ip Tunnel IP address (network byte order)
 * @return Pointer to connection_t if found, NULL otherwise
 */
connection_t* connection_find_by_tunnel_ip(connection_table_t *table, uint32_t tunnel_ip);

/**
 * Set tunnel IP for a connection
 * @param conn Connection
 * @param tunnel_ip Tunnel IP address (network byte order)
 */
void connection_set_tunnel_ip(connection_t *conn, uint32_t tunnel_ip);

/**
 * Create new connection
 * @param table Connection table
 * @param ssl SSL object
 * @param rbio Read BIO
 * @param wbio Write BIO
 * @param addr Client address
 * @param addr_len Address length
 * @return Pointer to connection_t on success, NULL on failure
 */
connection_t* connection_create(connection_table_t *table, SSL *ssl,
                                BIO *rbio, BIO *wbio,
                                const struct sockaddr *addr, socklen_t addr_len);

/**
 * Destroy connection
 * @param table Connection table
 * @param conn Connection to destroy
 */
void connection_destroy(connection_table_t *table, connection_t *conn);

/**
 * Update connection activity timestamp
 * @param conn Connection
 */
void connection_update_activity(connection_t *conn);

/**
 * Cleanup idle connections
 * @param table Connection table
 * @param timeout Timeout in seconds
 * @param uring_ctx IO uring context (for sending close_notify)
 * @return Number of connections cleaned up
 */
int connection_cleanup_idle(connection_table_t *table, time_t timeout, void *uring_ctx);

/**
 * Cleanup connection table and all connections
 * @param table Connection table
 */
void connection_table_cleanup(connection_table_t *table);

/**
 * Get connection count
 * @param table Connection table
 * @return Number of active connections
 */
static inline size_t connection_table_count(const connection_table_t *table) {
    return table ? table->conn_count : 0;
}

#endif // CONNECTION_H

// Made with Bob
