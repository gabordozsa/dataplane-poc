#include "connection.h"
#include "utils.h"
#include "iouring.h"
#include "packet_handler.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

connection_table_t* connection_table_init(size_t bucket_count, size_t max_connections) {
    connection_table_t *table = calloc(1, sizeof(connection_table_t));
    if (!table) {
        log_error("Failed to allocate connection table");
        return NULL;
    }
    
    table->buckets = calloc(bucket_count, sizeof(connection_t *));
    if (!table->buckets) {
        log_error("Failed to allocate connection table buckets");
        free(table);
        return NULL;
    }
    
    table->bucket_count = bucket_count;
    table->max_connections = max_connections;
    table->conn_count = 0;
    
    log_info("Initialized connection table: %zu buckets, max %zu connections",
             bucket_count, max_connections);
    
    return table;
}

connection_t* connection_find(connection_table_t *table, const struct sockaddr *addr) {
    if (!table || !addr) {
        return NULL;
    }
    
    uint32_t hash = addr_hash(addr, table->bucket_count);
    connection_t *conn = table->buckets[hash];
    
    while (conn) {
        if (addr_compare((struct sockaddr *)&conn->addr, addr) == 0) {
            return conn;
        }
        conn = conn->next;
    }
    
    return NULL;
}

connection_t* connection_find_by_tunnel_ip(connection_table_t *table, uint32_t tunnel_ip) {
    if (!table || tunnel_ip == 0) {
        return NULL;
    }
    
    // Linear search through all connections
    // In production, you'd want a separate hash table for tunnel IPs
    for (size_t i = 0; i < table->bucket_count; i++) {
        connection_t *conn = table->buckets[i];
        while (conn) {
            if (conn->tunnel_ip == tunnel_ip && conn->state == CONN_STATE_ESTABLISHED) {
                return conn;
            }
            conn = conn->next;
        }
    }
    
    return NULL;
}

void connection_set_tunnel_ip(connection_t *conn, uint32_t tunnel_ip) {
    if (conn) {
        conn->tunnel_ip = tunnel_ip;
        
        // Log the tunnel IP in human-readable format
        struct in_addr addr;
        addr.s_addr = tunnel_ip;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        log_debug("Set tunnel IP for connection: %s", ip_str);
    }
}

connection_t* connection_create(connection_table_t *table, SSL *ssl,
                                BIO *rbio, BIO *wbio,
                                const struct sockaddr *addr, socklen_t addr_len) {
    if (!table || !ssl || !rbio || !wbio || !addr) {
        log_error("Invalid parameters for connection creation");
        return NULL;
    }
    
    // Check connection limit
    if (table->conn_count >= table->max_connections) {
        log_error("Connection limit reached: %zu", table->max_connections);
        return NULL;
    }
    
    // Check if connection already exists
    if (connection_find(table, addr)) {
        log_warn("Connection already exists for this address");
        return NULL;
    }
    
    connection_t *conn = calloc(1, sizeof(connection_t));
    if (!conn) {
        log_error("Failed to allocate connection");
        return NULL;
    }
    
    conn->ssl = ssl;
    conn->rbio = rbio;
    conn->wbio = wbio;
    addr_copy(&conn->addr, addr, addr_len);
    conn->addr_len = addr_len;
    conn->state = CONN_STATE_HANDSHAKING;
    conn->last_activity = time(NULL);
    conn->next = NULL;
    
    // Add to hash table
    uint32_t hash = addr_hash(addr, table->bucket_count);
    conn->next = table->buckets[hash];
    table->buckets[hash] = conn;
    table->conn_count++;
    
    char addr_str[64];
    addr_to_string(addr, addr_str, sizeof(addr_str));
    log_info("Created connection from %s (total: %zu)", addr_str, table->conn_count);
    
    return conn;
}

void connection_destroy(connection_table_t *table, connection_t *conn) {
    if (!table || !conn) {
        return;
    }
    
    char addr_str[64];
    addr_to_string((struct sockaddr *)&conn->addr, addr_str, sizeof(addr_str));
    
    // Remove from hash table
    uint32_t hash = addr_hash((struct sockaddr *)&conn->addr, table->bucket_count);
    connection_t **curr = &table->buckets[hash];
    
    while (*curr) {
        if (*curr == conn) {
            *curr = conn->next;
            break;
        }
        curr = &(*curr)->next;
    }
    
    // Cleanup SSL (this also frees the BIOs)
    if (conn->ssl) {
        SSL_free(conn->ssl);
    }
    
    free(conn);
    table->conn_count--;
    
    log_info("Destroyed connection from %s (remaining: %zu)", 
             addr_str, table->conn_count);
}

void connection_update_activity(connection_t *conn) {
    if (conn) {
        conn->last_activity = time(NULL);
    }
}

int connection_cleanup_idle(connection_table_t *table, time_t timeout, void *uring_ctx_ptr) {
    if (!table) {
        return 0;
    }
    
    iouring_ctx_t *uring_ctx = (iouring_ctx_t *)uring_ctx_ptr;
    time_t now = time(NULL);
    int cleaned = 0;
    
    for (size_t i = 0; i < table->bucket_count; i++) {
        connection_t **curr = &table->buckets[i];
        
        while (*curr) {
            connection_t *conn = *curr;
            
            if (now - conn->last_activity > timeout) {
                char addr_str[64];
                addr_to_string((struct sockaddr *)&conn->addr, addr_str, sizeof(addr_str));
                log_info("Cleaning up idle connection from %s (idle for %ld seconds)",
                         addr_str, now - conn->last_activity);
                
                // Send close_notify alert before destroying connection
                if (conn->ssl && conn->state == CONN_STATE_ESTABLISHED && uring_ctx) {
                    log_debug("Sending close_notify to %s", addr_str);
                    
                    // Call SSL_shutdown to generate close_notify
                    int shutdown_ret = SSL_shutdown(conn->ssl);
                    log_debug("SSL_shutdown returned: %d", shutdown_ret);
                    
                    // Check if SSL generated close_notify data to send
                    int pending = BIO_ctrl_pending(conn->wbio);
                    if (pending > 0) {
                        uint8_t buffer[PACKET_BUFFER_SIZE];
                        int read = BIO_read(conn->wbio, buffer, sizeof(buffer));
                        if (read > 0) {
                            io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
                            if (op) {
                                iouring_submit_udp_send(uring_ctx, op,
                                                      (struct sockaddr *)&conn->addr,
                                                      conn->addr_len, buffer, read);
                                log_info("Sent close_notify (%d bytes) to %s", read, addr_str);
                            }
                        }
                    } else {
                        log_debug("No close_notify data generated");
                    }
                }
                
                *curr = conn->next;
                
                if (conn->ssl) {
                    SSL_free(conn->ssl);
                }
                free(conn);
                table->conn_count--;
                cleaned++;
            } else {
                curr = &conn->next;
            }
        }
    }
    
    if (cleaned > 0) {
        log_info("Cleaned up %d idle connections (remaining: %zu)",
                 cleaned, table->conn_count);
    }
    
    return cleaned;
}

void connection_table_cleanup(connection_table_t *table) {
    if (!table) {
        return;
    }
    
    log_info("Cleaning up connection table (%zu connections)", table->conn_count);
    
    for (size_t i = 0; i < table->bucket_count; i++) {
        connection_t *conn = table->buckets[i];
        
        while (conn) {
            connection_t *next = conn->next;
            
            if (conn->ssl) {
                SSL_free(conn->ssl);
            }
            free(conn);
            
            conn = next;
        }
    }
    
    free(table->buckets);
    free(table);
}

// Made with Bob
