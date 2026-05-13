#include "forwarder.h"
#include "udp_socket.h"
#include "packet_handler.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

static volatile int running = 1;

static void signal_handler(int signum) {
    (void)signum;
    log_info("Received signal, shutting down...");
    running = 0;
}

static connection_t* forwarder_create_connection(dtls_ctx_t *dtls_ctx,
                                                  const struct sockaddr *addr,
                                                  socklen_t addr_len) {
    if (!dtls_ctx || !addr) {
        return NULL;
    }
    
    // Create SSL
    SSL *ssl = dtls_create_ssl(dtls_ctx);
    if (!ssl) {
        log_error("Failed to create SSL");
        return NULL;
    }
    
    // Setup BIO pair
    BIO *rbio, *wbio;
    if (dtls_setup_bio_pair(ssl, &rbio, &wbio) < 0) {
        log_error("Failed to setup BIO pair");
        SSL_free(ssl);
        return NULL;
    }
    
    // Create connection structure
    connection_t *conn = calloc(1, sizeof(connection_t));
    if (!conn) {
        log_error("Failed to allocate connection");
        SSL_free(ssl);
        return NULL;
    }
    
    conn->ssl = ssl;
    conn->rbio = rbio;
    conn->wbio = wbio;
    memcpy(&conn->addr, addr, addr_len);
    conn->addr_len = addr_len;
    conn->state = CONN_STATE_HANDSHAKING;
    conn->last_activity = time(NULL);
    
    return conn;
}

static int forwarder_handle_handshake(forwarder_ctx_t *ctx,
                                       forwarder_connection_t *conn,
                                       const uint8_t *data, size_t len) {
    if (!ctx || !conn || !conn->conn || !data) {
        return -1;
    }
    
    // Feed data to SSL for handshake
    int written = BIO_write(conn->conn->rbio, data, len);
    log_debug("Wrote %d bytes to rbio for handshake", written);
    
    // Determine which UDP socket to use
    int udp_fd = (conn->role == FORWARDER_ROLE_CLIENT) ?
                 ctx->outbound_udp_fd : ctx->inbound_udp_fd;
    
    // Process handshake
    int hs_ret = process_dtls_handshake(conn->conn, udp_fd, ctx->uring_ctx);
    
    if (hs_ret == 0) {
        log_info("Handshake completed for %s connection",
                 conn->role == FORWARDER_ROLE_CLIENT ? "outbound" : "inbound");
        conn->established = 1;
        
        // Check if both connections are established
        if (ctx->outbound.established && ctx->inbound.established) {
            log_info("=== Both connections established - forwarding active ===");
        }
        return 0;
    } else if (hs_ret < 0) {
        log_error("Handshake failed for %s connection",
                  conn->role == FORWARDER_ROLE_CLIENT ? "outbound" : "inbound");
        return -1;
    }
    
    // Handshake in progress
    return 1;
}

static int forwarder_decrypt_and_forward(forwarder_ctx_t *ctx,
                                          forwarder_connection_t *recv_conn,
                                          forwarder_connection_t *forward_conn,
                                          const uint8_t *encrypted, size_t encrypted_len) {
    if (!ctx || !recv_conn || !forward_conn || !encrypted) {
        return -1;
    }
    
    // Determine which UDP socket to use
    int udp_fd = (recv_conn->role == FORWARDER_ROLE_CLIENT) ?
                 ctx->outbound_udp_fd : ctx->inbound_udp_fd;
    
    // Decrypt packet
    uint8_t decrypted[PACKET_BUFFER_SIZE];
    int decrypted_len = dtls_recv_and_decrypt(recv_conn->conn, udp_fd, encrypted,
                                               encrypted_len, decrypted,
                                               sizeof(decrypted), ctx->uring_ctx);
    
    if (decrypted_len > 0) {
        log_debug("Decrypted %d bytes", decrypted_len);
        
        // Validate as IP packet
        if (validate_ip_packet(decrypted, decrypted_len)) {
            print_ip_packet_info(decrypted, decrypted_len);
            
            // Forward to other connection
            return forwarder_forward_packet(ctx, recv_conn, forward_conn,
                                           decrypted, decrypted_len);
        } else {
            log_warn("Received non-IP packet, dropping");
            return -1;
        }
    } else if (decrypted_len < 0) {
        log_warn("Connection closed or error occurred");
        return -1;
    }
    
    return 0;
}

forwarder_ctx_t *forwarder_create(uint16_t inbound_port, uint16_t outbound_port,
                                   const char *cert_file, const char *key_file,
                                   const char *ca_file) {
    forwarder_ctx_t *ctx = calloc(1, sizeof(forwarder_ctx_t));
    if (!ctx) {
        log_error("Failed to allocate forwarder context");
        return NULL;
    }
    
    // Initialize OpenSSL
    dtls_library_init();
    
    // Create inbound UDP socket
    ctx->inbound_udp_fd = udp_socket_create();
    if (ctx->inbound_udp_fd < 0) {
        log_error("Failed to create inbound UDP socket");
        free(ctx);
        return NULL;
    }
    
    // Bind inbound socket to port
    if (udp_socket_bind(ctx->inbound_udp_fd, inbound_port, NULL) < 0) {
        log_error("Failed to bind inbound UDP socket to port %d", inbound_port);
        close(ctx->inbound_udp_fd);
        free(ctx);
        return NULL;
    }
    log_info("Created and bound inbound UDP socket on port %d (fd=%d)",
             inbound_port, ctx->inbound_udp_fd);
    
    // Create outbound UDP socket
    ctx->outbound_udp_fd = udp_socket_create();
    if (ctx->outbound_udp_fd < 0) {
        log_error("Failed to create outbound UDP socket");
        close(ctx->inbound_udp_fd);
        free(ctx);
        return NULL;
    }
    
    // Bind outbound socket to port
    if (udp_socket_bind(ctx->outbound_udp_fd, outbound_port, NULL) < 0) {
        log_error("Failed to bind outbound UDP socket to port %d", outbound_port);
        close(ctx->inbound_udp_fd);
        close(ctx->outbound_udp_fd);
        free(ctx);
        return NULL;
    }
    log_info("Created and bound outbound UDP socket on port %d (fd=%d)",
             outbound_port, ctx->outbound_udp_fd);
    
    // Create io-uring context
    ctx->uring_ctx = iouring_init(256);
    if (!ctx->uring_ctx) {
        log_error("Failed to create io-uring context");
        close(ctx->inbound_udp_fd);
        close(ctx->outbound_udp_fd);
        free(ctx);
        return NULL;
    }
    
    // Create server DTLS context (for accepting inbound connections)
    ctx->server_dtls_ctx = dtls_server_context_init(cert_file, key_file);
    if (!ctx->server_dtls_ctx) {
        log_error("Failed to create server DTLS context");
        iouring_cleanup(ctx->uring_ctx);
        close(ctx->inbound_udp_fd);
        close(ctx->outbound_udp_fd);
        free(ctx);
        return NULL;
    }
    log_info("Created server DTLS context");
    
    // Create client DTLS context (for initiating outbound connection)
    ctx->client_dtls_ctx = dtls_client_context_init(ca_file);
    if (!ctx->client_dtls_ctx) {
        log_error("Failed to create client DTLS context");
        dtls_context_cleanup(ctx->server_dtls_ctx);
        iouring_cleanup(ctx->uring_ctx);
        close(ctx->inbound_udp_fd);
        close(ctx->outbound_udp_fd);
        free(ctx);
        return NULL;
    }
    log_info("Created client DTLS context");
    
    // Initialize connection structures
    ctx->outbound.role = FORWARDER_ROLE_CLIENT;
    ctx->outbound.established = 0;
    ctx->outbound.conn = NULL;
    
    ctx->inbound.role = FORWARDER_ROLE_SERVER;
    ctx->inbound.established = 0;
    ctx->inbound.conn = NULL;
    
    log_info("Forwarder context created successfully");
    return ctx;
}

void forwarder_destroy(forwarder_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    
    log_info("Destroying forwarder context");
    
    // Print final statistics
    forwarder_print_stats(ctx);
    
    // Cleanup connections
    if (ctx->outbound.conn) {
        if (ctx->outbound.conn->ssl) {
            SSL_free(ctx->outbound.conn->ssl);
        }
        free(ctx->outbound.conn);
    }
    
    if (ctx->inbound.conn) {
        if (ctx->inbound.conn->ssl) {
            SSL_free(ctx->inbound.conn->ssl);
        }
        free(ctx->inbound.conn);
    }
    
    // Cleanup DTLS contexts
    if (ctx->server_dtls_ctx) {
        dtls_context_cleanup(ctx->server_dtls_ctx);
    }
    
    if (ctx->client_dtls_ctx) {
        dtls_context_cleanup(ctx->client_dtls_ctx);
    }
    
    // Cleanup io-uring
    if (ctx->uring_ctx) {
        iouring_cleanup(ctx->uring_ctx);
    }
    
    // Close UDP sockets
    if (ctx->inbound_udp_fd >= 0) {
        close(ctx->inbound_udp_fd);
    }
    if (ctx->outbound_udp_fd >= 0) {
        close(ctx->outbound_udp_fd);
    }
    
    free(ctx);
    log_info("Forwarder context destroyed");
}

int forwarder_connect_outbound(forwarder_ctx_t *ctx, const char *host, uint16_t port) {
    if (!ctx || !host) {
        return -1;
    }
    
    log_info("Initiating outbound connection to %s:%d", host, port);
    
    // Resolve hostname
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        log_error("Failed to resolve %s: %s", host, gai_strerror(ret));
        return -1;
    }
    
    // Copy address
    memcpy(&ctx->outbound.addr, result->ai_addr, result->ai_addrlen);
    ctx->outbound.addr_len = result->ai_addrlen;
    freeaddrinfo(result);
    
    log_info("Resolved to %s", addr_to_string((struct sockaddr *)&ctx->outbound.addr));
    
    // Create connection structure
    ctx->outbound.conn = forwarder_create_connection(ctx->client_dtls_ctx,
                                                      (struct sockaddr *)&ctx->outbound.addr,
                                                      ctx->outbound.addr_len);
    if (!ctx->outbound.conn) {
        log_error("Failed to create outbound connection");
        return -1;
    }
    
    log_info("Created outbound connection structure");
    
    // Initiate handshake
    log_info("Starting DTLS handshake with %s:%d", host, port);
    int hs_ret = process_dtls_handshake(ctx->outbound.conn, ctx->outbound_udp_fd, ctx->uring_ctx);
    if (hs_ret < 0) {
        log_error("Failed to initiate handshake");
        return -1;
    }
    
    log_info("Outbound connection initiated");
    return 0;
}

int forwarder_forward_packet(forwarder_ctx_t *ctx,
                              forwarder_connection_t *from_conn,
                              forwarder_connection_t *to_conn,
                              const uint8_t *data, size_t len) {
    if (!ctx || !from_conn || !to_conn || !data || len == 0) {
        return -1;
    }
    
    if (!to_conn->established || !to_conn->conn) {
        log_debug("Destination connection not established, dropping packet");
        return -1;
    }
    
    // Determine which UDP socket to use based on destination connection
    int udp_fd = (to_conn->role == FORWARDER_ROLE_CLIENT) ?
                 ctx->outbound_udp_fd : ctx->inbound_udp_fd;
    
    // Encrypt and send to destination
    int ret = dtls_encrypt_and_send(to_conn->conn, udp_fd, data, len, ctx->uring_ctx);
    if (ret < 0) {
        log_error("Failed to forward packet");
        return -1;
    }
    
    // Update statistics
    if (to_conn->role == FORWARDER_ROLE_CLIENT) {
        ctx->packets_forwarded_out++;
        ctx->bytes_forwarded_out += len;
    } else {
        ctx->packets_forwarded_in++;
        ctx->bytes_forwarded_in += len;
    }
    
    log_debug("Forwarded %zu bytes: %s -> %s", len,
              addr_to_string((struct sockaddr *)&from_conn->addr),
              addr_to_string((struct sockaddr *)&to_conn->addr));
    
    return 0;
}

void forwarder_print_stats(forwarder_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    
    log_info("=== Forwarder Statistics ===");
    log_info("Outbound connection: %s", ctx->outbound.established ? "ESTABLISHED" : "NOT ESTABLISHED");
    log_info("Inbound connection: %s", ctx->inbound.established ? "ESTABLISHED" : "NOT ESTABLISHED");
    log_info("Packets forwarded to outbound: %lu", ctx->packets_forwarded_out);
    log_info("Bytes forwarded to outbound: %lu", ctx->bytes_forwarded_out);
    log_info("Packets forwarded to inbound: %lu", ctx->packets_forwarded_in);
    log_info("Bytes forwarded to inbound: %lu", ctx->bytes_forwarded_in);
    log_info("Total packets: %lu", ctx->packets_forwarded_out + ctx->packets_forwarded_in);
    log_info("Total bytes: %lu", ctx->bytes_forwarded_out + ctx->bytes_forwarded_in);
}

static int handle_udp_packet(forwarder_ctx_t *ctx, struct io_uring_cqe *cqe, io_op_t *op) {
    if (cqe->res <= 0) {
        log_error("UDP recv failed: %s", strerror(-cqe->res));
        return -1;
    }
    
    int packet_len = cqe->res;
    struct sockaddr *src_addr = (struct sockaddr *)&op->addr;
    
    // Determine which connection based solely on which socket received the packet
    int from_inbound_socket = (op->udp_fd == ctx->inbound_udp_fd);
    log_debug("Received %d bytes from %s on %s socket (fd=%d)",
              packet_len, addr_to_string(src_addr),
              from_inbound_socket ? "inbound" : "outbound",
              op->udp_fd);
    
    forwarder_connection_t *recv_conn = NULL;
    forwarder_connection_t *forward_conn = NULL;
    
    if (from_inbound_socket) {
        // Packet on inbound socket
        if (!ctx->inbound.conn) {
            // New inbound connection
            log_info("New inbound connection from %s", addr_to_string(src_addr));
            
            // Create connection structure
            ctx->inbound.conn = forwarder_create_connection(ctx->server_dtls_ctx,
                                                            src_addr,
                                                            op->addr_len);
            if (!ctx->inbound.conn) {
                log_error("Failed to create inbound connection");
                return -1;
            }
            
            // Store address in forwarder connection structure
            memcpy(&ctx->inbound.addr, src_addr, op->addr_len);
            ctx->inbound.addr_len = op->addr_len;
            
            log_info("Created inbound connection structure");
        }
        
        recv_conn = &ctx->inbound;
        forward_conn = &ctx->outbound;
        log_debug("Packet from inbound connection");
    } else {
        // Packet on outbound socket - must be from outbound connection
        if (!ctx->outbound.conn) {
            log_warn("Received packet on outbound socket but no outbound connection exists");
            return -1;
        }
        
        recv_conn = &ctx->outbound;
        forward_conn = &ctx->inbound;
        log_debug("Packet from outbound connection");
    }
    
    // Update activity
    if (recv_conn->conn) {
        connection_update_activity(recv_conn->conn);
    }
    
    // Process based on connection state
    if (recv_conn->conn->state == CONN_STATE_HANDSHAKING) {
        // Handle DTLS handshake
        int hs_ret = forwarder_handle_handshake(ctx, recv_conn, op->buffer, packet_len);
        if (hs_ret < 0) {
            return -1;
        }
    } else if (recv_conn->conn->state == CONN_STATE_ESTABLISHED) {
        // Decrypt and forward packet
        forwarder_decrypt_and_forward(ctx, recv_conn, forward_conn,
                                     op->buffer, packet_len);
    }
    
    return 0;
}

int forwarder_run(forwarder_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }
    
    log_info("Starting forwarder main loop");
    
    // Submit initial UDP receive operations for inbound socket
    for (int i = 0; i < 4; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV);
        if (op) {
            op->udp_fd = ctx->inbound_udp_fd;
            int ret = iouring_submit_udp_recv(ctx->uring_ctx, ctx->inbound_udp_fd, op);
            if (ret != 0) {
                log_error("Failed to submit inbound UDP recv %d", i);
                io_op_free(op);
            }
        }
    }
    
    // Submit initial UDP receive operations for outbound socket
    for (int i = 0; i < 4; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV);
        if (op) {
            op->udp_fd = ctx->outbound_udp_fd;
            int ret = iouring_submit_udp_recv(ctx->uring_ctx, ctx->outbound_udp_fd, op);
            if (ret != 0) {
                log_error("Failed to submit outbound UDP recv %d", i);
                io_op_free(op);
            }
        }
    }
    
    time_t last_stats = time(NULL);
    
    // Main event loop
    while (running) {
        struct io_uring_cqe *cqe;
        
        // Wait for completion event with timeout
        int wait_ret = iouring_wait_cqe(ctx->uring_ctx, &cqe);
        if (wait_ret < 0) {
            if (wait_ret == -ETIME) {
                // Timeout - print stats periodically
                time_t now = time(NULL);
                if (now - last_stats >= 30) {
                    forwarder_print_stats(ctx);
                    last_stats = now;
                }
                continue;
            }
            log_error("io_uring_wait_cqe failed");
            break;
        }
        
        io_op_t *op = (io_op_t *)io_uring_cqe_get_data(cqe);
        if (!op) {
            iouring_cqe_seen(ctx->uring_ctx, cqe);
            continue;
        }
        
        // Process based on operation type
        switch (op->op_type) {
            case OP_TYPE_UDP_RECV:
                handle_udp_packet(ctx, cqe, op);
                
                // Resubmit UDP receive on the same socket
                {
                    int udp_fd = op->udp_fd;
                    io_op_free(op);
                    
                    io_op_t *new_op = io_op_alloc(OP_TYPE_UDP_RECV);
                    if (new_op) {
                        new_op->udp_fd = udp_fd;
                        iouring_submit_udp_recv(ctx->uring_ctx, udp_fd, new_op);
                    }
                }
                break;
                
            case OP_TYPE_UDP_SEND:
                if (cqe->res < 0) {
                    log_error("UDP send failed: %s", strerror(-cqe->res));
                } else {
                    log_debug("Sent %d bytes via UDP", cqe->res);
                }
                io_op_free(op);
                break;
                
            default:
                log_warn("Unknown operation type: %d", op->op_type);
                io_op_free(op);
                break;
        }
        
        iouring_cqe_seen(ctx->uring_ctx, cqe);
    }
    
    log_info("Forwarder main loop exited");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 8) {
        fprintf(stderr, "Usage: %s <inbound_port> <outbound_port> <cert_file> <key_file> <ca_file> <remote_host> <remote_port>\n", argv[0]);
        fprintf(stderr, "Example: %s 5000 5001 cert.pem key.pem ca.pem server.example.com 4433\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "The forwarder:\n");
        fprintf(stderr, "  - Listens on <inbound_port> for inbound DTLS connections\n");
        fprintf(stderr, "  - Uses <outbound_port> for outbound DTLS connection\n");
        fprintf(stderr, "  - Connects to <remote_host>:<remote_port> as outbound DTLS connection\n");
        fprintf(stderr, "  - Forwards IP packets between the two DTLS sessions\n");
        return 1;
    }
    
    uint16_t inbound_port = atoi(argv[1]);
    uint16_t outbound_port = atoi(argv[2]);
    const char *cert_file = argv[3];
    const char *key_file = argv[4];
    const char *ca_file = argv[5];
    const char *remote_host = argv[6];
    uint16_t remote_port = atoi(argv[7]);
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize logging
    log_set_level(LOG_DEBUG);
    log_info("Starting DTLS Forwarder");
    log_info("Inbound port: %d", inbound_port);
    log_info("Outbound port: %d", outbound_port);
    log_info("Certificate: %s", cert_file);
    log_info("Private key: %s", key_file);
    log_info("CA certificate: %s", ca_file);
    log_info("Remote endpoint: %s:%d", remote_host, remote_port);
    
    // Create forwarder context
    forwarder_ctx_t *ctx = forwarder_create(inbound_port, outbound_port, cert_file, key_file, ca_file);
    if (!ctx) {
        log_error("Failed to create forwarder context");
        return 1;
    }
    
    // Initiate outbound connection
    if (forwarder_connect_outbound(ctx, remote_host, remote_port) < 0) {
        log_error("Failed to initiate outbound connection");
        forwarder_destroy(ctx);
        return 1;
    }
    
    log_info("Forwarder ready - waiting for inbound connection and forwarding packets");
    
    // Run main loop
    int ret = forwarder_run(ctx);
    
    // Cleanup
    log_info("Cleaning up...");
    forwarder_destroy(ctx);
    dtls_library_cleanup();
    
    log_info("Forwarder shutdown complete");
    return ret;
}

// Made with Bob