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
#include <assert.h>

static volatile int running = 1;

static void signal_handler(int signum) {
    (void)signum;
    log_info("Received signal, shutting down...");
    running = 0;
}

static forwarder_connection_t* forwarder_create_connection(forwarder_role_t role,
                                                           const char *remote_host,
                                                           uint16_t remote_port,
                                                           uint16_t local_port,
                                                           const char *cert_file,
                                                           const char *key_file,
                                                           const char *ca_file) {

    if (role == FORWARDER_ROLE_CLIENT) {
        if (remote_host == NULL || remote_port == 0) {
            log_error("Remote host is NULL for CLIENT");
            return NULL;
        }
    } else if (cert_file == NULL || key_file == NULL) {
         log_error("Cert/key missing for SERVER");
         return NULL;
    }

    // Create connection structure
    forwarder_connection_t *conn = calloc(1, sizeof(forwarder_connection_t));
    if (!conn) {
        log_error("Failed to allocate connection");
        return NULL;
    }

    if (role == FORWARDER_ROLE_CLIENT) {
        // Resolve hostname
        int ret = resolve_hostname(remote_host, remote_port, (struct sockaddr *)(&conn->dtls_conn.addr), &conn->dtls_conn.addr_len);
        if (ret < 0) {
             free(conn);
            return NULL;
        }
        log_info("Resolved CLIENT address to %s", addr_to_string((const struct sockaddr *)&conn->dtls_conn.addr));
    }

    conn->role = role;
    const char *role_str = FORWARDER_ROLE_STR[role];

    // create UDP socket
    conn->udp_fd = udp_socket_create();
    if (conn->udp_fd < 0) {
        log_error("Failed to create UDP socket for %s", role_str);
        free(conn);
        return NULL;
    }
    // Bind udp socket to port
    if (udp_socket_bind(conn->udp_fd, local_port, NULL) < 0) {
        log_error("Failed to bind %s UDP socket to port %d", role_str, local_port);
        close(conn->udp_fd);
        free(conn);
        return NULL;
    }
    log_info("Created and bound %s UDP socket on port %d (fd=%d)",
             role_str, local_port, conn->udp_fd);

    // dtls context
    if (role == FORWARDER_ROLE_CLIENT)
        conn->dtls_ctx = dtls_client_context_init(ca_file);
    else
        conn->dtls_ctx = dtls_server_context_init(cert_file, key_file);

    if (!conn->dtls_ctx) {
        log_error("Failed to create %s DTLS context", role_str);
        close(conn->udp_fd);
        free(conn);
    }

    // Create SSL
    conn->dtls_conn.ssl = dtls_create_ssl(conn->dtls_ctx);
    if (!conn->dtls_conn.ssl) {
        log_error("Failed to create SSL for %s", role_str);
        SSL_free(conn->dtls_conn.ssl);
        close(conn->udp_fd);
        free(conn);
        return NULL;
    }

    // Setup BIO pair
    if (dtls_setup_bio_pair(conn->dtls_conn.ssl,
                            &conn->dtls_conn.rbio, 
                            &conn->dtls_conn.wbio) < 0) {
        log_error("Failed to setup BIO pair for %s", role_str);
        SSL_free(conn->dtls_conn.ssl);
        close(conn->udp_fd);
        free(conn);
        return NULL;
    }

    conn->dtls_conn.state = CONN_STATE_HANDSHAKING;
    conn->dtls_conn.last_activity = time(NULL);

    return conn;
}

forwarder_ctx_t *forwarder_create(const char *remote_host, uint16_t remote_port,
                                  uint16_t inbound_port, uint16_t outbound_port,
                                  const char *cert_file, const char *key_file,
                                  const char *ca_file) {
    forwarder_ctx_t *ctx = calloc(1, sizeof(forwarder_ctx_t));
    if (!ctx) {
        log_error("Failed to allocate forwarder context");
        return NULL;
    }

    // Create io-uring context
    ctx->uring_ctx = iouring_init(256);
    if (!ctx->uring_ctx) {
        log_error("Failed to create io-uring context");
        free(ctx);
        return NULL;
    }

    // Initialize OpenSSL
    dtls_library_init();

    ctx->inbound = forwarder_create_connection(FORWARDER_ROLE_SERVER,
                                                NULL, /*remote host */
                                                0, /* remote port */
                                                inbound_port,
                                                cert_file,
                                                key_file,
                                                NULL /* ca_file */);
    if (!ctx->inbound) {
        return NULL;
    }

    ctx->outbound = forwarder_create_connection(FORWARDER_ROLE_CLIENT,
                                                remote_host,
                                                remote_port,
                                                outbound_port,
                                                NULL, /* cert file */
                                                NULL, /* key file */
                                                ca_file);
    if (!ctx->outbound) {
        return NULL;
    }

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
    if (ctx->outbound) {
        if (ctx->outbound->dtls_conn.ssl) {
            SSL_free(ctx->outbound->dtls_conn.ssl);
        }
        if (ctx->outbound->dtls_ctx) {
            dtls_context_cleanup(ctx->outbound->dtls_ctx);
        }
    }

    if (ctx->inbound) {
        if (ctx->inbound->dtls_conn.ssl) {
            SSL_free(ctx->inbound->dtls_conn.ssl);
        }
        if (ctx->inbound->dtls_ctx) {
            dtls_context_cleanup(ctx->inbound->dtls_ctx);
        }
    }

    // Cleanup io-uring
    if (ctx->uring_ctx) {
        iouring_cleanup(ctx->uring_ctx);
    }

    // Close UDP sockets
    if (ctx->inbound && ctx->inbound->udp_fd >= 0) {
        close(ctx->inbound->udp_fd);
        free(ctx->inbound);
    }
    if (ctx->outbound && ctx->outbound->udp_fd >= 0) {
        close(ctx->outbound->udp_fd);
        free(ctx->outbound);
    }

    free(ctx);
    log_info("Forwarder context destroyed");
}

void forwarder_print_stats(forwarder_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    log_info("=== Forwarder Statistics ===");
    log_info("Outbound connection: %s", ctx->outbound->established ? "ESTABLISHED" : "NOT ESTABLISHED");
    log_info("Inbound connection: %s", ctx->inbound->established ? "ESTABLISHED" : "NOT ESTABLISHED");
    log_info("Packets forwarded to outbound: %lu", ctx->outbound->packets_forwarded);
    log_info("Bytes forwarded to outbound: %lu", ctx->outbound->bytes_forwarded);
    log_info("Packets forwarded to inbound: %lu", ctx->inbound->packets_forwarded);
    log_info("Bytes forwarded to inbound: %lu", ctx->inbound->bytes_forwarded);
    log_info("Total packets: %lu", ctx->outbound->packets_forwarded + ctx->inbound->packets_forwarded);
    log_info("Total bytes: %lu", ctx->outbound->bytes_forwarded + ctx->inbound->bytes_forwarded);
}

static int forward_udp_packet(forwarder_ctx_t *ctx, io_op_t *op) {

    int packet_len = op->data_len;
    struct sockaddr *src_addr = (struct sockaddr *)&op->addr;

    // Determine which connection based solely on which socket received the packet
    int from_inbound_socket = (op->udp_fd == ctx->inbound->udp_fd);
    log_debug("Received %d bytes from %s on %s socket (fd=%d)",
              packet_len, addr_to_string(src_addr),
              from_inbound_socket ? "inbound" : "outbound",
              op->udp_fd);

    if (packet_len <= 0) {
        log_warn("Connection closed or error occurred (packet_len: %d)", packet_len);
        return -1;
    }

    forwarder_connection_t *recv_conn = NULL;
    forwarder_connection_t *forward_conn = NULL;

    if (from_inbound_socket) {
        // Packet on inbound socket
        recv_conn = ctx->inbound;
        forward_conn = ctx->outbound;
        //log_debug("Packet from inbound connection");
    } else {
        recv_conn = ctx->outbound;
        forward_conn = ctx->inbound;
        //log_debug("Packet from outbound connection");
    }

    // Update receive activity
    connection_update_activity(&recv_conn->dtls_conn);

    uint8_t decrypted[PACKET_BUFFER_SIZE];
    int decrypted_len = dtls_decrypt_packet(&recv_conn->dtls_conn,
                                            op->buffer, packet_len,
                                            decrypted, sizeof(decrypted));
    if (decrypted_len <= 0) {
        return -1;
    }
    uint8_t encrypted[PACKET_BUFFER_SIZE];
    int encrypted_len = dtls_encrypt_packet(&forward_conn->dtls_conn,
                                            decrypted, decrypted_len,
                                            encrypted, sizeof(encrypted));
    if (encrypted_len <= 0) {
        return -1;
    }

    int ret = send_udp(ctx->uring_ctx, forward_conn, encrypted, encrypted_len);
    if (ret < 0) {
        return -1;
    }

    // Update statistics
    forward_conn->packets_forwarded++;
    forward_conn->bytes_forwarded += encrypted_len;

    return 0;
}

int dtls_encrypt_packet(connection_t *dtls,
                        const uint8_t *data, int data_len,
                        uint8_t *result, int result_size) {
    int written = SSL_write(dtls->ssl, data, data_len);
    if (written <= 0) {
        log_error("SSL_write failed: %s", dtls_get_error_string(dtls->ssl, written));
        return -1;
    }
    int read = BIO_read(dtls->wbio, result, result_size);
    if (read <= 0) {
        log_error("BIO read failed: %d, BIO should retry: %d", read, BIO_should_retry(dtls->wbio));
        return -1;
    }
    log_debug("Encypted packet, bytes: %d", read);
    return read;
}

int dtls_decrypt_packet(connection_t *dtls,
                        const uint8_t *encrypted, int encrypted_len,
                        uint8_t *decrypted, int decrypted_size) {
    int written = BIO_write(dtls->rbio, encrypted, encrypted_len);
    if (written <= 0) {
        log_error("BIO_write failed");
        return -1;
    }
    int read = SSL_read(dtls->ssl, decrypted, decrypted_size);
    int err = SSL_get_error(dtls->ssl, read);
    if (err != SSL_ERROR_NONE) {
        //if (err == SSL_ERROR_ZERO_RETURN) {
        //   close_dtls(dtls);
        //    return -1;
        //} else {
            log_error("SSL_read failed: %s", dtls_get_error_string(dtls->ssl, read));
            return -1;
    }
    log_debug("Decrypted packet, bytes: %d", read);
    return read;
}

int send_udp(iouring_ctx_t *uring_ctx, forwarder_connection_t *conn,
             const uint8_t *encrypted, int encrypted_len) {
    io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
    if (!op) {
        log_error("Could not allocate iop");
        return -1;
    }
    int ret = iouring_submit_udp_send(uring_ctx, conn->udp_fd, op,
                                      (struct sockaddr *)&conn->dtls_conn.addr, conn->dtls_conn.addr_len,
                                      encrypted, encrypted_len);
    return ret;
}

io_op_t *recv_udp(iouring_ctx_t *uring_ctx) {
    io_op_t *op = NULL;
    while (true) {
        struct io_uring_cqe *cqe;
        int wait_ret = iouring_wait_cqe(uring_ctx, &cqe);
        if (wait_ret < 0) {
            if (wait_ret == -ETIME) {
                log_debug("Waiting in recv_udp ...");
                    continue;
                }
            log_error("io_uring_wait_cqe failed");
            return NULL;
        }
        op = (io_op_t *)io_uring_cqe_get_data(cqe);
        int res = cqe->res;
         iouring_cqe_seen(uring_ctx, cqe);
        if (!op) {
            log_debug("CQE without io_op data");
            continue;
        }
        op->data_len = res;

        // Process based on operation type
        switch (op->op_type) {
            case OP_TYPE_UDP_RECV:
                if (res <= 0) {
                    log_error("UDP recv failed: %s", strerror(-res));
                    return NULL;
                }
                // Resubmit UDP receive on the same socket
                {
                    io_op_t *new_op = io_op_alloc(OP_TYPE_UDP_RECV);
                    if (new_op) {
                        new_op->udp_fd = op->udp_fd;
                        iouring_submit_udp_recv(uring_ctx, op->udp_fd, new_op);
                    }
                }
                return op;
                break;
            case OP_TYPE_UDP_SEND:
                if (res  < 0) {
                    log_error("UDP send failed: %s", strerror(-res));
                } else {
                    log_debug("Sent %d bytes via UDP", res);
                }
                io_op_free(op);
                continue;
            default:
                log_warn("Unknown operation type: %d", op->op_type);
                io_op_free(op);
                op = NULL;
                continue;
        }
    }

    return NULL;
}

int forwarder_run(forwarder_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }
    int ret = 0;

    log_info("Starting forwarder main loop");

    //time_t last_stats = time(NULL);

    // Main event loop
    while (true) {
        io_op_t *op = recv_udp(ctx->uring_ctx);
        if (!op) {
           return -1;
        }
        ret = forward_udp_packet(ctx, op);
        if (ret < 0)
            return ret;
        free(op);
    }
    return ret;
}

int do_dtls_handshake(iouring_ctx_t *uring_ctx, forwarder_connection_t *conn) {
    if (!conn) {
        log_error("No connection for handshake");
        return -1;
    }
    ERR_clear_error();

    int ret = 0;
    while (true) {
        ret = SSL_do_handshake(conn->dtls_conn.ssl);
        int err = SSL_get_error(conn->dtls_conn.ssl, ret);
        log_debug("Handshake:  SSL_do_handshake() ret: %d, err:%s", ret, ERR_error_string(err, NULL));
        // check if SSL wants to send data - this is necessary even if the handshake got completed locally!
        int ssl_send = BIO_ctrl_pending(conn->dtls_conn.wbio);
        if (ssl_send) {
            uint8_t buffer[PACKET_BUFFER_SIZE];
            int read = BIO_read(conn->dtls_conn.wbio, buffer, sizeof(buffer));
            assert(read > 0);
            io_op_t *new_op = io_op_alloc(OP_TYPE_UDP_SEND);
            assert(new_op);
            int ret = iouring_submit_udp_send(uring_ctx, conn->udp_fd, new_op,
                                              (struct sockaddr *)&conn->dtls_conn.addr,
                                              conn->dtls_conn.addr_len, buffer, read);
            if (ret < 0) {
                return -1;
            }
            log_debug("handshake sent response: %d bytes", read);
        }

        if (ret == 1) {
            conn->established = 1;
            break; // handshake completed
        } else if (ret == 0) {
            log_error("Handshake: SSL_do_handshake() error:%s", ERR_error_string(err, NULL));
            return -1;
        }

        switch(err) {
            case SSL_ERROR_WANT_READ:
                ret = BIO_ctrl_pending(conn->dtls_conn.rbio);
                if (ret) {
                    log_error("handshake: SSL wants to READ but RBIO has data (%d)", ret);
                    return -1;
                }
                // Receive UDP message
                io_op_t *op = recv_udp(uring_ctx);
                if (!op) {
                    return -1;
                }
                assert(op->op_type == OP_TYPE_UDP_RECV);
                if (op->udp_fd != conn->udp_fd) {
                    log_warn("handshake: received udp packet from different connection (fd expected:%d got:%d) Dropping it.", 
                             conn->udp_fd, op->udp_fd);
                    break;
                }

                if (conn->dtls_conn.addr_len == 0) {
                    // First packet
                    assert(op->addr_len > 0);
                    memcpy(&conn->dtls_conn.addr, &op->addr, op->addr_len);
                    conn->dtls_conn.addr_len = op->addr_len;
                }

                ret = BIO_write(conn->dtls_conn.rbio, op->buffer, op->data_len);
                log_debug("handshake: write RBIO: %d", ret);
                io_op_free(op);
                break;
            case SSL_ERROR_WANT_WRITE:
                ret = BIO_ctrl_pending(conn->dtls_conn.wbio);
                if (ret > 0) {
                    // We already emptied WBIO above
                    log_error("handshake: WBIO is not empty");
                    return -1;
                }
                break;
            default:
                log_error("handshake: SSL_do_handshake() error: %s", ERR_error_string(ret, NULL));
                return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr, "Usage: %s <inbound_port> <outbound_port> <cert_file> <key_file> <remote_host> <remote_port> [ca_file]\n", argv[0]);
        fprintf(stderr, "Example: %s 5000 5001 cert.pem key.pem server.example.com 4433 [ca.pem]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "The forwarder:\n");
        fprintf(stderr, "  - Listens on <inbound_port> for inbound DTLS connections\n");
        fprintf(stderr, "  - Uses <outbound_port> for outbound DTLS connection\n");
        fprintf(stderr, "  - Connects to <remote_host>:<remote_port> as outbound DTLS connection\n");
        fprintf(stderr, "  - Forwards IP packets between the two DTLS sessions\n");
        fprintf(stderr, "  - [ca_file] is optional for client certificate verification\n");
        return 1;
    }

    uint16_t inbound_port = atoi(argv[1]);
    uint16_t outbound_port = atoi(argv[2]);
    const char *cert_file = argv[3];
    const char *key_file = argv[4];
    const char *remote_host = argv[5];
    uint16_t remote_port = atoi(argv[6]);
    const char *ca_file = (argc > 7) ? argv[7] : NULL;

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
    log_info("CA certificate: %s", ca_file ? ca_file : "none (no client verification)");
    log_info("Remote endpoint: %s:%d", remote_host, remote_port);

    // Create forwarder context
    forwarder_ctx_t *ctx = forwarder_create(remote_host, remote_port, inbound_port, outbound_port, cert_file, key_file, ca_file);
    if (!ctx) {
        log_error("Failed to create forwarder context");
        return 1;
    }

    // Submit initial UDP receive operations for inbound socket
    for (int i = 0; i < 4; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV);
        if (op) {
            op->udp_fd = ctx->inbound->udp_fd;
            int ret = iouring_submit_udp_recv(ctx->uring_ctx, ctx->inbound->udp_fd, op);
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
            op->udp_fd = ctx->outbound->udp_fd;
            int ret = iouring_submit_udp_recv(ctx->uring_ctx, ctx->outbound->udp_fd, op);
            if (ret != 0) {
                log_error("Failed to submit outbound UDP recv %d", i);
                io_op_free(op);
            }
        }
    }

    log_info("Handshake STARTED - inbound");  
    int ret = do_dtls_handshake(ctx->uring_ctx, ctx->inbound);
    if (ret < 0) {
        log_info("Handshake FAILED - inbound");
        return ret;
    }
    log_info("Handshake COMPLETED - inbound");

    log_info("Handshake STARTED - outbound");
    ret = do_dtls_handshake(ctx->uring_ctx, ctx->outbound);
    if (ret < 0) {
        log_info("Handshake FAILED - outbound");
        return ret;
    }
    log_info("Handshake COMPLETED - outbound");

    // Run main loop
    ret = forwarder_run(ctx);

    // Cleanup
    log_info("Cleaning up...");
    forwarder_destroy(ctx);
    dtls_library_cleanup();

    log_info("Forwarder shutdown complete");
    return ret;
}

// Made with Bob