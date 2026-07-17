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

#define RING_DEPTH 8

// Note: we use multi-shot recvmsg
static iouring_config_t iouring_params = {
    .sq_depth   = 8,
    .cq_depth   = 1024,
    .br_n_bufs  = 2048,
    .br_gid     = 1,
    .n_io_ops   = 1024
};

static void print_config() {
    log_info("SQ depth %d CQ depth %d n_io_ops %d br_n_bufs %d",
             iouring_params.sq_depth,
             iouring_params.cq_depth,
             iouring_params.n_io_ops,
             iouring_params.br_n_bufs);
}

static volatile int running = 1;

static void signal_handler(int signum) {
    (void)signum;
    log_info("Received signal, shutting down...");
    running = 0;
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
    ctx->uring_ctx = iouring_init(&iouring_params);
    if (!ctx->uring_ctx) {
        log_error("Failed to create io-uring context");
        free(ctx);
        return NULL;
    }

    // Initialize OpenSSL
    dtls_library_init();

    ctx->inbound = create_connection(CONN_ROLE_SERVER,
                                     NULL, /*host*/
                                     0, /* remote port */
                                     inbound_port,
                                     cert_file,
                                     key_file,
                                     NULL /* ca_file */);
    if (!ctx->inbound) {
        return NULL;
    }

    ctx->outbound = create_connection(CONN_ROLE_CLIENT,
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

    // Cleanup connections
    if (ctx->outbound) {
        if (ctx->outbound->ssl) {
            SSL_free(ctx->outbound->ssl);
        }
        if (ctx->outbound->dtls_ctx) {
            dtls_context_cleanup(ctx->outbound->dtls_ctx);
        }
    }

    if (ctx->inbound) {
        if (ctx->inbound->ssl) {
            SSL_free(ctx->inbound->ssl);
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

static int forward_udp_packet(forwarder_ctx_t *ctx, io_op_t *op) {

    int packet_len = op->data_len;
    struct sockaddr *src_addr = (struct sockaddr *)op->addr;

    // Determine which connection based solely on which socket received the packet
    int from_inbound_socket = (op->fd == ctx->inbound->udp_fd);
    log_debug("Received %d bytes from %s on %s socket (fd=%d)",
              packet_len, addr_to_string(src_addr),
              from_inbound_socket ? "inbound" : "outbound",
              op->fd);

    if (packet_len <= 0) {
        log_warn("Connection closed or error occurred (packet_len: %d)", packet_len);
        return -1;
    }

    dtls_connection_t *recv_conn = NULL;
    dtls_connection_t *forward_conn = NULL;

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

    uint8_t decrypted[BUF_SIZE];
    int decrypted_len = dtls_decrypt_packet(recv_conn,
                                            op->buffer, packet_len,
                                            decrypted, sizeof(decrypted));
    if (decrypted_len <= 0) {
        return -1;
    }

    if (at_log_level(LOG_DEBUG)) {
        print_ip_packet_info(decrypted, decrypted_len, "forwarding");
    }

    int ret = dtls_encrypt_and_send_udp(forward_conn,
                                        decrypted, decrypted_len,
                                        ctx->uring_ctx);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int forwarder_run(forwarder_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }
    int ret = 0;

    log_info("Starting forwarder main loop");

    //time_t last_stats = time(NULL);

    // Main event loop
    io_op_t *op = NULL;
    while (true) {
        op = wait_for_recv(ctx->uring_ctx);
        if (!op) {
           return -1;
        }
        if (op->op_type != OP_TYPE_UDP_RECV) {
            log_error("Invalid io_op type for receive: %s", op_type_str(op->op_type));
            return -1;
        }
        ret = forward_udp_packet(ctx, op);
        if (ret < 0)
            return ret;
        io_op_free(ctx->uring_ctx, &op);
    }
    free(op); // for multi op
    return ret;
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
    log_set_level(LOG_LEVEL);
    log_info("Starting DTLS Forwarder");
    log_info("Inbound port: %d", inbound_port);
    log_info("Outbound port: %d", outbound_port);
    log_info("Certificate: %s", cert_file);
    log_info("Private key: %s", key_file);
    log_info("CA certificate: %s", ca_file ? ca_file : "none (no client verification)");
    log_info("Remote endpoint: %s:%d", remote_host, remote_port);

    print_config();

    // Create forwarder context
    forwarder_ctx_t *ctx = forwarder_create(remote_host, remote_port, inbound_port, outbound_port, cert_file, key_file, ca_file);
    if (!ctx) {
        log_error("Failed to create forwarder context");
        return 1;
    }


    // Submit initial UDP receive operations for inbound socket
    int ret = iouring_initial_udp_recvs(ctx->uring_ctx, ctx->inbound->udp_fd);
    if (ret != 0) {
        return -1;
    };
    log_debug("Submitted initial UDP receive operation(s) for inbound socket");

    // Submit initial UDP receive operations for outbound socket
    ret = iouring_initial_udp_recvs(ctx->uring_ctx, ctx->outbound->udp_fd);
    if (ret != 0) {
        return -1;
    };
    log_debug("Submitted initial UDP receive operation(s) for outbound socket");

    log_info("Handshake STARTED - inbound");  
    ret = do_dtls_handshake(ctx->uring_ctx, ctx->inbound);
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