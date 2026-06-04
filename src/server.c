#include "tun_device.h"
#include "udp_socket.h"
#include "iouring.h"
#include "dtls_context.h"
#include "connection.h"
#include "packet_handler.h"
#include "utils.h"
#include "tun_udp_run.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>

static volatile int running = 1;

static void signal_handler(int signum) {
    (void)signum;
    log_info("Received signal, shutting down...");
    running = 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <port> <cert_file> <key_file> [tun_ip]\n", argv[0]);
        fprintf(stderr, "Example: %s 4433 cert.pem key.pem 10.8.0.254\n", argv[0]);
        return 1;
    }

    uint16_t port = atoi(argv[1]);
    const char *cert_file = argv[2];
    const char *key_file = argv[3];
    const char *tun_ip = (argc > 4) ? argv[4] : "10.9.0.254";

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize logging
    log_set_level(LOG_DEBUG);
    log_info("Starting DTLS VPN server");
    log_info("Port: %d", port);
    log_info("Certificate: %s", cert_file);
    log_info("Private key: %s", key_file);
    log_info("TUN IP: %s", tun_ip);

    // Initialize OpenSSL
    //tls_library_init();

    dtls_connection_t *conn = create_dtls_connection(CONN_ROLE_SERVER,
                                                     NULL /*remote_ip*/, 0 /*remote_port*/,
                                                     port,
                                                     cert_file, key_file,
                                                     NULL /*ca_cert*/);

    // Initialize io-uring
    iouring_ctx_t *uring_ctx = iouring_init(256);
    if (!uring_ctx) {
        log_error("Failed to initialize io-uring");
        udp_socket_close(conn->udp_fd);
        return 1;
    }

    // Submit initial UDP receive operations
    int num_recv_ops = 8;
    for (int i = 0; i < num_recv_ops; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV, conn->udp_fd);
        if (op) {
            iouring_submit_udp_recv(uring_ctx, op);
        }
    }
    log_debug("Submitted %d UDP receive operations", num_recv_ops);

    log_info("Waiting for client connection, starting handshake ...");
    int ret = do_dtls_handshake(uring_ctx, conn);
    if (ret) {
        log_error("Handshake FAILURE");
        return 1;
    }
    log_info("Handshake COMPLETED");

    // creating TUN device
    tun_device_t *tun = new_tun_device("tun1", tun_ip, "255.255.255.0", 1400);
    if (!tun) {
        log_error("Failed to create new TUN device");
        return 1;
    }

    // Submit initial TUN read operations
    int num_read_ops = 8;
    for (int i = 0; i < num_read_ops; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_TUN_READ, tun->fd);
        if (op) {
            int ret = iouring_submit_tun_read(uring_ctx, op);
            if (ret < 0) {
                log_error("Failed to submit TUN read %d", i);
                return 1;
            }
        }
    }
    log_debug("Submitted %d TUN read operations", num_read_ops);

    ret = tun_udp_run(uring_ctx, conn, tun->fd, &running);
    if (ret < 0) {
        log_error("ABORTED due to error");
    }

    // Cleanup
    log_info("Cleaning up...");


    dtls_context_cleanup(conn->dtls_ctx);
    iouring_cleanup(uring_ctx);
    udp_socket_close(conn->udp_fd);
    tun_device_down(tun);
    tun_device_destroy(tun);
    //dtls_library_cleanup();

    log_info("Clean up done");

    return 0;
}

// Made with Bob
