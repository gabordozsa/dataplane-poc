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
#include <netinet/in.h>
#include <arpa/inet.h>

static volatile int running = 1;

static void signal_handler(int signum) {
    (void)signum;
    log_info("Received signal, shutting down...");
    running = 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port> [tun_ip] [ca_cert]\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.100 4433 10.8.0.1 ca.pem\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    uint16_t server_port = atoi(argv[2]);
    const char *tun_ip = (argc > 3) ? argv[3] : "10.8.0.1";
    const char *ca_cert = (argc > 4) ? argv[4] : NULL;

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize logging
    log_set_level(LOG_LEVEL);
    log_info("Starting DTLS VPN client");
    log_info("Server: %s:%d", server_ip, server_port);
    log_info("TUN IP: %s", tun_ip);

    // Initialize OpenSSL
    //dtls_library_init();

    dtls_connection_t *conn = create_dtls_connection(CONN_ROLE_CLIENT,
                                                     server_ip, server_port,
                                                     0 /*local_port*/,
                                                     NULL /*cert_file*/, NULL /*key_file*/,
                                                     ca_cert);


    // Initialize io-uring
    iouring_ctx_t *uring_ctx = iouring_init(RING_DEPTH);
    if (!uring_ctx) {
        log_error("Failed to initialize io-uring");
        udp_socket_close(conn->udp_fd);
        return 1;
    }

    // Submit initial UDP receive operations
    int ret = iouring_initial_udp_recvs(uring_ctx, conn->udp_fd);
    if (ret != 0) {
        return -1;
    };
    log_debug("Submitted initial UDP receive operation(s)");

    log_info("Connecting to server, starting handshake ...");
    ret = do_dtls_handshake(uring_ctx, conn);
    if (ret) {
        log_error("Handshake FAILURE");
        return 1;
    }
    log_info("Handshake COMPLETED");

    // creating TUN device
    tun_device_t *tun = new_tun_device("tun0", tun_ip, "255.255.255.0", 1400);
    if (!tun) {
        log_error("Failed to create new TUN device");
        return 1;
    }

    // Submit initial TUN read operations
    ret = iouring_initial_tun_reads(uring_ctx, tun->fd);
    if (ret != 0) {
        return ret;
    }
    log_debug("Submitted initial TUN read operation(s)");

    ret = tun_udp_run(uring_ctx, conn, tun->fd, &running);
    if (ret < 0) {
        log_error("ABORTED due to error");
    }

    // Cleanup
    log_info("Cleaning up...");

    SSL_free(conn->ssl);
    dtls_context_cleanup(conn->dtls_ctx);
    iouring_cleanup(uring_ctx);
    udp_socket_close(conn->udp_fd);
    tun_device_down(tun);
    tun_device_destroy(tun);
    //dtls_library_cleanup();

    log_info("Client shutdown complete");

    return 0;
}

// Made with Bob
