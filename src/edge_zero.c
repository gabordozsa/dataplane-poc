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

#define RING_DEPTH 16

// Note: we use multi-shot recvmsg
static iouring_config_t iouring_params = {
    .sq_depth           = RING_DEPTH,
    .cq_depth           = 1024,
    .br_n_bufs          = 2048,
    .br_gid             = 1,
    .n_io_ops           = 1024,
    .n_initial_read_ops = RING_DEPTH - 1 // all slot but one (1 multidhot recv)
};

static void print_config() {
    log_info("SQ depth %d CQ depth %d n_io_ops %d br_n_bufs %d",
             iouring_params.sq_depth,
             iouring_params.cq_depth,
             iouring_params.n_io_ops,
             iouring_params.br_n_bufs,
             iouring_params.n_initial_read_ops);
}

static volatile int running = 1;

static void signal_handler(int signum) {
    (void)signum;
    log_info("Received signal, shutting down...");
    running = 0;
}

void usage(const char *cmd) {
    fprintf(stderr, "Usage: %s client <tun_ip> <server_port>  <server_ip>\n", cmd);
    fprintf(stderr, "Usage: %s server <tun_ip> <server_port>\n", cmd);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        usage(argv[0]);
    }

    conn_role_t role;
    const char *tun_ip;
    uint16_t server_port = 0;
    const char *server_ip = NULL;

    if (strcmp(argv[1], "server") == 0) {
        role = CONN_ROLE_SERVER;
        if (argc != 4) {
            usage(argv[0]);
        }
    } else if (strcmp(argv[1], "client") == 0) {
        role = CONN_ROLE_CLIENT;
        if (argc != 5) {
            usage(argv[0]);
        }
    } else {
        usage(argv[0]);
    }

    tun_ip = argv[2];
    server_port = atoi(argv[3]);

    if (role == CONN_ROLE_CLIENT) {
        server_ip = argv[4];
    }

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize logging
    log_set_level(LOG_LEVEL);
    log_info("Starting edge %s", conn_role_str(role));
    log_info("TUN IP: %s", tun_ip);
    log_info("Server port: %d", server_port);
    if (role == CONN_ROLE_CLIENT) {
         log_info("Server IP %s", server_ip);
    }

    print_config();

    const char *remote_host;
    uint16_t remote_port, local_port;
    const char *tun_ifname;
    if (role == CONN_ROLE_CLIENT) {
        local_port = 0;
        remote_port = server_port;
        remote_host = server_ip;
        tun_ifname = "tun0";
    } else {
        local_port = server_port;
        remote_port = 0;
        remote_host = NULL;
        tun_ifname = "tun1";
    }

    connection_t *conn = create_connection(role,
                                           remote_host, remote_port,
                                           local_port);

    // Initialize io-uring
    iouring_ctx_t *uring_ctx = iouring_init(&iouring_params);
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

    // creating TUN device
    tun_device_t *tun = new_tun_device(tun_ifname, tun_ip, "255.255.255.0", 1400);
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

    ret = tun_udp_run_zero(uring_ctx, conn, tun->fd, &running);
    if (ret < 0) {
        log_error("ABORTED due to error");
    }

    // Cleanup
    log_info("Cleaning up...");

    iouring_cleanup(uring_ctx);
    udp_socket_close(conn->udp_fd);
    tun_device_down(tun);
    tun_device_destroy(tun);

    log_info("Edge %s shutdown complete", conn_role_str(role));

    return 0;
}

// Made with Bob
