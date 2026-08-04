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
#include <pthread.h>


// TUN uring config params
static iouring_config_t tun_iouring_params = {
    .sq_depth           = 4,      // submissiom queue depth
    .cq_depth           = 512,   // completion queue depth
    .n_io_ops           = 2048 + 16,   // number of user context structs for submisson requests
    .n_initial_read_ops = 8,      // number of (single-shot) TUN reads submitted initially
    .tr_depth           = 512,
    .name               = "TUN"
};

// UDP uring config params
static iouring_config_t udp_iouring_params = {
    .sq_depth           = 4,      // submissiom queue depth
    .cq_depth           = 1024,   // completion queue depth
    .br_n_bufs          = 2048,   // number of provuded buffers in buffer ring
    .br_gid             = 1,      // group ID of buffer ring
    .n_io_ops           = 512,   // number of user context structs for submisson requests
    .tr_depth.          = 512, 
    .name               = "UDP"
};

static void print_config() {
    log_info("UDP uring SQ depth %d CQ depth %d n_io_ops %d br_n_bufs %d",
             udp_iouring_params.sq_depth,
             udp_iouring_params.cq_depth,
             udp_iouring_params.n_io_ops,
             udp_iouring_params.br_n_bufs);
    log_info("TUN uring SQ depth %d CQ depth %d n_io_ops %d br_n_bufs %d",
             tun_iouring_params.sq_depth,
             tun_iouring_params.cq_depth,
             tun_iouring_params.n_io_ops,
             tun_iouring_params.br_n_bufs,
             tun_iouring_params.n_initial_read_ops);
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

// multi threading
typedef struct {
    const iouring_ctx_t *tun_uring_ctx;
    const iouring_ctx_t *udp_uring_ctx;
    const connection_t *conn;
    const int tun_fd;
    volatile int *running;
} thread_args;

void *tun_thread_func(void *a) {
    thread_args *args = (thread_args *)a;
    iouring_ctx_t *tun_uring_ctx = args->tun_uring_ctx;
    spsc_ring_t *transfer_from_udp = args->udp_uring_ctx->transfer;
    int tun_fd = args->tun_fd;
    int ret =  run_zero_tun2udp(tun_uring_ctx, tun_fd, transfer_from_udp, args->running);
    return (void *)ret;
}

void *udp_thread_func(void *a) {
    thread_args *args = (thread_args *)a;
    iouring_ctx_t *udp_uring_ctx = args->udp_uring_ctx;
    spsc_ring_t *transfer_from_udp = args->tun_uring_ctx->transfer;
    connection_t *conn = args->conn;
    int ret =  run_zero_udp2tun(udp_uring_ctx, conn, transfer_from_tun, args->running);
    return (void *)ret;
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

    // Initialize io-uring for UDP
    iouring_ctx_t *udp_uring_ctx = iouring_init(&udp_iouring_params);
    if (!udp_uring_ctx) {
        log_error("Failed to initialize io-uring for UDP");
        udp_socket_close(conn->udp_fd);
        return 1;
    }

    // Submit initial UDP receive operations
    int ret = iouring_initial_udp_recvs(udp_uring_ctx, conn->udp_fd);
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

    // Initialize io-uring for TUN
    iouring_ctx_t *tun_uring_ctx = iouring_init(&tun_iouring_params);
    if (!tun_uring_ctx) {
        log_error("Failed to initialize io-uring for TUN");
        tun_device_down(tun);
        tun_device_destroy(tun);
        udp_socket_close(conn->udp_fd);
        return 1;
    }

    // Submit initial TUN read operations
    ret = iouring_initial_tun_reads(tun_uring_ctx, tun->fd);
    if (ret != 0) {
        return ret;
    }
    log_debug("Submitted initial TUN read operation(s)");

    thtread_args th_args = {
        .tun_uring_ctx = tun_uring_ctx,
        .udp_uring_ctx = udp_uring_ctx,
        .conn          = conn,
        .tun_fd        = tun_fd,
        .running       = &running
    };

    // start TUN thread
    pthread_t tun_thread;
    ret = pthread_create(&tun_thread, NULL, tun_thread_func, &th_args);
    if (ret != 0) {
        log_error("Failed to crreate TUN thread: %s", strerror(ret));
        return -1;
    }

    // start UDP thread
    pthread_t udp_thread;
    ret = pthread_create(&tun_thread, NULL, udp_thread_func, &th_args);
    if (ret != 0) {
        log_error("Failed to crreate UDP thread: %s", strerror(ret));
        return -1;
    }

    // Join the threads before clean up
    // main loop
    void *retval;
    ret = pthread_join(tun_thread, &retval);
    if (ret != 0) {
        log_error("TUN thread join failed: %s", strerror(ret));
        return -1;
    }
    if (retval != NULL) {
        log_error("TUN thread exited with error")
    }

    pthread_join(udp_thread, &retval);
    if (ret != 0) {
        log_error("UDP thread join failed: %s", strerror(ret));
        return -1;
    }
    if (retval != NULL) {
        log_error("UDP thread exited with error")
    }

    // Cleanup
    log_info("Cleaning up...");

    iouring_cleanup(udp_uring_ctx);
    iouring_cleanup(tun_uring_ctx);
    udp_socket_close(conn->udp_fd);
    tun_device_down(tun);
    tun_device_destroy(tun);

    log_info("Edge %s shutdown complete", conn_role_str(role));

    return 0;
}

// Made with Bob
