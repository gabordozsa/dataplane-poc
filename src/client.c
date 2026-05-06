#include "tun_device.h"
#include "udp_socket.h"
#include "iouring.h"
#include "dtls_context.h"
#include "connection.h"
#include "packet_handler.h"
#include "utils.h"
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
    log_set_level(LOG_DEBUG);
    log_info("Starting DTLS VPN client");
    log_info("Server: %s:%d", server_ip, server_port);
    log_info("TUN IP: %s", tun_ip);
    
    // Initialize OpenSSL
    dtls_library_init();
    
    // Create TUN device
    tun_device_t *tun = tun_device_create("tun0");
    if (!tun) {
        log_error("Failed to create TUN device");
        return 1;
    }
    
    // Configure TUN device
    if (tun_device_configure(tun, tun_ip, "255.255.255.0", 1400) < 0) {
        log_error("Failed to configure TUN device");
        tun_device_destroy(tun);
        return 1;
    }
    
    // Bring TUN device up
    if (tun_device_up(tun) < 0) {
        log_error("Failed to bring TUN device up");
        tun_device_destroy(tun);
        return 1;
    }
    
    // Create UDP socket
    int udp_fd = udp_socket_create();
    if (udp_fd < 0) {
        log_error("Failed to create UDP socket");
        tun_device_destroy(tun);
        return 1;
    }
    
    // Set socket options
    udp_socket_set_options(udp_fd);
    udp_socket_set_nonblocking(udp_fd);
    
    // Initialize io-uring
    iouring_ctx_t *uring_ctx = iouring_init(256);
    if (!uring_ctx) {
        log_error("Failed to initialize io-uring");
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    iouring_set_fds(uring_ctx, tun_device_get_fd(tun), udp_fd);
    
    // Initialize DTLS client context
    dtls_ctx_t *dtls_ctx = dtls_client_context_init(ca_cert);
    if (!dtls_ctx) {
        log_error("Failed to initialize DTLS context");
        iouring_cleanup(uring_ctx);
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    // Create SSL object for server connection
    SSL *ssl = dtls_create_ssl(dtls_ctx);
    if (!ssl) {
        log_error("Failed to create SSL object");
        dtls_context_cleanup(dtls_ctx);
        iouring_cleanup(uring_ctx);
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    // Setup BIO pair
    BIO *rbio, *wbio;
    if (dtls_setup_bio_pair(ssl, &rbio, &wbio) < 0) {
        log_error("Failed to setup BIO pair");
        SSL_free(ssl);
        dtls_context_cleanup(dtls_ctx);
        iouring_cleanup(uring_ctx);
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    // Create connection structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
    connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.ssl = ssl;
    conn.rbio = rbio;
    conn.wbio = wbio;
    addr_copy(&conn.addr, (struct sockaddr *)&server_addr, sizeof(server_addr));
    conn.addr_len = sizeof(server_addr);
    conn.state = CONN_STATE_HANDSHAKING;
    conn.last_activity = time(NULL);
    
    log_info("Connecting to server...");
    
    // Start DTLS handshake
    SSL_do_handshake(ssl);
    int pending = BIO_ctrl_pending(wbio);
    if (pending > 0) {
        uint8_t buffer[PACKET_BUFFER_SIZE];
        int read = BIO_read(wbio, buffer, sizeof(buffer));
        if (read > 0) {
            io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
            if (op) {
                iouring_submit_udp_send(uring_ctx, op,
                                      (struct sockaddr *)&server_addr,
                                      sizeof(server_addr), buffer, read);
            }
        }
    }
    
    // Submit initial operations
    for (int i = 0; i < 4; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV);
        if (op) {
            iouring_submit_udp_recv(uring_ctx, op);
        }
    }
    
    log_info("Entering main loop...");
    
    // Main event loop
    while (running) {
        struct io_uring_cqe *cqe;
        
        // Wait for completion event
        if (iouring_wait_cqe(uring_ctx, &cqe) < 0) {
            break;
        }
        
        io_op_t *op = (io_op_t *)io_uring_cqe_get_data(cqe);
        if (!op) {
            iouring_cqe_seen(uring_ctx, cqe);
            continue;
        }
        
        // Process based on operation type
        switch (op->op_type) {
            case OP_TYPE_TUN_READ:
                handle_tun_read(cqe, &conn, uring_ctx);
                break;
                
            case OP_TYPE_UDP_RECV:
                handle_udp_recv(cqe, NULL, &conn, NULL, uring_ctx);
                
                // Start reading from TUN once handshake is complete
                if (conn.state == CONN_STATE_ESTABLISHED) {
                    static int tun_read_started = 0;
                    if (!tun_read_started) {
                        log_info("DTLS connection established, starting TUN read");
                        for (int i = 0; i < 4; i++) {
                            io_op_t *tun_op = io_op_alloc(OP_TYPE_TUN_READ);
                            if (tun_op) {
                                iouring_submit_tun_read(uring_ctx, tun_op);
                            }
                        }
                        tun_read_started = 1;
                    }
                }
                break;
                
            case OP_TYPE_TUN_WRITE:
                handle_tun_write(cqe);
                break;
                
            case OP_TYPE_UDP_SEND:
                handle_udp_send(cqe);
                break;
                
            default:
                log_warn("Unknown operation type: %d", op->op_type);
                io_op_free(op);
                break;
        }
        
        iouring_cqe_seen(uring_ctx, cqe);
    }
    
    // Cleanup
    log_info("Cleaning up...");
    
    SSL_free(ssl);
    dtls_context_cleanup(dtls_ctx);
    iouring_cleanup(uring_ctx);
    udp_socket_close(udp_fd);
    tun_device_down(tun);
    tun_device_destroy(tun);
    dtls_library_cleanup();
    
    log_info("Client shutdown complete");
    
    return 0;
}

// Made with Bob
