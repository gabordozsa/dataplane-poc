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

/**
 * Initiate DTLS handshake and send initial ClientHello
 * @param ssl SSL object
 * @param wbio Write BIO
 * @param rbio Read BIO
 * @param server_addr Server address
 * @param udp_fd UDP socket file descriptor
 * @param uring_ctx io-uring context
 * @return 0 on success, -1 on failure
 */
static int initiate_dtls_handshake(SSL *ssl, BIO *wbio, BIO *rbio,
                                   struct sockaddr_in *server_addr,
                                   int udp_fd, iouring_ctx_t *uring_ctx) {
    log_info("Initiating DTLS handshake...");
    
    // Clear any previous errors
    ERR_clear_error();
    
    // Call SSL_do_handshake to initiate the handshake
    int hs_ret = SSL_do_handshake(ssl);
    int ssl_err = SSL_get_error(ssl, hs_ret);
    log_debug("SSL_do_handshake returned: %d, SSL error: %d (%s)",
              hs_ret, ssl_err, dtls_get_error_string(ssl, hs_ret));
    
    // If there's an SSL error, print the error queue
    if (ssl_err == SSL_ERROR_SSL) {
        log_error("SSL protocol error occurred:");
        ERR_print_errors_fp(stderr);
    }
    
    // For DTLS client, we expect SSL_ERROR_WANT_WRITE or SSL_ERROR_WANT_READ
    // Check if SSL generated any data to send
    int pending = BIO_ctrl_pending(wbio);
    log_debug("BIO wbio pending bytes: %d", pending);
    
    // Also check rbio
    int rbio_pending = BIO_ctrl_pending(rbio);
    log_debug("BIO rbio pending bytes: %d", rbio_pending);
    
    if (pending > 0) {
        uint8_t buffer[PACKET_BUFFER_SIZE];
        int read = BIO_read(wbio, buffer, sizeof(buffer));
        log_info("Read %d bytes from wbio for initial handshake", read);
        
        // Dump all bytes to see what's being sent
        if (read > 0) {
            char hex_str[256] = {0};
            int offset = 0;
            for (int i = 0; i < read && i < 20; i++) {
                offset += snprintf(hex_str + offset, sizeof(hex_str) - offset, "%02x ", buffer[i]);
            }
            log_debug("All %d bytes: %s", read, hex_str);
            
            // Decode the message type
            if (buffer[0] == 0x16) {
                log_info("Message type: Handshake (0x16) - GOOD!");
            } else if (buffer[0] == 0x15) {
                log_error("Message type: Alert (0x15) - SSL ERROR!");
                if (read >= 5) {
                    log_error("Alert level: %d, description: %d", buffer[3], buffer[4]);
                }
            } else {
                log_warn("Message type: Unknown (0x%02x)", buffer[0]);
            }
        }
        
        if (read > 0) {
            io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
            if (op) {
                int submit_ret = iouring_submit_udp_send(uring_ctx, udp_fd, op,
                                      (struct sockaddr *)server_addr,
                                      sizeof(*server_addr), buffer, read);
                log_info("Submitted initial ClientHello: %d bytes (ret=%d)", read, submit_ret);
                return 0;
            } else {
                log_error("Failed to allocate op for initial handshake send");
                return -1;
            }
        }
    } else {
        log_error("No data to send after SSL_do_handshake - handshake not initiated!");
        log_error("This usually means the BIO pair is not set up correctly");
        
        // Try to diagnose the issue
        log_debug("SSL state: %s", SSL_state_string_long(ssl));
        log_debug("SSL is_init_finished: %d", SSL_is_init_finished(ssl));
        
        // Check if BIOs are properly connected
        BIO *ssl_rbio = SSL_get_rbio(ssl);
        BIO *ssl_wbio = SSL_get_wbio(ssl);
        log_debug("SSL rbio: %p, wbio: %p", (void*)ssl_rbio, (void*)ssl_wbio);
        log_debug("Our rbio: %p, wbio: %p", (void*)rbio, (void*)wbio);
        return -1;
    }
    
    return 0;
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
    
    iouring_set_tun_fd(uring_ctx, tun_device_get_fd(tun));
    
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
    conn.tunnel_ip = 0;  // Will be set from server if needed
    conn.state = CONN_STATE_HANDSHAKING;
    conn.last_activity = time(NULL);
    
    log_info("Connecting to server...");
    
    // Start DTLS handshake
    if (initiate_dtls_handshake(ssl, wbio, rbio, &server_addr, udp_fd, uring_ctx) < 0) {
        log_error("Failed to initiate DTLS handshake");
        SSL_free(ssl);
        dtls_context_cleanup(dtls_ctx);
        iouring_cleanup(uring_ctx);
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    // Submit initial UDP receive operations
    log_info("Submitting initial UDP receive operations...");
    int recv_submitted = 0;
    for (int i = 0; i < 4; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV);
        if (op) {
            int ret = iouring_submit_udp_recv(uring_ctx, udp_fd, op);
            if (ret == 0) {
                recv_submitted++;
            } else {
                log_error("Failed to submit UDP recv %d", i);
                io_op_free(op);
            }
        }
    }
    log_info("Submitted %d UDP receive operations", recv_submitted);
    
    log_info("Entering main loop...");
    
    // Main event loop
    while (running) {
        struct io_uring_cqe *cqe;
        
        // Wait for completion event with timeout
        int wait_ret = iouring_wait_cqe(uring_ctx, &cqe);
        if (wait_ret < 0) {
            if (wait_ret == -ETIME) {
                // Timeout - no events, just continue
                continue;
            }
            // Other error - exit
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
                handle_tun_read(cqe, &conn, udp_fd, uring_ctx);
                break;
                
            case OP_TYPE_UDP_RECV:
                handle_udp_recv(cqe, NULL, &conn, NULL, udp_fd, uring_ctx);
                
                // Check if connection was closed by server
                if (conn.state == CONN_STATE_CLOSING) {
                    log_warn("Server closed the connection");
                    running = 0;  // Exit main loop
                    break;
                }
                
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
