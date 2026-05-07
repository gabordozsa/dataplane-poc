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
    const char *tun_ip = (argc > 4) ? argv[4] : "10.8.0.254";
    
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
    dtls_library_init();
    
    // Create TUN device
    tun_device_t *tun = tun_device_create("tun1");
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
    
    // Bind to port
    if (udp_socket_bind(udp_fd, port, NULL) < 0) {
        log_error("Failed to bind UDP socket");
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    // Initialize io-uring
    iouring_ctx_t *uring_ctx = iouring_init(256);
    if (!uring_ctx) {
        log_error("Failed to initialize io-uring");
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    iouring_set_fds(uring_ctx, tun_device_get_fd(tun), udp_fd);
    
    // Initialize DTLS server context
    dtls_ctx_t *dtls_ctx = dtls_server_context_init(cert_file, key_file);
    if (!dtls_ctx) {
        log_error("Failed to initialize DTLS context");
        iouring_cleanup(uring_ctx);
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    // Initialize connection table
    connection_table_t *conn_table = connection_table_init(1024, 10000);
    if (!conn_table) {
        log_error("Failed to initialize connection table");
        dtls_context_cleanup(dtls_ctx);
        iouring_cleanup(uring_ctx);
        udp_socket_close(udp_fd);
        tun_device_destroy(tun);
        return 1;
    }
    
    // Submit initial UDP receive operations
    for (int i = 0; i < 8; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV);
        if (op) {
            iouring_submit_udp_recv(uring_ctx, op);
        }
    }
    
    // Submit initial TUN read operations
    for (int i = 0; i < 4; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_TUN_READ);
        if (op) {
            iouring_submit_tun_read(uring_ctx, op);
        }
    }
    
    log_info("Server ready, entering main loop...");
    
    time_t last_cleanup = time(NULL);
    
    // Main event loop
    while (running) {
        struct io_uring_cqe *cqe;
        
        // Wait for completion event with timeout
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
                // Server reads from TUN and routes to appropriate client
                if (cqe->res > 0) {
                    int packet_len = cqe->res;
                    log_debug("Read %d bytes from TUN (server)", packet_len);
                    
                    // Validate IP packet
                    if (validate_ip_packet(op->buffer, packet_len)) {
                        print_ip_packet_info(op->buffer, packet_len);
                        
                        // Extract destination IP
                        uint32_t dest_ip = get_ipv4_destination(op->buffer, packet_len);
                        
                        if (dest_ip != 0) {
                            // Find connection by tunnel IP
                            connection_t *target_conn = connection_find_by_tunnel_ip(conn_table, dest_ip);
                            
                            if (target_conn) {
                                // Route to specific client
                                dtls_encrypt_and_send(target_conn, op->buffer, packet_len, uring_ctx);
                                
                                struct in_addr addr;
                                addr.s_addr = dest_ip;
                                char ip_str[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                                log_debug("Routed packet to client with tunnel IP %s", ip_str);
                            } else {
                                struct in_addr addr;
                                addr.s_addr = dest_ip;
                                char ip_str[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                                log_debug("No client found for tunnel IP %s", ip_str);
                            }
                        } else {
                            // Not IPv4 or couldn't extract IP, broadcast to all
                            log_debug("Non-IPv4 packet, broadcasting to all clients");
                            int sent_count = 0;
                            for (size_t i = 0; i < conn_table->bucket_count; i++) {
                                connection_t *conn = conn_table->buckets[i];
                                while (conn) {
                                    if (conn->state == CONN_STATE_ESTABLISHED) {
                                        dtls_encrypt_and_send(conn, op->buffer, packet_len, uring_ctx);
                                        sent_count++;
                                    }
                                    conn = conn->next;
                                }
                            }
                            log_debug("Broadcast packet to %d client(s)", sent_count);
                        }
                    } else {
                        log_warn("Invalid IP packet from TUN (server)");
                    }
                }
                
                io_op_free(op);
                
                // Resubmit TUN read
                {
                    io_op_t *new_op = io_op_alloc(OP_TYPE_TUN_READ);
                    if (new_op) {
                        iouring_submit_tun_read(uring_ctx, new_op);
                    }
                }
                break;
                
            case OP_TYPE_UDP_RECV:
                handle_udp_recv(cqe, conn_table, NULL, dtls_ctx, uring_ctx);
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
        
        // Periodic cleanup of idle connections
        time_t now = time(NULL);
        if (now - last_cleanup > 30) {
            int cleaned = connection_cleanup_idle(conn_table, 60);
            if (cleaned > 0) {
                log_info("Cleaned up %d idle connections", cleaned);
            }
            last_cleanup = now;
        }
    }
    
    // Cleanup
    log_info("Cleaning up...");
    
    connection_table_cleanup(conn_table);
    dtls_context_cleanup(dtls_ctx);
    iouring_cleanup(uring_ctx);
    udp_socket_close(udp_fd);
    tun_device_down(tun);
    tun_device_destroy(tun);
    dtls_library_cleanup();
    
    log_info("Server shutdown complete");
    
    return 0;
}

// Made with Bob
