#include "packet_handler.h"
#include "utils.h"
#include <string.h>
#include <errno.h>

int process_dtls_handshake(connection_t *conn, iouring_ctx_t *uring_ctx) {
    if (!conn || !conn->ssl) {
        return -1;
    }
    
    int ret = SSL_do_handshake(conn->ssl);
    
    if (ret == 1) {
        // Handshake complete - but check if we need to send final messages
        conn->state = CONN_STATE_ESTABLISHED;
        log_info("DTLS handshake completed");
        
        // Check if SSL has any final messages to send (e.g., server's Finished)
        int pending = BIO_ctrl_pending(conn->wbio);
        if (pending > 0) {
            uint8_t buffer[PACKET_BUFFER_SIZE];
            int read = BIO_read(conn->wbio, buffer, sizeof(buffer));
            if (read > 0) {
                io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
                if (op) {
                    iouring_submit_udp_send(uring_ctx, op,
                                          (struct sockaddr *)&conn->addr,
                                          conn->addr_len, buffer, read);
                    log_debug("Sent final handshake message after completion: %d bytes", read);
                }
            }
        }
        
        return 0;
    }
    
    int err = SSL_get_error(conn->ssl, ret);
    log_debug("process_dtls_handshake: ret=%d, err=%d (%s)", ret, err, dtls_get_error_string(conn->ssl, ret));
    
    if (err == SSL_ERROR_WANT_READ) {
        // Need more data - check if SSL wants to send anything
        int pending = BIO_ctrl_pending(conn->wbio);
        log_debug("WANT_READ: wbio pending=%d", pending);
        if (pending > 0) {
            uint8_t buffer[PACKET_BUFFER_SIZE];
            int read = BIO_read(conn->wbio, buffer, sizeof(buffer));
            if (read > 0) {
                // Send handshake message
                io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
                if (op) {
                    iouring_submit_udp_send(uring_ctx, op,
                                          (struct sockaddr *)&conn->addr,
                                          conn->addr_len, buffer, read);
                    log_debug("Sent handshake message: %d bytes", read);
                }
            }
            
            // After sending, try handshake again to see if complete
            log_debug("Retrying SSL_do_handshake after send...");
            ret = SSL_do_handshake(conn->ssl);
            err = SSL_get_error(conn->ssl, ret);
            log_debug("Retry result: ret=%d, err=%d", ret, err);
            
            if (ret == 1) {
                conn->state = CONN_STATE_ESTABLISHED;
                log_info("DTLS handshake completed (after WANT_READ send)");
                return 0;
            }
        }
        return 1;  // In progress
    } else if (err == SSL_ERROR_WANT_WRITE) {
        // Need to send data
        int pending = BIO_ctrl_pending(conn->wbio);
        if (pending > 0) {
            uint8_t buffer[PACKET_BUFFER_SIZE];
            int read = BIO_read(conn->wbio, buffer, sizeof(buffer));
            if (read > 0) {
                io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
                if (op) {
                    iouring_submit_udp_send(uring_ctx, op,
                                          (struct sockaddr *)&conn->addr,
                                          conn->addr_len, buffer, read);
                    log_debug("Sent handshake message: %d bytes", read);
                }
            }
        }
        
        // After sending, try handshake again to see if it completes
        ret = SSL_do_handshake(conn->ssl);
        if (ret == 1) {
            conn->state = CONN_STATE_ESTABLISHED;
            log_info("DTLS handshake completed");
            return 0;
        }
        
        return 1;  // In progress
    } else {
        log_error("DTLS handshake failed: %s", dtls_get_error_string(conn->ssl, ret));
        return -1;
    }
}

int dtls_encrypt_and_send(connection_t *conn, const uint8_t *data, size_t len,
                          iouring_ctx_t *uring_ctx) {
    if (!conn || !conn->ssl || !data || len == 0) {
        return -1;
    }
    
    // Write plaintext to SSL
    int written = SSL_write(conn->ssl, data, len);
    if (written <= 0) {
        int err = SSL_get_error(conn->ssl, written);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            log_error("SSL_write failed: %s", dtls_get_error_string(conn->ssl, written));
            return -1;
        }
    }
    
    // Read encrypted data from wbio
    int pending = BIO_ctrl_pending(conn->wbio);
    if (pending > 0) {
        uint8_t buffer[PACKET_BUFFER_SIZE];
        int read = BIO_read(conn->wbio, buffer, sizeof(buffer));
        if (read > 0) {
            // Send encrypted packet
            io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
            if (op) {
                log_debug("Sending encrypted packet: %d bytes", read);
                return iouring_submit_udp_send(uring_ctx, op,
                                              (struct sockaddr *)&conn->addr,
                                              conn->addr_len, buffer, read);
            }
        }
    }
    
    return 0;
}

int dtls_recv_and_decrypt(connection_t *conn, const uint8_t *encrypted,
                          size_t encrypted_len, uint8_t *decrypted,
                          size_t decrypted_size, iouring_ctx_t *uring_ctx) {
    if (!conn || !conn->ssl || !encrypted || !decrypted) {
        return -1;
    }
    
    // Write encrypted data to rbio
    int written = BIO_write(conn->rbio, encrypted, encrypted_len);
    if (written <= 0) {
        log_error("BIO_write failed");
        return -1;
    }
    
    // Try to read decrypted data
    int read = SSL_read(conn->ssl, decrypted, decrypted_size);
    
    if (read > 0) {
        // Successfully decrypted
        log_debug("Decrypted %d bytes", read);
        
        // Check if SSL wants to send anything (handshake messages, etc.)
        int pending = BIO_ctrl_pending(conn->wbio);
        if (pending > 0) {
            uint8_t buffer[PACKET_BUFFER_SIZE];
            int out_len = BIO_read(conn->wbio, buffer, sizeof(buffer));
            if (out_len > 0) {
                io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
                if (op) {
                    iouring_submit_udp_send(uring_ctx, op,
                                          (struct sockaddr *)&conn->addr,
                                          conn->addr_len, buffer, out_len);
                }
            }
        }
        
        return read;
    }
    
    int err = SSL_get_error(conn->ssl, read);
    
    if (err == SSL_ERROR_WANT_READ) {
        // Need more data - check if SSL wants to send
        int pending = BIO_ctrl_pending(conn->wbio);
        if (pending > 0) {
            uint8_t buffer[PACKET_BUFFER_SIZE];
            int out_len = BIO_read(conn->wbio, buffer, sizeof(buffer));
            if (out_len > 0) {
                io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
                if (op) {
                    iouring_submit_udp_send(uring_ctx, op,
                                          (struct sockaddr *)&conn->addr,
                                          conn->addr_len, buffer, out_len);
                }
            }
        }
        return 0;  // No data yet
    } else if (err == SSL_ERROR_WANT_WRITE) {
        // Need to send data
        int pending = BIO_ctrl_pending(conn->wbio);
        if (pending > 0) {
            uint8_t buffer[PACKET_BUFFER_SIZE];
            int out_len = BIO_read(conn->wbio, buffer, sizeof(buffer));
            if (out_len > 0) {
                io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND);
                if (op) {
                    iouring_submit_udp_send(uring_ctx, op,
                                          (struct sockaddr *)&conn->addr,
                                          conn->addr_len, buffer, out_len);
                }
            }
        }
        return 0;  // No data yet
    } else {
        log_error("SSL_read failed: %s", dtls_get_error_string(conn->ssl, read));
        return -1;
    }
}

int handle_tun_read(struct io_uring_cqe *cqe, connection_t *conn,
                    iouring_ctx_t *uring_ctx) {
    if (!cqe || !conn || !uring_ctx) {
        return -1;
    }
    
    io_op_t *op = (io_op_t *)io_uring_cqe_get_data(cqe);
    if (!op) {
        log_error("No operation data in CQE");
        return -1;
    }
    
    if (cqe->res < 0) {
        log_error("TUN read failed: %s", strerror(-cqe->res));
        io_op_free(op);
        return -1;
    }
    
    if (cqe->res == 0) {
        log_warn("TUN read returned 0 bytes");
        io_op_free(op);
        return -1;
    }
    
    int packet_len = cqe->res;
    log_debug("Read %d bytes from TUN", packet_len);
    
    // Validate IP packet
    if (!validate_ip_packet(op->buffer, packet_len)) {
        log_warn("Invalid IP packet from TUN");
        io_op_free(op);
        
        // Resubmit read
        io_op_t *new_op = io_op_alloc(OP_TYPE_TUN_READ);
        if (new_op) {
            iouring_submit_tun_read(uring_ctx, new_op);
        }
        return -1;
    }
    
    print_ip_packet_info(op->buffer, packet_len);
    
    // Encrypt and send
    if (conn->state == CONN_STATE_ESTABLISHED) {
        dtls_encrypt_and_send(conn, op->buffer, packet_len, uring_ctx);
    } else {
        log_debug("Connection not established, dropping packet");
    }
    
    io_op_free(op);
    
    // Resubmit TUN read
    io_op_t *new_op = io_op_alloc(OP_TYPE_TUN_READ);
    if (new_op) {
        iouring_submit_tun_read(uring_ctx, new_op);
    }
    
    return 0;
}

int handle_udp_recv(struct io_uring_cqe *cqe, connection_table_t *conn_table,
                    connection_t *conn, dtls_ctx_t *dtls_ctx,
                    iouring_ctx_t *uring_ctx) {
    if (!cqe || !uring_ctx) {
        return -1;
    }
    
    io_op_t *op = (io_op_t *)io_uring_cqe_get_data(cqe);
    if (!op) {
        log_error("No operation data in CQE");
        return -1;
    }
    
    if (cqe->res < 0) {
        log_error("UDP recv failed: %s", strerror(-cqe->res));
        io_op_free(op);
        return -1;
    }
    
    if (cqe->res == 0) {
        log_warn("UDP recv returned 0 bytes");
        io_op_free(op);
        return -1;
    }
    
    int packet_len = cqe->res;
    struct sockaddr *src_addr = (struct sockaddr *)&op->addr;
    
    char addr_str[64];
    addr_to_string(src_addr, addr_str, sizeof(addr_str));
    log_debug("Received %d bytes from %s", packet_len, addr_str);
    
    connection_t *active_conn = conn;
    
    // Server: find or create connection
    if (conn_table) {
        active_conn = connection_find(conn_table, src_addr);
        
        if (!active_conn && dtls_ctx) {
            // New connection
            log_info("New connection from %s", addr_str);
            
            SSL *ssl = dtls_create_ssl(dtls_ctx);
            if (!ssl) {
                log_error("Failed to create SSL for new connection");
                io_op_free(op);
                goto resubmit;
            }
            
            BIO *rbio, *wbio;
            if (dtls_setup_bio_pair(ssl, &rbio, &wbio) < 0) {
                log_error("Failed to setup BIO pair");
                SSL_free(ssl);
                io_op_free(op);
                goto resubmit;
            }
            
            active_conn = connection_create(conn_table, ssl, rbio, wbio,
                                          src_addr, op->addr_len);
            if (!active_conn) {
                log_error("Failed to create connection");
                SSL_free(ssl);
                io_op_free(op);
                goto resubmit;
            }
        }
    }
    
    if (!active_conn) {
        log_warn("No connection for packet from %s", addr_str);
        io_op_free(op);
        goto resubmit;
    }
    
    // Update activity
    connection_update_activity(active_conn);
    
    // Process based on connection state
    if (active_conn->state == CONN_STATE_HANDSHAKING) {
        // Feed data to SSL for handshake
        BIO_write(active_conn->rbio, op->buffer, packet_len);
        
        // Process handshake - call once, not in a loop
        // DTLS handshake is asynchronous and may need multiple packets
        int hs_result = process_dtls_handshake(active_conn, uring_ctx);
        
        if (hs_result < 0) {
            log_error("Handshake failed for connection");
        } else if (hs_result == 0) {
            log_info("Handshake completed successfully");
        }
    } else if (active_conn->state == CONN_STATE_ESTABLISHED) {
        // Decrypt and write to TUN
        uint8_t decrypted[PACKET_BUFFER_SIZE];
        int decrypted_len = dtls_recv_and_decrypt(active_conn, op->buffer,
                                                  packet_len, decrypted,
                                                  sizeof(decrypted), uring_ctx);
        
        if (decrypted_len > 0) {
            // Learn client's tunnel IP from source address
            uint32_t src_ip = get_ipv4_source(decrypted, decrypted_len);
            if (src_ip != 0 && active_conn->tunnel_ip == 0) {
                // First packet from this client, learn its tunnel IP
                connection_set_tunnel_ip(active_conn, src_ip);
            }
            
            // Write to TUN device
            io_op_t *tun_op = io_op_alloc(OP_TYPE_TUN_WRITE);
            if (tun_op) {
                log_debug("Writing %d bytes to TUN", decrypted_len);
                print_ip_packet_info(decrypted, decrypted_len);
                iouring_submit_tun_write(uring_ctx, tun_op, decrypted, decrypted_len);
            }
        }
    }
    
    io_op_free(op);
    
resubmit:
    // Resubmit UDP receive
    io_op_t *new_op = io_op_alloc(OP_TYPE_UDP_RECV);
    if (new_op) {
        iouring_submit_udp_recv(uring_ctx, new_op);
    }
    
    return 0;
}

int handle_tun_write(struct io_uring_cqe *cqe) {
    if (!cqe) {
        return -1;
    }
    
    io_op_t *op = (io_op_t *)io_uring_cqe_get_data(cqe);
    
    if (cqe->res < 0) {
        log_error("TUN write failed: %s", strerror(-cqe->res));
    } else {
        log_debug("Wrote %d bytes to TUN", cqe->res);
    }
    
    if (op) {
        io_op_free(op);
    }
    
    return 0;
}

int handle_udp_send(struct io_uring_cqe *cqe) {
    if (!cqe) {
        return -1;
    }
    
    io_op_t *op = (io_op_t *)io_uring_cqe_get_data(cqe);
    
    if (cqe->res < 0) {
        log_error("UDP send failed: %s", strerror(-cqe->res));
    } else {
        log_debug("Sent %d bytes via UDP", cqe->res);
    }
    
    if (op) {
        io_op_free(op);
    }
    
    return 0;
}

// Made with Bob
