#include "connection.h"
#include "utils.h"
#include "iouring.h"
#include "packet_handler.h"
#include "udp_socket.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>

char *conn_role_str(conn_role_t role) {
    switch (role) {
        case CONN_ROLE_CLIENT:
            return "CLIENT";
            break;
        case CONN_ROLE_SERVER:
            return "SERVER";
            break;
        default:
            return NULL;
    }
    return NULL;
}

connection_t* create_connection(conn_role_t role,
                                const char *remote_host,
                                uint16_t remote_port,
                                uint16_t local_port) {
    if (role == CONN_ROLE_CLIENT) {
        if (remote_host == NULL || remote_port == 0) {
            log_error("Remote host is NULL for CLIENT");
            return NULL;
        }
    }

    // Create connection structure
    connection_t *conn = calloc(1, sizeof(connection_t));
    if (!conn) {
        log_error("Failed to allocate connection");
        return NULL;
    }

    if (role == CONN_ROLE_CLIENT) {
        // Resolve hostname
        int ret = resolve_hostname(remote_host, remote_port, (struct sockaddr *)(&conn->addr), &conn->addr_len);
        if (ret < 0) {
             free(conn);
            return NULL;
        }
        log_info("Resolved CLIENT address to %s", addr_to_string((const struct sockaddr *)&conn->addr));
    }

    // create UDP socket
    conn->udp_fd = udp_socket_create();
    if (conn->udp_fd < 0) {
        log_error("Failed to create UDP socket for %s", conn_role_str(role));
        free(conn);
        return NULL;
    }
    log_info("Created %s UDP socket (fd=%d)", conn_role_str(role), conn->udp_fd);

    if (local_port > 0) {
        // Bind udp socket to port
        if (udp_socket_bind(conn->udp_fd, local_port, NULL) < 0) {
            log_error("Failed to bind %s UDP socket to port %d", conn_role_str(role), local_port);
            close(conn->udp_fd);
            free(conn);
            return NULL;
        }
        log_info("Bound %s UDP socket on port %d (fd=%d)",
                  conn_role_str(role), local_port, conn->udp_fd);
    }
    conn->role = role;

    return conn;
}

int init_dtls_connection(connection_t *conn,
                         const char *cert_file,
                         const char *key_file,
                         const char *ca_file) {
    // dtls context
    if (conn->role == CONN_ROLE_CLIENT)
        conn->dtls_ctx = dtls_client_context_init(ca_file);
    else
        conn->dtls_ctx = dtls_server_context_init(cert_file, key_file);

    if (!conn->dtls_ctx) {
        log_error("Failed to create %s DTLS context", conn_role_str(conn->role));
        return -1;
    }

    // Create SSL
    conn->ssl = dtls_create_ssl(conn->dtls_ctx);
    if (!conn->ssl) {
        log_error("Failed to create SSL for %s", conn_role_str(conn->role));
        return -1;
    }

    // Setup BIO pair
    if (dtls_setup_bio_pair(conn->ssl, &conn->rbio, &conn->wbio) < 0) {
        log_error("Failed to setup BIO pair for %s", conn_role_str(conn->role));
        SSL_free(conn->ssl);
        return -1;
    }

    conn->state = CONN_STATE_HANDSHAKING;
    conn->last_activity = time(NULL);

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
    log_debug("Encrypted packet, bytes: %d", read);
    return read;
}

int dtls_decrypt_packet(connection_t *dtls,
                        const uint8_t *encrypted, int encrypted_len,
                        uint8_t *decrypted, int decrypted_size) {
    int written = BIO_write(dtls->rbio, encrypted, encrypted_len);
    if (written <= 0) {
        log_error("BIO_write failed");
        return -1;
    } else if (written != encrypted_len) {
        log_error("BIO_write wrote %d bytes, expected %d", written, encrypted_len);
        return -1;
    }

    (void)decrypted_size;
    assert(encrypted_len < decrypted_size);
    int read = SSL_read(dtls->ssl, decrypted, encrypted_len);
    int err = SSL_get_error(dtls->ssl, read);
    if (err == SSL_ERROR_WANT_READ) {
        for (int i = 0; i < 4; i++) {
            read = SSL_read(dtls->ssl, decrypted, encrypted_len);
            err = SSL_get_error(dtls->ssl, read);
            if (err != SSL_ERROR_WANT_READ) break;
        }
    }
    if (err != SSL_ERROR_NONE) {
        if (err == SSL_ERROR_ZERO_RETURN) {
        //   close_dtls(dtls);
            log_error("SSL_read failed: ZERO_RETURN");
            return -1;
        } else {
            log_error("SSL_read failed: %s", dtls_get_error_string(dtls->ssl, read));
            return -1;
        }
    }

    log_debug("Decrypted packet, bytes: %d", read);
    return read;
}

int do_dtls_handshake(iouring_ctx_t *uring_ctx, connection_t *conn) {
    if (!conn) {
        log_error("No connection for handshake");
        return -1;
    }
    ERR_clear_error();

    int ret = 0;
    while (true) {
        ret = SSL_do_handshake(conn->ssl);
        log_debug("Handshake:  SSL_do_handshake() ret: %d, err:%s", ret, dtls_get_error_string(conn->ssl, ret));
        // check if SSL wants to send data - this is necessary even if the handshake got completed locally!
        int ssl_send = BIO_ctrl_pending(conn->wbio);
        if (ssl_send) {
            uint8_t buffer[BUF_SIZE];
            int read = BIO_read(conn->wbio, buffer, sizeof(buffer));
            assert(read > 0);
            io_op_t *new_op = io_op_alloc(uring_ctx, OP_TYPE_UDP_SEND, conn->udp_fd, false/*is_multi*/);
            assert(new_op);
            int ret = iouring_submit_udp_send(uring_ctx, new_op,
                                              (struct sockaddr *)&conn->addr,
                                              conn->addr_len, buffer, read);
            if (ret < 0) {
                return -1;
            }
            log_debug("handshake sent response: %d bytes", read);
        }

        if (ret == 1) {
            conn->state = CONN_STATE_ESTABLISHED;
            break; // handshake completed
        } else if (ret == 0) {
            log_error("Handshake: SSL_do_handshake() error:%s", dtls_get_error_string(conn->ssl, ret));
            return -1;
        }
        int err = SSL_get_error(conn->ssl, ret);
        switch(err) {
            case SSL_ERROR_WANT_READ:
                ret = BIO_ctrl_pending(conn->rbio);
                if (ret) {
                    log_error("handshake: SSL wants to READ but RBIO has data (%d)", ret);
                    return -1;
                }
                // Receive UDP message
                io_op_t *op = wait_for_recv(uring_ctx, NULL);
                if (!op) {
                    return -1;
                }
                assert(op->op_type == OP_TYPE_UDP_RECV);
                if (op->fd != conn->udp_fd) {
                    log_warn("handshake: received udp packet from different connection (fd expected:%d got:%d) Dropping it.",
                             conn->udp_fd, op->fd);
                    break;
                }

                if (conn->addr_len == 0) {
                    // First packet
                    assert(op->addr_len > 0);
                    memcpy(&conn->addr, op->addr, op->addr_len);
                    conn->addr_len = op->addr_len;
                    log_debug("Connection address is set to %s (len %d fd %d)",
                               addr_to_string((struct sockaddr *)&conn->addr), conn->addr_len, conn->udp_fd);
                }

                ret = BIO_write(conn->rbio, op->buffer, op->data_len);
                log_debug("handshake: write RBIO: %d", ret);
                io_op_free(uring_ctx, &op);
                break;
            case SSL_ERROR_WANT_WRITE:
                ret = BIO_ctrl_pending(conn->wbio);
                if (ret > 0) {
                    // We already emptied WBIO above
                    log_error("handshake: WBIO is not empty");
                    return -1;
                }
                break;
            default:
                log_error("handshake: SSL_do_handshake() error: %s",  dtls_get_error_string(conn->ssl, ret));
                return -1;
        }
    }
    return 0;
}

// Made with Bob
