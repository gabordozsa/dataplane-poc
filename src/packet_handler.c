#include "packet_handler.h"
#include "utils.h"
#include <string.h>
#include <errno.h>
#include <assert.h>


static
int finalize_completion(iouring_ctx_t *uring_ctx, struct io_uring_cqe *cqe, io_op_t **op1) {
    int ret = 0;
    int cqe_res = cqe->res;
    unsigned cqe_flags = cqe->flags;
    bool recv_completed = false;
    io_op_t *op = io_uring_cqe_get_data(cqe);
    *op1 = op;
    iouring_cqe_seen(uring_ctx, cqe);
    if (cqe_res < 0) {
        log_error("%s failed: %s (is_multi %d)", op_type_str(op->op_type), strerror(-cqe_res), op->is_multi);
        return -1;
    }
    if (!op) {
        log_error("CQE without io_op data");
        return -1;
    }
    op->data_len = cqe_res;
    if (op->data_len== 0) {
        log_warn("%s 0 byte", op_type_str(op->op_type));
    }
    // Process based on operation type
    switch (op->op_type) {
        case OP_TYPE_UDP_RECV:
            if (op->is_multi) {
                ret = iouring_multishot_recvmsg_out(uring_ctx, op, cqe_flags);
            } else {
                log_debug("UDP received %d bytes, fd %d", op->data_len, op->fd);
                ret = iouring_resubmit_recv(uring_ctx, op);
            }
            recv_completed = true;
            break;
        case OP_TYPE_UDP_SEND:
            assert(!op->is_multi);
            log_debug("UDP sent %d bytes, fd %d", op->data_len, op->fd);
            io_op_free(uring_ctx, &op);
            break;
        case OP_TYPE_TUN_READ:
            if (op->is_multi) {
                ret = iouring_multishot_read_out(uring_ctx, op, cqe_flags);
            } else {
                log_debug("TUN read %d bytes", op->data_len);
                ret = iouring_resubmit_recv(uring_ctx, op);
                if (ret < 0) {
                     log_error("ERROR finalize_completion() io_op_pool %p", uring_ctx->io_op_pool);
                }
            }
            recv_completed = true;
            break;
        case OP_TYPE_TUN_WRITE:
            assert(!op->is_multi);
            log_debug("TUN wrote %d bytes", op->data_len);
            io_op_free(uring_ctx, &op);
            break;
        default:
            log_error("Unknown operation type: %d", op->op_type);
            ret = -1;
            break;
    }

    if (ret < 0) {
        io_op_free(uring_ctx, &op);
        return -1;
    }

    if (recv_completed)
        ret = 0;
    else
        ret = 1;

    return ret;
}

io_op_t *wait_for_recv(iouring_ctx_t *uring_ctx, volatile int *running) {
    int ret = 0;
    io_op_t *op = NULL;
    bool done = false;
    log_debug("Entering wait_for_recv ...");
    while (!done) {
        struct io_uring_cqe *cqe;
        int wait_ret = iouring_wait_cqe(uring_ctx, &cqe);
        if (wait_ret < 0) {
            if (wait_ret == -ETIME) {
                //log_debug("Waiting in wait_for_recv ...");
                if (running && *running) {
                    continue;
                } else {
                    log_info("wait_for_recv signaled to quit");
                    return NULL;
                }
            }
            log_error("io_uring_wait_cqe failed");
            return NULL;
        }
        ret = finalize_completion(uring_ctx, cqe, &op);
        if (ret == -1) {
            return NULL;
        } else if (ret == 0) {
            done = true;
        }
    }
    return op;
}

io_op_t *check_for_recv(iouring_ctx_t *uring_ctx, int *err) {
    int ret = 0;
    io_op_t *op = NULL;
    bool done = false;
    *err = 0; 
    //log_debug("Entering wait_for_recv2 ...");
    while (!done) {
        struct io_uring_cqe *cqe;
        ret = iouring_peek_cqe(uring_ctx, &cqe);
        if (ret < 0) {
            if (ret == -EAGAIN) {
                *err = 0;
            } else {
                *err = ret;
            }
            return NULL;
        }
        ret = finalize_completion(uring_ctx, cqe, &op);
        if (ret == -1) {
            log_error("ERROR check_for_recv() io_op_pool %p", uring_ctx->io_op_pool);
            *err = -1;
            return NULL;
        } else if (ret == 0) {
            done = true;
        }
    }
    return op;
}

int dtls_encrypt_and_send_udp(connection_t *conn,
                              const uint8_t *data, size_t len,
                              iouring_ctx_t *uring_ctx) {
    if (at_log_level(LOG_DEBUG)) {
        print_ip_packet_info(data, len, "To be encrypted");
    }

    io_op_t *op = io_op_alloc(uring_ctx, OP_TYPE_UDP_SEND, conn->udp_fd, false /*is_multi*/);
    if (!op) {
        return -1;
    }

    op->data_len = dtls_encrypt_packet(conn, data, len, op->buffer, BUF_SIZE);
    if (op->data_len < 0) {
        io_op_free(uring_ctx, &op);
        return -1;
    }

    int ret = iouring_submit_udp_send(uring_ctx, op,
                                      (struct sockaddr *)&conn->addr, conn->addr_len,
                                      NULL /*data is already in place*/, op->data_len);
    if (ret < 0) {
        io_op_free(uring_ctx, &op);
        return -1;
    }
    return 0;
}

int dtls_decrypt_and_write_tun(connection_t *conn,
                               int tun_fd,
                               const uint8_t *encrypted, int encrypted_len,
                               iouring_ctx_t *uring_ctx) {
    io_op_t *tun_op = io_op_alloc(uring_ctx, OP_TYPE_TUN_WRITE, tun_fd, false /*is_multi*/);
    if (!tun_op) {
        return -1;
    }
    tun_op->data_len = dtls_decrypt_packet(conn,
                                           encrypted, encrypted_len,
                                           tun_op->buffer, BUF_SIZE);
    if ( tun_op->data_len < 0) {
        io_op_free(uring_ctx, &tun_op);
        return -1;
    }

    log_debug("Writing %d bytes to TUN",  tun_op->data_len);
    if (at_log_level(LOG_DEBUG)) {
        print_ip_packet_info(tun_op->buffer, tun_op->data_len, "decrypted");
    }

    tun_op->fd = tun_fd;
    int ret = iouring_submit_tun_write(uring_ctx, tun_op, 
                                       NULL /*data is already in place*/, tun_op->data_len);
    if (ret < 0) {
        io_op_free(uring_ctx, &tun_op);
        return -1;
    }

    return 0;
}


int tun_to_udp(connection_t *conn,
               io_op_t *tun_read_op,
               iouring_ctx_t *tun2udp_ctx) {
    if (at_log_level(LOG_DEBUG)) {
        print_ip_packet_info(tun_read_op->buffer, tun_read_op->data_len, "TUN -> UDP");
    }

    io_op_t *send_op = io_op_alloc_buf(tun2udp_ctx, OP_TYPE_UDP_SEND, conn->udp_fd, false /*is_multi*/, tun_read_op);
    if (!send_op) {
        return -1;
    }

    int ret = iouring_submit_udp_send(tun2udp_ctx, send_op,
                                      (struct sockaddr *)&conn->addr, conn->addr_len,
                                      NULL /*data is already in place*/, send_op->data_len);
    if (ret < 0) {
        io_op_free(tun2udp_ctx, &send_op);
        return -1;
    }
    return 0;
}

int udp_to_tun(int tun_fd,
               io_op_t *udp_recv_op,
               iouring_ctx_t *udp2tun_ctx) {
    if (at_log_level(LOG_DEBUG)) {
        print_ip_packet_info(udp_recv_op->buffer, udp_recv_op->data_len, "UDP -> TUN");
    }

    io_op_t *send_op = io_op_alloc_buf(udp2tun_ctx, OP_TYPE_TUN_WRITE, tun_fd, false /*is_multi*/, udp_recv_op);
    if (!send_op) {
        return -1;
    }

    int ret = iouring_submit_tun_write(udp2tun_ctx, send_op, NULL /*data is in place*/, send_op->data_len);
    if (ret < 0) {
        io_op_free(udp2tun_ctx, &send_op);
        return -1;
    }
    return 0;
}




