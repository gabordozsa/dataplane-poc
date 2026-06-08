#include "packet_handler.h"
#include "utils.h"
#include <string.h>
#include <errno.h>

io_op_t *wait_for_recv(iouring_ctx_t *uring_ctx) {
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
                continue;
            }
            log_error("io_uring_wait_cqe failed");
            return NULL;
        }
        op = (io_op_t *)io_uring_cqe_get_data(cqe);
        ret = cqe->res;
        iouring_cqe_seen(uring_ctx, cqe);
         if (ret < 0) {
            log_error("%s failed: %s", op_type_str(op->op_type), strerror(-ret));
            return NULL;
        }
        if (!op) {
            log_error("CQE without io_op data");
            return NULL;
        }
         op->data_len = ret;
        if (op->data_len== 0) {
            log_warn("%s 0 byte", op_type_str(op->op_type));
        }
        // Process based on operation type
        switch (op->op_type) {
            case OP_TYPE_UDP_RECV:
                log_debug("UDP received %d bytes, fd %d", op->data_len, op->fd);
                ret = iouring_resubmit_recv(uring_ctx, op);
                done = true;
                break;
            case OP_TYPE_UDP_SEND:
                log_debug("UDP sent %d bytes, fd %d", op->data_len, op->fd);
                io_op_free(op);
                break;
            case OP_TYPE_TUN_READ:
                log_debug("TUN read %d bytes", op->data_len);
                 ret = iouring_resubmit_recv(uring_ctx, op);
                 done = true;
                 break;
            case OP_TYPE_TUN_WRITE:
                 log_debug("TUN wrote %d bytes", op->data_len);
                 io_op_free(op);
                 break;
            default:
                log_error("Unknown operation type: %d", op->op_type);
                ret = -1;
                done = true;
                break;
        }
    }

    if (ret < 0) {
         io_op_free(op);
         return NULL;
    }
    return op;
}

int dtls_encrypt_and_send_udp(dtls_connection_t *conn,
                              const uint8_t *data, size_t len,
                              iouring_ctx_t *uring_ctx) {
    uint8_t encrypted[PACKET_BUFFER_SIZE];
    int encrypted_len = dtls_encrypt_packet(conn, data, len,
                                            encrypted, sizeof(encrypted));
    if (encrypted_len < 0) {
        return -1;
    }

    if (at_log_level(LOG_DEBUG)) {
        print_ip_packet_info(encrypted, encrypted_len, "encrypted");
    }

    io_op_t *op = io_op_alloc(OP_TYPE_UDP_SEND, conn->udp_fd);
    if (!op) {
        return -1;
    }
    int ret = iouring_submit_udp_send(uring_ctx, op,
                                      (struct sockaddr *)&conn->addr, conn->addr_len,
                                      encrypted, encrypted_len);
    return ret;
}

int dtls_decrypt_and_write_tun(dtls_connection_t *conn,
                               int tun_fd,
                               const uint8_t *encrypted, int encrypted_len,
                               iouring_ctx_t *uring_ctx) {
    uint8_t decrypted[PACKET_BUFFER_SIZE];
    int decrypted_len = dtls_decrypt_packet(conn,
                                  encrypted, encrypted_len,
                                  decrypted, sizeof(decrypted));
    if (decrypted_len < 0) {
        return -1;
    }

    if (at_log_level(LOG_DEBUG)) {
        print_ip_packet_info(decrypted, decrypted_len, "decrypted");
    }

    io_op_t *tun_op = io_op_alloc(OP_TYPE_TUN_WRITE, tun_fd);
    if (tun_op) {
        log_debug("Writing %d bytes to TUN", decrypted_len);
        //print_ip_packet_info(decrypted, decrypted_len);
        tun_op->fd = tun_fd;
        int ret = iouring_submit_tun_write(uring_ctx, tun_op, decrypted, decrypted_len);
        if (ret < 0) {
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}
// Made with Bob
