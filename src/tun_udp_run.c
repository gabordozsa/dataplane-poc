#include "connection.h"
#include "iouring.h"
#include "utils.h"
#include "packet_handler.h"
#include "assert.h"

int tun_udp_run(iouring_ctx_t *uring_ctx, connection_t *conn, int tun_fd, volatile int *running) {
    if (!uring_ctx || !conn || tun_fd < 0) {
            return -1;
    }
    int ret = 0;

    log_info("Starting main loop");

    // Main event loop
    io_op_t *op = NULL;
    while (*running) {
        op = wait_for_recv(uring_ctx);
        if (op) {
            switch (op->op_type) {
                case OP_TYPE_TUN_READ:
                    ret = dtls_encrypt_and_send_udp(conn, op->buffer, op->data_len, uring_ctx);
                    break;
                case OP_TYPE_UDP_RECV:
                    ret = dtls_decrypt_and_write_tun(conn, tun_fd, op->buffer, op->data_len, uring_ctx);
                    break;
                default:
                    log_error("Invalid recv OP type");
                    ret = -1;
                }
            io_op_free(uring_ctx, &op);
        } else {
            ret = -1;
        }
        if (ret < 0)
            break;
    }
    free(op); // for multi op

    return ret;
}

// no dtls version
int tun_udp_run_zero(iouring_ctx_t *udp_uring_ctx, connection_t *conn, iouring_ctx_t *tun_uring_ctx, int tun_fd, volatile int *running) {
    int ret = 0;

    log_info("Starting main loop");

    // Main event loop
    io_op_t *op = NULL;
    while (*running) {
        int err;
        // check for a cumpleted UDP recv
        op = check_for_recv(udp_uring_ctx, &err);
        if (err != 0)
            return -1;
        if (op) {
            assert(op->op_type == OP_TYPE_UDP_RECV);
            if (conn->addr_len == 0) {
                assert(op->addr_len > 0);
                memcpy(&conn->addr, op->addr, op->addr_len);
                conn->addr_len = op->addr_len;
                log_debug("Connection address is set to %s (len %d fd %d)",
                            addr_to_string((struct sockaddr *)&conn->addr), conn->addr_len, conn->udp_fd);
            }
            ret = udp_to_tun(tun_fd, op, tun_uring_ctx);
            if (ret < 0) {
                log_error("ERROR udp_to_tun()  op->buf_idx %d io_op_pool %p", op->buf_idx, tun_uring_ctx->io_op_pool);
                break;
            }
            io_op_free(udp_uring_ctx, &op);
        }

         // check for a cumpleted TUN read
        op = check_for_recv(tun_uring_ctx, &err);
        if (err != 0) {
            log_error("ERROR  check_for_recv() io_op_pool %p", tun_uring_ctx->io_op_pool);
            return -1;
        }
        if (op) {
            assert(op->op_type == OP_TYPE_TUN_READ);
            ret = tun_to_udp(conn, op,udp_uring_ctx);
            if (ret < 0)
                break;
             io_op_free(tun_uring_ctx, &op);
        }
    }
    return ret;
}