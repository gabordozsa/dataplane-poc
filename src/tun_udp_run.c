#include "connection.h"
#include "iouring.h"
#include "utils.h"
#include "packet_handler.h"

int tun_udp_run(iouring_ctx_t *uring_ctx, dtls_connection_t *conn, int tun_fd, volatile int *running) {
    if (!uring_ctx || !conn || tun_fd < 0) {
            return -1;
    }
    int ret = 0;

    log_info("Starting server main loop");

    // Main event loop
    io_op_t *op = NULL;
    while (*running) {
        op = wait_for_recv(uring_ctx);
        if (op) {
            switch (op->op_type) {
                case OP_TYPE_TUN_READ:
                    ret = dtls_encrypt_and_send_udp(conn, op->buffer, op->data_len, uring_ctx);
                    if (ret >= 0) {
                        log_debug("IP packet from TUN got encrypted to be sent via UDP");
                    }
                    break;
                case OP_TYPE_UDP_RECV:
                    ret = dtls_decrypt_and_write_tun(conn, tun_fd, op->buffer, op->data_len, uring_ctx);
                    if (ret >= 0) {
                        log_debug("IP packet from UDP got decrypted to be written to TUN");
                    }
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