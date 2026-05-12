#include "iouring.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

iouring_ctx_t* iouring_init(unsigned queue_depth) {
    iouring_ctx_t *ctx = calloc(1, sizeof(iouring_ctx_t));
    if (!ctx) {
        log_error("Failed to allocate io-uring context");
        return NULL;
    }
    
    ctx->queue_depth = queue_depth;
    ctx->tun_fd = -1;
    
    // Initialize io-uring
    int ret = io_uring_queue_init(queue_depth, &ctx->ring, 0);
    if (ret < 0) {
        log_error("Failed to initialize io-uring: %s", strerror(-ret));
        free(ctx);
        return NULL;
    }
    
    log_info("Initialized io-uring with queue depth %u", queue_depth);
    
    return ctx;
}

void iouring_set_tun_fd(iouring_ctx_t *ctx, int tun_fd) {
    if (ctx) {
        ctx->tun_fd = tun_fd;
        log_debug("Set io-uring TUN fd: tun=%d", tun_fd);
    }
}

int iouring_submit_tun_read(iouring_ctx_t *ctx, io_op_t *op) {
    if (!ctx || !op || ctx->tun_fd < 0) {
        log_error("Invalid parameters for TUN read");
        return -1;
    }
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_error("Failed to get SQE for TUN read");
        return -1;
    }
    
    op->op_type = OP_TYPE_TUN_READ;
    
    // Prepare read operation
    io_uring_prep_read(sqe, ctx->tun_fd, op->buffer, PACKET_BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, op);
    
    // Submit
    int ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        log_error("Failed to submit TUN read: %s", strerror(-ret));
        return -1;
    }
    
    log_debug("Submitted TUN read operation");
    return 0;
}

int iouring_submit_tun_write(iouring_ctx_t *ctx, io_op_t *op,
                             const uint8_t *data, size_t len) {
    if (!ctx || !op || !data || ctx->tun_fd < 0) {
        log_error("Invalid parameters for TUN write");
        return -1;
    }
    
    if (len > PACKET_BUFFER_SIZE) {
        log_error("TUN write data too large: %zu", len);
        return -1;
    }
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_error("Failed to get SQE for TUN write");
        return -1;
    }
    
    op->op_type = OP_TYPE_TUN_WRITE;
    memcpy(op->buffer, data, len);
    
    // Prepare write operation
    io_uring_prep_write(sqe, ctx->tun_fd, op->buffer, len, 0);
    io_uring_sqe_set_data(sqe, op);
    
    // Submit
    int ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        log_error("Failed to submit TUN write: %s", strerror(-ret));
        return -1;
    }
    
    log_debug("Submitted TUN write operation: %zu bytes", len);
    return 0;
}

int iouring_submit_udp_recv(iouring_ctx_t *ctx, int udp_fd, io_op_t *op) {
    if (!ctx || !op || udp_fd < 0) {
        log_error("Invalid parameters for UDP recv");
        return -1;
    }
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_error("Failed to get SQE for UDP recv");
        return -1;
    }
    
    op->op_type = OP_TYPE_UDP_RECV;
    
    // Setup msghdr for recvmsg
    memset(&op->msg, 0, sizeof(op->msg));
    memset(&op->addr, 0, sizeof(op->addr));
    
    op->iov.iov_base = op->buffer;
    op->iov.iov_len = PACKET_BUFFER_SIZE;
    
    op->msg.msg_iov = &op->iov;
    op->msg.msg_iovlen = 1;
    op->msg.msg_name = &op->addr;
    op->msg.msg_namelen = sizeof(op->addr);
    op->addr_len = sizeof(op->addr);
    
    // Prepare recvmsg operation
    io_uring_prep_recvmsg(sqe, udp_fd, &op->msg, 0);
    io_uring_sqe_set_data(sqe, op);
    
    // Submit
    int ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        log_error("Failed to submit UDP recv: %s", strerror(-ret));
        return -1;
    }
    
    log_debug("Submitted UDP recv operation on fd=%d", udp_fd);
    return 0;
}

int iouring_submit_udp_send(iouring_ctx_t *ctx, int udp_fd, io_op_t *op,
                            const struct sockaddr *addr, socklen_t addr_len,
                            const uint8_t *data, size_t len) {
    if (!ctx || !op || !addr || !data || udp_fd < 0) {
        log_error("Invalid parameters for UDP send");
        return -1;
    }
    
    if (len > PACKET_BUFFER_SIZE) {
        log_error("UDP send data too large: %zu", len);
        return -1;
    }
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_error("Failed to get SQE for UDP send");
        return -1;
    }
    
    op->op_type = OP_TYPE_UDP_SEND;
    memcpy(op->buffer, data, len);
    
    // Setup msghdr for sendmsg
    memset(&op->msg, 0, sizeof(op->msg));
    memcpy(&op->addr, addr, addr_len);
    op->addr_len = addr_len;
    
    op->iov.iov_base = op->buffer;
    op->iov.iov_len = len;
    
    op->msg.msg_iov = &op->iov;
    op->msg.msg_iovlen = 1;
    op->msg.msg_name = &op->addr;
    op->msg.msg_namelen = addr_len;
    
    // Prepare sendmsg operation
    io_uring_prep_sendmsg(sqe, udp_fd, &op->msg, 0);
    io_uring_sqe_set_data(sqe, op);
    
    // Submit
    int ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        log_error("Failed to submit UDP send: %s", strerror(-ret));
        return -1;
    }
    
    log_debug("Submitted UDP send operation on fd=%d: %zu bytes to %s",
              udp_fd, len, addr_to_string(addr));
    
    return 0;
}

int iouring_wait_cqe(iouring_ctx_t *ctx, struct io_uring_cqe **cqe_ptr) {
    if (!ctx || !cqe_ptr) {
        log_error("Invalid parameters for wait_cqe");
        return -1;
    }
    
    // Use timeout to allow periodic tasks (like idle connection cleanup)
    // Timeout of 1 second allows checking for idle connections regularly
    struct __kernel_timespec ts = {
        .tv_sec = 1,
        .tv_nsec = 0
    };
    
    int ret = io_uring_wait_cqe_timeout(&ctx->ring, cqe_ptr, &ts);
    if (ret < 0) {
        if (ret == -ETIME) {
            // Timeout - not an error, just no events within timeout period
            return -ETIME;
        }
        log_error("Failed to wait for CQE: %s", strerror(-ret));
        return -1;
    }
    
    return 0;
}

int iouring_peek_cqe(iouring_ctx_t *ctx, struct io_uring_cqe **cqe_ptr) {
    if (!ctx || !cqe_ptr) {
        log_error("Invalid parameters for peek_cqe");
        return -1;
    }
    
    int ret = io_uring_peek_cqe(&ctx->ring, cqe_ptr);
    if (ret < 0) {
        if (ret == -EAGAIN) {
            return -EAGAIN;
        }
        log_error("Failed to peek CQE: %s", strerror(-ret));
        return -1;
    }
    
    return 0;
}

void iouring_cqe_seen(iouring_ctx_t *ctx, struct io_uring_cqe *cqe) {
    if (ctx && cqe) {
        io_uring_cqe_seen(&ctx->ring, cqe);
    }
}

void iouring_cleanup(iouring_ctx_t *ctx) {
    if (ctx) {
        log_info("Cleaning up io-uring");
        io_uring_queue_exit(&ctx->ring);
        free(ctx);
    }
}

io_op_t* io_op_alloc(int op_type) {
    io_op_t *op = calloc(1, sizeof(io_op_t));
    if (!op) {
        log_error("Failed to allocate I/O operation");
        return NULL;
    }
    
    op->op_type = op_type;
    return op;
}

void io_op_free(io_op_t *op) {
    if (op) {
        free(op);
    }
}

// Made with Bob
