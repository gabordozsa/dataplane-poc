#include "iouring.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#if !(HAS_MULTI_RECV)
void io_uring_prep_recvmsg_multishot(struct io_uring_sqe *sqe,
                                     int fd,
                                     struct msghdr *msg,
                                     unsigned flags) {
    (void)sqe, (void)fd, (void)msg, (void)flags;
    log_error("io_uring_prep_recvmsg_multishot() is not available");
    assert(0);
}
#endif /*HAS_MULTI_RECV*/

#if  !(HAS_MULTI_READ)
void io_uring_prep_read_multishot(struct io_uring_sqe *sqe,
                                  int fd,
                                  unsigned nbytes,
                                  __u64 offset,
                                  int buf_group) {
    (void)sqe, (void)fd, (void)nbytes, (void)offset, (void)buf_group;
    log_error("io_uring_prep_read_multishot() is not available");
    assert(0);
}
#endif /*HAS_MULTI_READ*/

const char *op_type_str(int op_type)
{
    switch (op_type)
    {
    case OP_TYPE_TUN_READ:
        return "TUN read";
        break;
    case OP_TYPE_TUN_WRITE:
        return "TUN write";
        break;
    case OP_TYPE_UDP_RECV:
        return "UDP recv";
        break;
    case OP_TYPE_UDP_SEND:
        return "UDP send";
        break;
    default:
        break;
    }
    return "UNKNOWN";
}

iouring_ctx_t* iouring_init(unsigned queue_depth) {
    iouring_ctx_t *ctx = calloc(1, sizeof(iouring_ctx_t));
    if (!ctx) {
        log_error("Failed to allocate io-uring context");
        return NULL;
    }

    ctx->queue_depth = queue_depth;

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

int iouring_alloc_buffers(iouring_ctx_t *ctx) {
    if (USE_MULTI_RECV || USE_MULTI_READ) {
        int ret = iouring_alloc_multishot_buffers(ctx, BUF_SIZE, N_BUFS);
        if (ret != 0) {
            return -1;
        }
    }
     // TODO : pre-alloc buffers for single send/recv operations

     return 0;
}

int iouring_alloc_multishot_buffers(iouring_ctx_t *ctx, int buf_size, int n_bufs) {
    /* Create buffers and buffer ring */
    int pagesize = (int)sysconf(_SC_PAGESIZE);
    if (posix_memalign((void**)&ctx->bufs, pagesize, buf_size * n_bufs)) {
        log_error("Could not allocate memory for io_uring buffers");
        return -1;
    }
    memset((void*)ctx->bufs, 0, buf_size * n_bufs);
    ctx->buf_size = buf_size;
    ctx->n_bufs = n_bufs;

    int err = 0;
    ctx->br = io_uring_setup_buf_ring(&ctx->ring, n_bufs, BUF_BGID, 0, &err);
    if (!ctx->br) {
        log_error("Could not create buffer ring");
        return -1;
    }
    //io_uring_buf_ring_init(br);
    for (int i = 0; i < n_bufs; i++) {
        io_uring_buf_ring_add(ctx->br, ctx->bufs + i * buf_size, buf_size, i,
                              io_uring_buf_ring_mask(n_bufs), i);

    }
    io_uring_buf_ring_advance(ctx->br, n_bufs);
    return 0;
}

void iouring_free_buffers(iouring_ctx_t *ctx) {
    int ret = io_uring_free_buf_ring(&ctx->ring, ctx->br, ctx->n_bufs, BUF_BGID);
    if (ret != 0) {
        log_error("Failed to free buffer ring: %s",strerror(ret));
        return;
    }
    free(ctx->bufs);
}

void iouring_recycle_buffer(iouring_ctx_t *ctx, io_op_t *op) {
    assert(op && op->is_multi);
    io_uring_buf_ring_add(ctx->br, ctx->bufs + op->buf_idx * ctx->buf_size, ctx->buf_size, op->buf_idx,
                          io_uring_buf_ring_mask(ctx->n_bufs), 0);
    io_uring_buf_ring_advance(ctx->br, 1);
    log_debug("UDP multishot recycled buffer %p idx %d",op->buffer, op->buf_idx);
}

int iouring_submit_multishot_recvmsg(iouring_ctx_t *ctx, int fd) {
    io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV, fd, true/*is_multi*/);
    if (!op) {
        return -1;
    }
    assert(op->is_multi == true);
    op->msg.msg_namelen = sizeof(struct sockaddr_storage);

    struct io_uring_sqe *sqe;
    sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_warn("Submission queue is full");
        return -1;
    }
    //io_uring_sqe_set_data(sqe, op);
    //io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
    //sqe->buf_group = BUF_BGID;
    io_uring_prep_recvmsg_multishot(sqe, op->fd, &op->msg, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = BUF_BGID;
    io_uring_sqe_set_data(sqe, op);
    if (io_uring_submit(&ctx->ring) < 0) {
        log_error("Failed to submit multishot recvmsg SQE");
        return -1;
    }
    return 0;
}

int iouring_multishot_recvmsg_out(iouring_ctx_t *ctx, io_op_t *op, unsigned cqe_flags) {
    if (!(cqe_flags & IORING_CQE_F_BUFFER)) {
        log_error("Buffer selected flag is not set for multishot recvmsg");
        return -1;
    }

    op->buf_idx = cqe_flags >> IORING_CQE_BUFFER_SHIFT;
    uint8_t *buf = ctx->bufs + op->buf_idx * ctx->buf_size;
    struct io_uring_recvmsg_out *mout = io_uring_recvmsg_validate(buf, op->data_len /*cqe->res*/, &op->msg);
    if (!mout) {
        log_error("Failed to validate multishot recvmsg");
        return -1;
    }
    op->addr = (struct sockaddr_storage *)io_uring_recvmsg_name(mout);
    op->addr_len = mout->namelen;
    if (!op->addr ||  !op->addr_len) {
        log_error("Could not get address from multishot recvmsg (len:%d)", op->addr_len);
        return -1;
    }
    op->buffer = (uint8_t *)io_uring_recvmsg_payload(mout, &op->msg);
    op->data_len = io_uring_recvmsg_payload_length(mout, op->data_len /*cqe->res*/, &op->msg);
    if (!op->buffer || !op->data_len) {
        log_error("Could not get data from multishot recvmsg (len:%d)", op->data_len);
        return -1;
    }
    log_debug("UDP multishot received %d bytes, buffer %p buffer idx %d [%02x %02x %02x %02x] fd %d", op->data_len, op->buffer, op->buf_idx, op->buffer[0], op->buffer[1], op->buffer[2], op->buffer[3], op->fd);

    if (!(cqe_flags & IORING_CQE_F_MORE)) {
        // multishot request is done
        log_error("Multishot recvmsg is done unexpectedly");
        return -1;
    }
    return 0;
}

int iouring_multishot_read_out(iouring_ctx_t *ctx, io_op_t *op, unsigned cqe_flags) {
    if (!(cqe_flags & IORING_CQE_F_BUFFER)) {
        log_error("Buffer selected flag is not set for multishot read");
        return -1;
    }

    op->buf_idx = cqe_flags >> IORING_CQE_BUFFER_SHIFT;
    op->buffer = ctx->bufs + op->buf_idx * ctx->buf_size;

    if (!(cqe_flags & IORING_CQE_F_MORE)) {
        // multishot request is done
        log_error("Multishot read is done unexpectedly");
        return -1;
    }
    return 0;
}

int iouring_submit_multishot_read(iouring_ctx_t *ctx, int fd) {
    io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV, fd, true/*is_multi*/);
    if (!op) {
        return -1;
    }
    assert(op->is_multi == true);

    struct io_uring_sqe *sqe;
    sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_warn("Submission queue is full");
        return -1;
    }
    io_uring_sqe_set_data(sqe, op);
    io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
    sqe->buf_group = BUF_BGID;
    io_uring_prep_read_multishot(sqe, op->fd, 0 /*nbytes*/, 0, BUF_BGID);
    if (io_uring_submit(&ctx->ring) < 0) {
        log_error("Failed to submit multishot read SQE");
        return -1;
    }
    return 0;
}

int iouring_initial_udp_recvs(iouring_ctx_t *ctx, int fd) {
    if (USE_MULTI_RECV) {
        int ret = iouring_submit_multishot_recvmsg(ctx, fd);
        return ret;
    }

    int num_recv_ops = 8;
    for (int i = 0; i < num_recv_ops; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_UDP_RECV, fd, false /*is_multi*/);
        if (op) {
            int ret = iouring_submit_udp_recv(ctx, op);
            if (ret < 0) {
                log_error("Failed to submit UDP recv %d", i);
                io_op_free(ctx, &op);
                return 1;
            }
        }
    }
    return 0;
}

int iouring_initial_tun_reads(iouring_ctx_t *ctx, int fd) {
    if (USE_MULTI_READ) {
        int ret = iouring_submit_multishot_read(ctx, fd);
        return ret;
    }

    int num_recv_ops = 8;
    for (int i = 0; i < num_recv_ops; i++) {
        io_op_t *op = io_op_alloc(OP_TYPE_TUN_READ, fd, false /*is_multi*/);
        if (op) {
            int ret = iouring_submit_tun_read(ctx, op);
            if (ret < 0) {
                log_error("Failed to submit UDP recv %d", i);
                io_op_free(ctx, &op);
                return 1;
            }
        }
    }
    return 0;
}

int iouring_submit_tun_read(iouring_ctx_t *ctx, io_op_t *op) {
    if (!ctx || !op) {
        log_error("Invalid parameters for TUN read");
        return -1;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_error("Failed to get SQE for TUN read");
        return -1;
    }

    assert(op->op_type == OP_TYPE_TUN_READ);

    // Prepare read operation
    io_uring_prep_read(sqe, op->fd, op->buffer, BUF_SIZE, 0);
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
    if (!ctx || !op || !data || op->fd < 0) {
        log_error("Invalid parameters for TUN write");
        return -1;
    }
    assert(!op->is_multi);

    if (len > BUF_SIZE) {
        log_error("TUN write data too large: %zu", len);
        return -1;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_error("Failed to get SQE for TUN write");
        return -1;
    }

    assert(op->op_type == OP_TYPE_TUN_WRITE);
    memcpy(op->buffer, data, len);

    // Prepare write operation
    io_uring_prep_write(sqe, op->fd, op->buffer, len, 0);
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

int iouring_submit_udp_recv(iouring_ctx_t *ctx, io_op_t *op) {
    if (!ctx || !op) {
        log_error("Invalid parameters for UDP recv");
        return -1;
    }
    assert(op->op_type == OP_TYPE_UDP_RECV);
    assert(!op->is_multi);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_error("Failed to get SQE for UDP recv");
        return -1;
    }

    // Setup msghdr for recvmsg
    memset(&op->msg, 0, sizeof(op->msg));
    memset(op->addr, 0, sizeof(*op->addr));

    op->iov.iov_base = op->buffer;
    op->iov.iov_len = BUF_SIZE;

    op->msg.msg_iov = &op->iov;
    op->msg.msg_iovlen = 1;
    op->msg.msg_name = op->addr;
    op->msg.msg_namelen = sizeof(*op->addr);
    op->addr_len = sizeof(*op->addr);

    // Prepare recvmsg operation
    io_uring_prep_recvmsg(sqe, op->fd, &op->msg, 0);
    io_uring_sqe_set_data(sqe, op);

    // Submit
    int ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        log_error("Failed to submit UDP recv: %s", strerror(-ret));
        return -1;
    }

    log_debug("Submitted UDP recv operation on fd=%d", op->fd);
    return 0;
}

int iouring_submit_udp_send(iouring_ctx_t *ctx, io_op_t *op,
                            const struct sockaddr *addr, socklen_t addr_len,
                            const uint8_t *data, size_t len) {
    if (!ctx || !op || !addr || !data || op->fd < 0) {
        log_error("Invalid parameters for UDP send");
        return -1;
    }

    if (len > BUF_SIZE) {
        log_error("UDP send data too large: %zu", len);
        return -1;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_error("Failed to get SQE for UDP send");
        return -1;
    }

    assert(op->op_type == OP_TYPE_UDP_SEND);
    memcpy(op->buffer, data, len);

    // Setup msghdr for sendmsg
    memset(&op->msg, 0, sizeof(op->msg));
    memcpy(op->addr, addr, addr_len);
    op->addr_len = addr_len;

    op->iov.iov_base = op->buffer;
    op->iov.iov_len = len;

    op->msg.msg_iov = &op->iov;
    op->msg.msg_iovlen = 1;
    op->msg.msg_name = op->addr;
    op->msg.msg_namelen = addr_len;

    // Prepare sendmsg operation
    io_uring_prep_sendmsg(sqe, op->fd, &op->msg, 0);
    io_uring_sqe_set_data(sqe, op);

    // Submit
    int ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        log_error("Failed to submit UDP send: %s", strerror(-ret));
        return -1;
    } else if (ret == 0) {
        log_error("Failed to submit UDP send, ret=0");
        return -1;
    }

    log_debug("Submitted UDP send operation on fd=%d: %zu bytes to %s op %p",
              op->fd, len, addr_to_string(addr), op);

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
        if (USE_MULTI_RECV || USE_MULTI_READ) {
            iouring_free_buffers(ctx);
        }
        free(ctx);
    }
}

io_op_t* io_op_alloc(int op_type, int fd, bool is_multi) {
    io_op_t *op = calloc(1, sizeof(io_op_t));
    if (!op) {
        log_error("Failed to allocate I/O operation");
        return NULL;
    }
    op->is_multi = is_multi;
    op->op_type = op_type;
    op->fd = fd;
    if (!is_multi) {
        op->buffer = (uint8_t*)malloc(BUF_SIZE);
        op->addr = (struct sockaddr_storage*)malloc(sizeof(struct sockaddr_storage));
        if (!op->buffer || ! op->addr) {
            log_error("Failed to allocate memory for I/O operation");
            free(op->buffer);
            free(op->addr);
            free(op);
            return NULL;
        }
        memset((void *)op->buffer, 0, BUF_SIZE);
    }
    return op;
}

void io_op_free(iouring_ctx_t *ctx, io_op_t **op) {
    if (*op) {
        if ((*op)->is_multi) {
            iouring_recycle_buffer(ctx, *op);
            //memset(&(*op)->msg, 0, sizeof((*op)->msg));
            //(*op)->msg.msg_namelen = sizeof(struct sockaddr_storage);
        } else {
            free((*op)->buffer);
            free((*op)->addr);
            free(*op);
            *op = NULL;
        }
    }
}

int iouring_resubmit_recv(iouring_ctx_t *uring_ctx, io_op_t *completed) {
    int ret = 0;
    io_op_t * new_op = io_op_alloc(completed->op_type, completed->fd, false /*is_multi*/);
    if (!new_op) {
        ret = -1;
    } else {
        switch(completed->op_type) {
            case OP_TYPE_TUN_READ:
                ret = iouring_submit_tun_read(uring_ctx, new_op);
                break;
            case OP_TYPE_UDP_RECV:
                ret = iouring_submit_udp_recv(uring_ctx, new_op);
                break;
            default:
                log_error("Wrong recv op type");
                ret = -1;
        }
    }
    return ret;
}

// Made with Bob
