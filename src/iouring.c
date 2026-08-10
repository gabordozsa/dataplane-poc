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

static int iouring_alloc_io_op_pool(iouring_ctx_t *ctx, int n_io_ops) {
    io_op_t *prev = NULL;
    for (int i = 0; i < n_io_ops; i++) {
        io_op_t *op = calloc(1, sizeof(io_op_t));
        if (!op) {
            log_error("Failed to allocate I/O operation");
            return -1;
        }
        if (prev) {
            prev->next = op;
        } else {
            ctx->io_op_pool = op;
        }
        prev = op;
    }
    return 0;
}

static void iouring_free_io_op_pool(iouring_ctx_t *ctx) {
    io_op_t *op = ctx->io_op_pool;
    while(op) {
        io_op_t *prev = op;
        op = op->next;
        free(prev);
    }
    ctx->io_op_pool = NULL;
}

static io_op_t *iouring_get_io_op(iouring_ctx_t *ctx) {
    io_op_t *op = ctx->io_op_pool;
    if (!op) {
        log_error("Failed to get I/O operation from pool (%s)", ctx->config->name);
        return NULL;
    }
    ctx->io_op_pool = op->next;
    memset(op, 0, sizeof(io_op_t));
    op->buf_idx = -1;

    log_debug("GET io_op %p (%s)", op, ctx->config->name); 
    return op;
}

static void iouring_put_io_op(iouring_ctx_t *ctx,io_op_t *op) {
    op->next = ctx->io_op_pool;
    ctx->io_op_pool = op;
    log_debug("PUT io_op %p (%s)", op, ctx->config->name);
}

static int iouring_alloc_buf_addr_pool(iouring_ctx_t *ctx) {
    int n_bufs = ctx->config->n_io_ops;
    ctx->buf_addr_pool = spsc_ring_create(n_bufs);
    if (!ctx->buf_addr_pool) {
        log_error("Failed to create buf_addr ring (%s)", ctx->config->name);
        return -1;
    }
    for (int i = 0; i < n_bufs; i++) {
        buf_addr_t *buf_addr = calloc(1, sizeof(buf_addr_t));
        if (!buf_addr) {
            log_error("Failed to allocate I/O buffer and address for pool (%s)", ctx->config->name);
            return -1;
        }
        buf_addr->pool = ctx->buf_addr_pool;
        bool ok = spsc_ring_push(ctx->buf_addr_pool, (void *)buf_addr);
        if (!ok) {
            log_error("Failed to initialize buf_addr pool: ring is full (%s)", ctx->config->name);
            return -1;
        }
    }
    return 0;
}

static void iouring_free_buf_addr_pool(iouring_ctx_t *ctx) {
    buf_addr_t *buf_addr;
    while(spsc_ring_pop(ctx->buf_addr_pool, (void **)&buf_addr)) {
        assert(buf_addr);
        free(buf_addr);
    }
    spsc_ring_destroy(ctx->buf_addr_pool);
}

buf_addr_t *iouring_get_buf_addr(iouring_ctx_t *ctx) {
    buf_addr_t *buf_addr;
    bool ok = spsc_ring_pop(ctx->buf_addr_pool, (void **)&buf_addr);
    if (!ok) {
        log_error("Failed to get I/O buffer and address (%s)", ctx->config->name);
        return NULL;
    }
    return buf_addr;
}

static void iouring_put_buf_addr(buf_addr_t *buf_addr) {
    bool ok = spsc_ring_push(buf_addr->pool, (void *)buf_addr);
    if (!ok) {
        log_error("Failed to put buf_addr into the pool");
    }
}

static int iouring_alloc_multishot_buffers(iouring_ctx_t *ctx) {
    const int buf_size = BUF_SIZE;
    const int n_bufs = ctx->config->br_n_bufs;
    int pagesize = (int)sysconf(_SC_PAGESIZE);
    void *buf_mem = NULL;
    int ret = posix_memalign(&buf_mem, pagesize, buf_size * n_bufs);
    if (ret != 0) {
        log_error("Could not allocate memory for io_uring buffers");
        return -1;
    }
    ctx->br_bufs = buf_mem;
    memset((void*)ctx->br_bufs, 0, buf_size * n_bufs);

    int err = 0;
    ctx->br = io_uring_setup_buf_ring(&ctx->ring, n_bufs, ctx->config->br_gid, 0, &err);
    if (!ctx->br) {
        log_error("Could not create buffer ring: %s", strerror(-err));
        return -1;
    }
    //io_uring_buf_ring_init(br);
    for (int i = 0; i < n_bufs; i++) {
        io_uring_buf_ring_add(ctx->br, ctx->br_bufs + i * buf_size, buf_size, i,
                              io_uring_buf_ring_mask(n_bufs), i);

    }
    io_uring_buf_ring_advance(ctx->br, n_bufs);
    log_debug("Buffer ring allocated");
    return 0;
}

void iouring_free_buffers(iouring_ctx_t *ctx) {
    iouring_free_io_op_pool(ctx);
    iouring_free_buf_addr_pool(ctx);
    if (USE_MULTI_RECV || USE_MULTI_READ) {
        int ret = io_uring_free_buf_ring(&ctx->ring,
                                         ctx->br,
                                         ctx->config->br_n_bufs,
                                         ctx->config->br_gid);
        if (ret != 0) {
            log_error("Failed to free buffer ring: %s",strerror(ret));
            return;
        }
        free(ctx->br_bufs);
    }
}

static int iouring_alloc_buffers(iouring_ctx_t *ctx) {
    // alloc io_op pool
    int ret = iouring_alloc_io_op_pool(ctx, ctx->config->n_io_ops);
    if (ret != 0) {
        return -1;
    }

    // alloc buffer pool for sends and single shot recvs
     ret = iouring_alloc_buf_addr_pool(ctx);
     if (ret != 0) {
        return -1;
     }

    if (ctx->config->br_n_bufs > 0) {
        assert(USE_MULTI_RECV || USE_MULTI_READ);
        // buffer ring for multishot
        ret = iouring_alloc_multishot_buffers(ctx);
        if (ret != 0) {
            return -1;
        }
}
     return 0;
}

iouring_ctx_t* iouring_init(iouring_config_t *c) {
    iouring_ctx_t *ctx = calloc(1, sizeof(iouring_ctx_t));
    if (!ctx) {
        log_error("Failed to allocate io-uring context");
        return NULL;
    }

    ctx->config = c;

    // Initialize io-uring
    struct io_uring_params p;
    memset(&p, 0, sizeof(struct io_uring_params));
    // TOFO: try  IORING_SETUP_COOP_TASKRUN
    p.flags = IORING_SETUP_CQSIZE;
    p.cq_entries = c->cq_depth;

    int ret = io_uring_queue_init_params(ctx->config->sq_depth, &ctx->ring, &p);
    if (ret < 0) {
        log_error("Failed to initialize io-uring: %s", strerror(-ret));
        free(ctx);
        return NULL;
    }
    bool cqe_no_drop = (p.features & IORING_FEAT_NODROP);

    ret = iouring_alloc_buffers(ctx);
    if (ret != 0)
    {
        return NULL;
    }

    log_info("Initialized io-uring with sq depth %u, cq depth %u, cqe_no_drop %d (%s)",
              c->sq_depth, c->cq_depth, cqe_no_drop, c->name);

    return ctx;
}

static void iouring_recycle_buffer(iouring_ctx_t *ctx, int buf_idx) {
    assert(buf_idx >= 0);
    io_uring_buf_ring_add(ctx->br,
                          ctx->br_bufs +  buf_idx * BUF_SIZE,
                          BUF_SIZE,
                          buf_idx,
                          io_uring_buf_ring_mask(ctx->config->br_n_bufs), 0);
    io_uring_buf_ring_advance(ctx->br, 1);
    log_debug("Recycled br buffer idx %d (%s)", buf_idx, ctx->config->name);
}

static int iouring_submit_multishot_recvmsg_op(iouring_ctx_t *ctx, io_op_t *op) {
    assert(op->is_multi == true);

    struct io_uring_sqe *sqe;
    sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_warn("Submission queue is full");
        return -1;
    }
    // prep be called before sge flags are set !!!!
    io_uring_prep_recvmsg_multishot(sqe, op->fd, &op->msg, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = ctx->config->br_gid;
    io_uring_sqe_set_data(sqe, op);
    if (io_uring_submit(&ctx->ring) < 0) {
        log_error("Failed to submit multishot recvmsg SQE");
        return -1;
    }
    return 0;
}

int iouring_submit_multishot_recvmsg(iouring_ctx_t *ctx, int fd) {
    io_op_t *op = io_op_alloc(ctx, OP_TYPE_UDP_RECV, fd, true/*is_multi*/);
    if (!op) {
        return -1;
    }
    op->msg.msg_namelen = sizeof(struct sockaddr_storage);

    int ret = iouring_submit_multishot_recvmsg_op(ctx, op);
    return ret;
}

int iouring_multishot_recvmsg_out(iouring_ctx_t *ctx, io_op_t *op, unsigned cqe_flags) {
    if (!(cqe_flags & IORING_CQE_F_BUFFER)) {
        log_error("Buffer selected flag is not set for multishot recvmsg");
        return -1;
    }

    op->buf_idx = cqe_flags >> IORING_CQE_BUFFER_SHIFT;
    uint8_t *buf = ctx->br_bufs + op->buf_idx * BUF_SIZE;
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
        int ret = iouring_submit_multishot_recvmsg_op(ctx, op);
        if (ret != 0) {
            return -1;
        }
        ctx->stats.multi_recv_rearmed++;
        log_debug("Multishot recvmsg got completed and re-submitted.");
    }
    return 0;
}

static
int iouring_submit_multishot_read_op(iouring_ctx_t *ctx, io_op_t *op) {
    assert(op->is_multi && op->op_type == OP_TYPE_TUN_READ);

    struct io_uring_sqe *sqe;
    sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        log_warn("Submission queue is full");
        return -1;
    }
    io_uring_prep_read_multishot(sqe, op->fd, 0 /*nbytes*/, 0, ctx->config->br_gid);
    io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
    sqe->buf_group = ctx->config->br_gid;
    io_uring_sqe_set_data(sqe, op);
    if (io_uring_submit(&ctx->ring) < 0) {
        log_error("Failed to submit multishot read SQE");
        return -1;
    }
    return 0;
}

int iouring_submit_multishot_read(iouring_ctx_t *ctx, int fd) {
    io_op_t *op = io_op_alloc(ctx, OP_TYPE_UDP_RECV, fd, true/*is_multi*/);
    if (!op) {
        return -1;
    }
    assert(op->is_multi == true);

    return iouring_submit_multishot_read_op(ctx, op);
}

int iouring_multishot_read_out(iouring_ctx_t *ctx, io_op_t *op, unsigned cqe_flags) {
    if (!(cqe_flags & IORING_CQE_F_BUFFER)) {
        log_error("Buffer selected flag is not set for multishot read");
        return -1;
    }

    op->buf_idx = cqe_flags >> IORING_CQE_BUFFER_SHIFT;
    op->buffer = ctx->br_bufs + op->buf_idx * BUF_SIZE;

    if (!(cqe_flags & IORING_CQE_F_MORE)) {
        // multishot request is done
        int ret = iouring_submit_multishot_read_op(ctx, op);
        if (ret != 0) {
            log_error("Failed to re-submit multi-read op");
            return -1;
        }
        ctx->stats.multi_recv_rearmed++;
        log_debug("Multishot read got completed and re-submitted.");
    }
    return 0;
}


int iouring_initial_udp_recvs(iouring_ctx_t *ctx, int fd) {
    if (USE_MULTI_RECV) {
        int ret = iouring_submit_multishot_recvmsg(ctx, fd);
        return ret;
    }

    int num_recv_ops = ctx->config->n_initial_recv_ops;
    for (int i = 0; i < num_recv_ops; i++) {
        io_op_t *op = io_op_alloc(ctx, OP_TYPE_UDP_RECV, fd, false /*is_multi*/);
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

    int num_recv_ops = ctx->config->n_initial_read_ops;
    for (int i = 0; i < num_recv_ops; i++) {
        io_op_t *op = io_op_alloc(ctx, OP_TYPE_TUN_READ, fd, false /*is_multi*/);
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

    log_debug("Submitted new TUN read operation");
    return 0;
}

int iouring_submit_tun_write(iouring_ctx_t *ctx, io_op_t *op,
                             const uint8_t *data, int len) {
    if (!ctx || !op || len <= 0 || op->fd < 0) {
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

    // if data is NULL then it is already in place
    if (data) {
        memcpy(op->buffer, data, len);
        op->data_len = len;
    }
    assert(op->data_len == len);

    // Prepare write operation
    io_uring_prep_write(sqe, op->fd, op->buffer, op->data_len, 0);
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
    //memset(&op->msg, 0, sizeof(op->msg));
    //memset(op->addr, 0, sizeof(*op->addr));

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

    log_debug("Submitted new UDP recv operation on fd=%d", op->fd);
    return 0;
}

int iouring_submit_udp_send(iouring_ctx_t *ctx, io_op_t *op,
                            const struct sockaddr *addr, socklen_t addr_len,
                            const uint8_t *data, int len) {
    if (!ctx || !op || !addr || len <= 0 || op->fd < 0) {
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

    // if data is NULL then it is already in op->buffer
    if (data) {
        memcpy(op->buffer, data, len);
        op->data_len = len;
    }
    assert(op->data_len == len);

    // Setup msghdr for sendmsg
    //memset(&op->msg, 0, sizeof(op->msg));
    memcpy(op->addr, addr, addr_len);
    op->addr_len = addr_len;

    op->iov.iov_base = op->buffer;
    op->iov.iov_len = op->data_len;

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

    log_debug("Submitted UDP send operation on fd=%d: %zu bytes to %s",
              op->fd, len, addr_to_string(addr));

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
        log_info("Cleaning up %s io-uring (multishot_recv rearmed: %d)", 
                  ctx->config->name, ctx->stats.multi_recv_rearmed);
        iouring_free_buffers(ctx);
        io_uring_queue_exit(&ctx->ring);
        free(ctx);
    }
}

io_op_t* io_op_alloc(iouring_ctx_t *ctx, int op_type, int fd, bool is_multi) {
    return io_op_alloc_buf(ctx, op_type, fd, is_multi, NULL /*buf_addr*/);
}

io_op_t* io_op_alloc_buf(iouring_ctx_t *ctx, int op_type, int fd, bool is_multi, io_op_t *buf_owner) {
    io_op_t *op = iouring_get_io_op(ctx);
    if (!op) {
        return NULL;
    }
    assert(!is_multi || !buf_owner);
    op->is_multi = is_multi;
    op->op_type = op_type;
    op->fd = fd;

    if (!is_multi) {
        if(!buf_owner) {
            buf_addr_t *buf_addr = iouring_get_buf_addr(ctx);
            if (!buf_addr) {
                log_error("Failed to allocate I/O buffer and address");
                iouring_put_io_op(ctx, op);
                return NULL;
            }
            op->buf_addr = buf_addr;
            op->buffer = buf_addr->buf;
            op->addr = &buf_addr->addr;
        } else {
            if (!buf_owner->is_multi) {
                op->data_len = buf_owner->data_len;
                op->buf_addr = buf_owner->buf_addr;
                op->buffer = buf_owner->buf_addr->buf;
                op->addr = &buf_owner->buf_addr->addr;
                buf_owner->buf_addr = NULL;
            } else {
                // data is in an io_uring managed br buffer
                op->buf_idx = buf_owner->buf_idx;
                op->buffer = buf_owner->buffer;
                op->data_len = buf_owner->data_len;
                buf_owner->buf_idx = DO_NOT_FREE;
            }
        }
    }
    return op;
}

void io_op_free(iouring_ctx_t *ctx, io_op_t **op) {
    if (*op) {
        if ((*op)->is_multi) {
            if ((*op)->buf_idx >= 0) {
                // only recycle buffer, multishot op is still in use
                iouring_recycle_buffer(ctx, (*op)->buf_idx);
                (*op)->buf_idx = -1;
            } else if ((*op)->buf_idx != DO_NOT_FREE) {
                log_debug("Freeing multishot op");
                iouring_put_io_op(ctx, *op);
                *op = NULL;
            }
            //memset(&(*op)->msg, 0, sizeof((*op)->msg));
            //(*op)->msg.msg_namelen = sizeof(struct sockaddr_storage);
        } else {
            assert(!(*op)->buf_addr || (*op)->buf_idx == -1);
            if ((*op)->buf_addr) {
                iouring_put_buf_addr((*op)->buf_addr);
            } else if ( (*op)->buf_idx >= 0) {
                // a provided br buffer got transfered to a send op
                iouring_recycle_buffer(ctx, (*op)->buf_idx);
            }
            iouring_put_io_op(ctx, *op);
            *op = NULL;
        }
    }
}

int iouring_resubmit_recv(iouring_ctx_t *uring_ctx, io_op_t *completed) {
    int ret = 0;
    io_op_t * new_op = io_op_alloc(uring_ctx, completed->op_type, completed->fd, false /*is_multi*/);
    if (!new_op) {
        log_error("ERROR iouring_resubmit_recv() io_op_pool %p", uring_ctx->io_op_pool);
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
