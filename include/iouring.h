#ifndef IOURING_H
#define IOURING_H

#include <liburing.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>


#define HAS_MULTI_RECV true
#define USE_MULTI_RECV false

#define HAS_MULTI_READ false
#define USE_MULTI_READ false

#if !(HAS_MULTI_RECV)
void io_uring_prep_recvmsg_multishot(struct io_uring_sqe *sqe,
                                     int fd,
                                     struct msghdr *msg,
                                     unsigned flags)  __attribute__((weak));
#endif /*MULTI_RECV*/

#if !(HAS_MULTI_READ)
void io_uring_prep_read_multishot(struct io_uring_sqe *sqe,
                                  int fd,
                                  unsigned nbytes,
                                  __u64 offset,
                                  int buf_group);
#endif /*MULTI_READ*/

// Operation types for user_data
#define OP_TYPE_TUN_READ    1
#define OP_TYPE_TUN_WRITE   2
#define OP_TYPE_UDP_RECV    3
#define OP_TYPE_UDP_SEND    4


#define RING_DEPTH                 64
#define BUF_SIZE                 1600
#define N_BUFS      (RING_DEPTH * 16)


// Buffer pool group ID
#define BUF_BGID  1


// I/O operation context
typedef struct {
    int op_type;
    int fd;  // Fle descriptor for this operation
    bool is_multi;
    uint8_t *buffer;
    int data_len;
    int buf_idx;
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_storage *addr;
    socklen_t addr_len;
} io_op_t;

// io-uring context
typedef struct {
    struct io_uring ring;
    unsigned queue_depth;
    uint8_t *bufs;
    int buf_size;
    int n_bufs;
    struct io_uring_buf_ring *br;
} iouring_ctx_t;

/**
 * Initialize io-uring context
 * @param queue_depth Queue depth (e.g., 256)
 * @return Pointer to iouring_ctx_t on success, NULL on failure
 */
iouring_ctx_t* iouring_init(unsigned queue_depth);

/**
 * Alloc buffers
 */
int iouring_alloc_buffers(iouring_ctx_t *ctx);

/**
 * Allocate buffer ring
 */
int iouring_alloc_multishot_buffers(iouring_ctx_t *ctx, int buf_size, int n_bufs);

/**
 * Free buffer ring
 */
void  iouring_free_buffer_ring(iouring_ctx_t *ctx);

/**
 * Recycle buffer
 */
void iouring_recycle_buffer(iouring_ctx_t *ctx, io_op_t *op);

/**
 * Create and submoit a multishot recvmg request
 */
int iouring_submit_multishot_recvmsg(iouring_ctx_t *ctx, int fd);

/**
 * Configure io_op with the result of a completed multishot recvmsg
 */
int iouring_multishot_recvmsg_out(iouring_ctx_t *ctx, io_op_t *op, unsigned cqe_flags);

/**
 * Configure io_op with the result of a completed multishot read
 */
int iouring_multishot_read_out(iouring_ctx_t *ctx, io_op_t *op, unsigned cqe_flags);

/**
 * Create and submoit a multishot read request
 */
int iouring_submit_multishot_read(iouring_ctx_t *ctx, int fd);

/**
 * Submit initial UDP recveives
 */
int iouring_initial_udp_recvs(iouring_ctx_t *ctx, int fd);

/**
 * Submit initial TUN reads
 */
int iouring_initial_tun_reads(iouring_ctx_t *ctx, int fd);

/**
 * Submit a TUN read operation
 * @param ctx io-uring context
 * @param op I/O operation context
 * @return 0 on success, -1 on failure
 */
int iouring_submit_tun_read(iouring_ctx_t *ctx, io_op_t *op);

/**
 * Submit a TUN write operation
 * @param ctx io-uring context
 * @param op I/O operation context
 * @param data Data to write
 * @param len Length of data
 * @return 0 on success, -1 on failure
 */
int iouring_submit_tun_write(iouring_ctx_t *ctx, io_op_t *op,
                             const uint8_t *data, size_t len);

/**
 * Submit a UDP receive operation
 * @param ctx io-uring context
 * @param udp_fd UDP socket file descriptor
 * @param op I/O operation context
 * @return 0 on success, -1 on failure
 */
int iouring_submit_udp_recv(iouring_ctx_t *ctx, io_op_t *op);

/**
 * Submit a UDP send operation
 * @param ctx io-uring context
 * @param udp_fd UDP socket file descriptor
 * @param op I/O operation context
 * @param addr Destination address
 * @param data Data to send
 * @param len Length of data
 * @return 0 on success, -1 on failure
 */
int iouring_submit_udp_send(iouring_ctx_t *ctx, io_op_t *op,
                            const struct sockaddr *addr, socklen_t addr_len,
                            const uint8_t *data, size_t len);

/**
 * Wait for a completion event
 * @param ctx io-uring context
 * @param cqe_ptr Pointer to store completion queue entry
 * @return 0 on success, -1 on failure
 */
int iouring_wait_cqe(iouring_ctx_t *ctx, struct io_uring_cqe **cqe_ptr);

/**
 * Peek for a completion event (non-blocking)
 * @param ctx io-uring context
 * @param cqe_ptr Pointer to store completion queue entry
 * @return 0 if event available, -EAGAIN if not, -1 on error
 */
int iouring_peek_cqe(iouring_ctx_t *ctx, struct io_uring_cqe **cqe_ptr);

/**
 * Mark completion event as seen
 * @param ctx io-uring context
 * @param cqe Completion queue entry
 */
void iouring_cqe_seen(iouring_ctx_t *ctx, struct io_uring_cqe *cqe);

/**
 * Cleanup io-uring context
 * @param ctx io-uring context
 */
void iouring_cleanup(iouring_ctx_t *ctx);

/**
 * Allocate I/O operation context
 * @param op_type Operation type
 * @param fd File descriptor
 * @param is_multi True if it is a multi-shot I/O operation
 * @return Pointer to io_op_t on success, NULL on failure
 */
io_op_t* io_op_alloc(int op_typ, int fd, bool is_multi);

/**
 * Free I/O operation context
 * @param op I/O operation context
 */
void io_op_free(iouring_ctx_t *ctx, io_op_t **op);

/**
 * Get the name of an IO op type as a string
 */
const char *op_type_str(int op_type);

/**
 * Resubmit a completed receive op
 */
int iouring_resubmit_recv(iouring_ctx_t *uring_ctx, io_op_t *completed);

#endif // IOURING_H

// Made with Bob
